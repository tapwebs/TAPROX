"""Linux discovery backend: `ip -j neigh`, /proc/net/arp and an unprivileged UDP datagram.

No raw sockets and no root: sending a datagram to an on-link address makes the kernel resolve it
with ARP, and the completed entry then appears in /proc/net/arp. The `ip` and `ping` binaries are
located in fixed system directories only (never through PATH) and run with fixed arguments, no
shell and a timeout.
"""

import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from app.services.discovery.backend import (
    DiscoveryBackend,
    DiscoveryError,
    NeighborEntry,
    ensure_scannable,
)
from app.services.netutil import is_unicast_mac, normalize_mac

IP_CANDIDATES = ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
PING_CANDIDATES = ("/usr/bin/ping", "/bin/ping", "/usr/sbin/ping", "/sbin/ping")
ARP_FILE = Path("/proc/net/arp")
_DISCARD_PORT = 9
_INTERFACE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,14}")  # Linux limit: 15 characters
_STATES = {
    "REACHABLE": "reachable",
    "STALE": "stale",
    "DELAY": "delay",
    "PROBE": "probe",
    "PERMANENT": "permanent",
}
_ARP_COMPLETE = 0x2


def _find(candidates: tuple[str, ...]) -> str | None:
    return next((p for p in candidates if os.access(p, os.X_OK)), None)


def _find_ping() -> str | None:
    return _find(PING_CANDIDATES)


def _run_ip(args: list[str]) -> str:
    binary = _find(IP_CANDIDATES)
    if binary is None:
        raise DiscoveryError("tool_missing", "The 'ip' command (iproute2) was not found.")
    try:
        done = subprocess.run(  # noqa: S603 - absolute binary, constant arguments, no shell
            [binary, *args], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError("os_error", f"Running 'ip' failed: {exc}") from exc
    if done.returncode != 0:
        raise DiscoveryError(
            "os_error", f"'ip {' '.join(args)}' exited with code {done.returncode}."
        )
    return done.stdout


def _send_datagram(source: str, target: str, interface: str | None = None) -> None:
    """One byte to the discard port, from the interface's own address. Failure means no route.

    With `interface` the socket is bound to that device, so the kernel cannot resolve the host
    through another interface that shares the private range. Binding to a device needs
    CAP_NET_RAW on kernels before 5.7; when it is refused the datagram is still sent from the
    interface's address and the answer is still only accepted from that device (see
    `parse_proc_arp`), so a different interface can never be credited with it.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        if interface:
            # Not permitted here: fine, the device filter on the answer still applies.
            with contextlib.suppress(OSError, AttributeError):
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,  # type: ignore[attr-defined,unused-ignore]
                    interface.encode(),
                )
        try:
            sock.bind((source, 0))
            sock.sendto(b"\0", (target, _DISCARD_PORT))
        except OSError:
            pass  # unreachable or no buffer space: the table will simply not show an answer


# --- pure helpers (unit-tested on any OS) -------------------------------------------------------


def parse_ip_neigh(text: str) -> list[NeighborEntry]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DiscoveryError(
            "os_error", "'ip neigh' returned output that could not be read."
        ) from exc
    if not isinstance(parsed, list):
        raise DiscoveryError("os_error", "'ip neigh' returned an unexpected structure.")
    entries: list[NeighborEntry] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        ip, mac_text, device = item.get("dst"), item.get("lladdr"), item.get("dev")
        mac = normalize_mac(mac_text) if isinstance(mac_text, str) else None
        if not isinstance(ip, str) or mac is None or not isinstance(device, str):
            continue  # unresolved (no link-layer address) or malformed: nothing to report
        try:
            ip_address(ip)
        except ValueError:
            continue
        states: Any = item.get("state")
        word = str(states[0]).upper() if isinstance(states, list) and states else "UNKNOWN"
        entries.append(NeighborEntry(ip, mac, _STATES.get(word, "unknown"), if_name=device))
    return entries


def parse_proc_arp(text: str, device: str | None = None) -> dict[str, str]:
    """IPv4 -> MAC for the entries the kernel has completed (it skips the header and junk).

    With `device`, only rows learned on that interface count.
    """
    found: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            flags = int(parts[2], 16)
        except ValueError:
            continue
        mac = normalize_mac(parts[3])
        if device is not None and (len(parts) < 6 or parts[5] != device):
            continue
        if flags & _ARP_COMPLETE and mac and is_unicast_mac(mac):
            found[parts[0]] = mac
    return found


# --- the backend ----------------------------------------------------------------------------


class LinuxDiscoveryBackend(DiscoveryBackend):
    name = "linux-iproute2"

    def __init__(
        self,
        *,
        run: Callable[[list[str]], str] = _run_ip,
        arp_path: Path = ARP_FILE,
        send: Callable[[str, str, str | None], None] = _send_datagram,
        poll_interval: float = 0.1,
    ) -> None:
        self._run = run
        self._arp_path = arp_path
        self._send = send
        self._poll = poll_interval

    def preflight(self) -> None:
        if not sys.platform.startswith("linux"):
            raise DiscoveryError(
                "unsupported_platform", "The Linux discovery backend only runs on Linux."
            )
        if _find(IP_CANDIDATES) is None:
            raise DiscoveryError("tool_missing", "The 'ip' command (iproute2) was not found.")

    def read_neighbors(self) -> list[NeighborEntry]:
        return parse_ip_neigh(self._run(["-j", "neigh", "show"]))

    def _completed(self, device: str | None = None) -> dict[str, str]:
        try:
            return parse_proc_arp(self._arp_path.read_text(encoding="utf-8"), device)
        except OSError:
            return {}

    def arp_probe(
        self, source: str, target: str, *, timeout: float, interface: str | None = None
    ) -> str | None:
        """The MAC if the kernel *newly* resolved `target` on `interface` because of this probe.

        A host the kernel already has cached is not reported: its entry may be old, so it is no
        proof of an answer now. read_neighbors() reports it with its real state instead.
        """
        src, dst = ensure_scannable(source, target)
        if str(dst) in self._completed(interface):
            return None
        self._send(str(src), str(dst), interface)
        end = time.monotonic() + timeout
        while True:
            mac = self._completed(interface).get(str(dst))
            if mac is not None:
                return mac
            if time.monotonic() >= end:
                return None
            time.sleep(self._poll)

    def nudge_ipv6(self, *, if_index: int | None, if_name: str, timeout: float) -> None:
        if not _INTERFACE_NAME.fullmatch(if_name):
            raise DiscoveryError("invalid_interface", "The interface name is not safe to use.")
        ping = _find_ping()
        if ping is None:
            raise DiscoveryError("tool_missing", "The 'ping' command was not found.")
        try:
            subprocess.run(  # noqa: S603 - absolute binary, validated name, no shell
                [ping, "-6", "-c", "2", "-W", "1", f"ff02::1%{if_name}"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise DiscoveryError("timeout", "The IPv6 neighbor probe timed out.") from None
        except OSError as exc:
            raise DiscoveryError("os_error", f"Running ping failed: {exc.strerror or exc}") from exc
