"""Linux interface provider: `ip -j` (iproute2), /sys/class/net and /etc/resolv.conf.

Everything the operating system reports is read; nothing is changed. The `ip` binary is located in
fixed system directories only (never through PATH or the current directory) and is run with a fixed
argument list, no shell, and a timeout.
"""

import json
import os
import subprocess
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from app.services.interface_manager.raw import (
    InterfaceProvider,
    InterfaceProviderError,
    RawInterface,
)
from app.services.netutil import normalize_mac

IP_CANDIDATES = ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
_STUB_RESOLVERS = {"127.0.0.53", "127.0.0.54", "::1", "127.0.0.1"}
_OPERSTATE = {
    "UP": "up",
    "DOWN": "down",
    "DORMANT": "dormant",
    "LOWERLAYERDOWN": "lower_layer_down",
    "NOTPRESENT": "not_present",
    "TESTING": "testing",
    "UNKNOWN": "unknown",
}
_TUNNEL_LINK_TYPES = {
    "none",
    "sit",
    "gre",
    "gretap",
    "ipip",
    "ip6tnl",
    "tunnel",
    "tunnel6",
    "wireguard",
}


def default_run(args: list[str]) -> str:
    binary = next((p for p in IP_CANDIDATES if os.access(p, os.X_OK)), None)
    if binary is None:
        raise InterfaceProviderError(
            "provider_unavailable",
            "The 'ip' command (iproute2) was not found in the system directories.",
        )
    try:
        done = subprocess.run(  # noqa: S603 - absolute binary, constant arguments, no shell
            [binary, *args], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InterfaceProviderError("os_error", f"Running 'ip' failed: {exc}") from exc
    if done.returncode != 0:
        raise InterfaceProviderError(
            "os_error", f"'ip {' '.join(args)}' exited with code {done.returncode}."
        )
    return done.stdout


class LinuxInterfaceProvider(InterfaceProvider):
    name = "linux-iproute2"

    def __init__(
        self,
        *,
        run: Callable[[list[str]], str] = default_run,
        sysfs: Path = Path("/sys/class/net"),
        resolv_conf: Path = Path("/etc/resolv.conf"),
        realpath: Callable[[Path], str] = lambda p: str(p.resolve()),
    ) -> None:
        self._run = run
        self._sysfs = sysfs
        self._resolv = resolv_conf
        self._realpath = realpath

    # --- helpers ---------------------------------------------------------------------------

    def _json(self, args: list[str]) -> list[dict[str, Any]]:
        try:
            parsed = json.loads(self._run(args))
        except json.JSONDecodeError as exc:
            raise InterfaceProviderError(
                "os_error", "'ip' returned output that could not be read."
            ) from exc
        if not isinstance(parsed, list):
            raise InterfaceProviderError("os_error", "'ip' returned an unexpected structure.")
        return [item for item in parsed if isinstance(item, dict)]

    def _gateways(self, warnings: list[str]) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for args in (["-j", "route", "show", "default"], ["-j", "-6", "route", "show", "default"]):
            try:
                routes = self._json(args)
            except InterfaceProviderError:
                warnings.append("Default gateways could not be read from the routing table.")
                continue
            for route in routes:
                device, gateway = route.get("dev"), route.get("gateway")
                if isinstance(device, str) and isinstance(gateway, str):
                    found.setdefault(device, []).append(gateway)
        return found

    def _dns(self, warnings: list[str]) -> list[str]:
        try:
            text = self._resolv.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        servers = [
            parts[1]
            for line in text.splitlines()
            if len(parts := line.split()) >= 2 and parts[0] == "nameserver"
        ]
        stubs = [s for s in servers if s in _STUB_RESOLVERS]
        if stubs:
            warnings.append(
                f"DNS is handled by a local resolver ({stubs[0]}); the upstream servers per "
                "interface are not shown."
            )
        return [s for s in servers if s not in _STUB_RESOLVERS]

    def _read(self, name: str, leaf: str) -> str | None:
        try:
            return (self._sysfs / name / leaf).read_text(encoding="utf-8").strip()
        except OSError:
            return None

    def _kind(self, name: str, link_type: str) -> str:
        if link_type == "loopback":
            return "loopback"
        if (self._sysfs / name / "wireless").exists() or (self._sysfs / name / "phy80211").exists():
            return "wifi"
        if link_type in _TUNNEL_LINK_TYPES:
            return "tunnel"
        return "ethernet" if link_type == "ether" else "other"

    def _hardware(self, name: str) -> str:
        try:
            real = self._realpath(self._sysfs / name)
        except (OSError, KeyError):
            return "unknown"
        if "/virtual/" in real:
            return "virtual"
        return "usb" if "/usb" in real else "physical"

    # --- the provider ------------------------------------------------------------------------

    def list_interfaces(self) -> tuple[list[RawInterface], list[str]]:
        warnings: list[str] = []
        entries = self._json(["-j", "addr", "show"])
        gateways = self._gateways(warnings)
        dns = self._dns(warnings)

        result: list[RawInterface] = []
        for entry in entries:
            name, index = entry.get("ifname"), entry.get("ifindex")
            if not isinstance(name, str) or not isinstance(index, int):
                continue  # malformed entry: skipped rather than guessed at
            flags = entry.get("flags") or []
            state = _OPERSTATE.get(str(entry.get("operstate", "UNKNOWN")).upper(), "unknown")
            if state == "unknown" and "UP" in flags and "LOWER_UP" in flags:
                state = "up"  # loopback and some virtual devices never report a clearer state
            link_type = str(entry.get("link_type", ""))
            kind = self._kind(name, link_type)

            ipv4: list[tuple[str, int]] = []
            ipv6: list[tuple[str, int]] = []
            for info in entry.get("addr_info") or []:
                local, prefix = info.get("local"), info.get("prefixlen")
                if not isinstance(local, str) or not isinstance(prefix, int):
                    continue
                try:
                    version = ip_address(local).version
                except ValueError:
                    continue
                (ipv4 if version == 4 else ipv6).append((local, prefix))

            speed_text = self._read(name, "speed")
            speed = (
                int(speed_text) * 1_000_000
                if speed_text and speed_text.lstrip("-").isdigit() and int(speed_text) > 0
                else None
            )
            mac = normalize_mac(entry.get("address")) if kind != "loopback" else None
            if mac == "00:00:00:00:00:00":
                mac = None
            gateway_list = gateways.get(name, [])

            result.append(
                RawInterface(
                    id=name,
                    name=name,
                    description=None,
                    os_index=index,
                    if_type=None,
                    kind=kind,
                    hardware=self._hardware(name),
                    mac=mac,
                    oper_status=state,
                    ipv4=ipv4,
                    ipv6=ipv6,
                    gateways=gateway_list,
                    dns_servers=dns if gateway_list else [],
                    mtu=entry.get("mtu") if isinstance(entry.get("mtu"), int) else None,
                    link_speed_bps=speed,
                    dhcp_enabled=None,  # not exposed by the kernel; depends on the network manager
                )
            )
        return result, warnings
