"""Windows discovery backend: the IP Helper API through ctypes.

* Neighbor table: GetIpNetTable2 (IPv4 ARP cache and IPv6 NDP cache in one call). Read only.
* Probe: SendARP, which needs neither administrator rights nor a packet driver. The source address
  is pinned to the chosen interface, and Windows applies its own ARP timeout, so `timeout` is not
  used here.
* IPv6 nudge: one multicast ping (`ping -6 ff02::1%<ifindex>`) run by absolute path, with fixed
  arguments and no shell.

The row layout is declared in full (MIB_IPNET_ROW2 is 88 bytes on 64-bit Windows) and the parser
works on plain bytes, so it is unit-tested with hand-built rows on any OS.
"""

import ctypes
import os
import struct
import subprocess
import sys
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from app.services.discovery.backend import (
    DiscoveryBackend,
    DiscoveryError,
    NeighborEntry,
    ensure_scannable,
)
from app.services.netutil import is_unicast_mac, normalize_mac

AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23  # Windows value (10 on Linux)
ROW_SIZE = 88
_TABLE_HEADER = 8  # NumEntries (4) + padding to the 8-byte aligned first row
_MAX_ROWS = 100_000
_STATES = {
    0: "unreachable",
    1: "incomplete",
    2: "probe",
    3: "delay",
    4: "stale",
    5: "reachable",
    6: "permanent",
}
# SendARP results that mean "nobody answered", not "something is broken".
_NO_ANSWER = {
    31,  # ERROR_GEN_FAILURE
    67,  # ERROR_BAD_NET_NAME: the usual result when the host does not reply
    121,  # ERROR_SEM_TIMEOUT
    1168,  # ERROR_NOT_FOUND
    1460,  # ERROR_TIMEOUT
}
_ACCESS_DENIED = 5
_NOT_SUPPORTED = 50


class _Row(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ubyte * 28),  # SOCKADDR_INET
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceLuid", ctypes.c_uint64),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("State", ctypes.c_int32),
        ("Flags", ctypes.c_uint8),
        ("ReachabilityTime", ctypes.c_uint32),
    ]


# --- pure helpers (unit-tested without Windows) ---------------------------------------------


def parse_neighbor_row(raw: bytes) -> NeighborEntry | None:
    """One MIB_IPNET_ROW2 as bytes -> entry, or None when it has no usable MAC or address."""
    if len(raw) < ROW_SIZE:
        return None
    (family,) = struct.unpack_from("<H", raw, 0)
    if family == AF_INET:
        ip = str(IPv4Address(raw[4:8]))
    elif family == AF_INET6:
        ip = str(IPv6Address(raw[8:24]))  # the zone id (bytes 24..28) is dropped
    else:
        return None
    (index,) = struct.unpack_from("<I", raw, 28)
    (mac_length,) = struct.unpack_from("<I", raw, 72)
    if mac_length != 6:
        return None
    mac = normalize_mac(raw[40:46])
    if mac is None:
        return None
    (state,) = struct.unpack_from("<i", raw, 76)
    return NeighborEntry(ip, mac, _STATES.get(state, "unknown"), if_index=index or None)


def interpret_sendarp(code: int, mac_buffer: bytes, length: int) -> str | None:
    """SendARP's return value and buffer -> MAC, None for 'no answer', or an error."""
    if code == 0:
        if length != 6:
            return None
        mac = normalize_mac(mac_buffer[:6])
        return mac if mac and is_unicast_mac(mac) else None
    if code in _NO_ANSWER:
        return None
    if code == _ACCESS_DENIED:
        raise DiscoveryError(
            "permission_denied", "Windows refused the ARP request (access denied)."
        )
    if code == _NOT_SUPPORTED:
        raise DiscoveryError("not_supported", "This network adapter does not support ARP requests.")
    raise DiscoveryError("os_error", f"The ARP request failed (Windows error {code}).")


def _ping_path() -> str:
    return os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "PING.EXE")


# --- the backend -----------------------------------------------------------------------------


class WindowsDiscoveryBackend(DiscoveryBackend):
    name = "windows-iphlpapi"

    @staticmethod
    def _iphlpapi() -> Any:
        if sys.platform != "win32":
            raise DiscoveryError(
                "unsupported_platform", "The Windows discovery backend only runs on Windows."
            )
        # WinDLL exists only in Windows' typeshed, hence "unused-ignore" for other platforms.
        dll = ctypes.WinDLL("iphlpapi", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
        return dll

    def preflight(self) -> None:
        self._iphlpapi()

    def read_neighbors(self) -> list[NeighborEntry]:
        api = self._iphlpapi()
        get_table = api.GetIpNetTable2
        get_table.argtypes = [ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p)]
        get_table.restype = ctypes.c_uint32
        free_table = api.FreeMibTable
        free_table.argtypes = [ctypes.c_void_p]
        free_table.restype = None

        table = ctypes.c_void_p()
        result = get_table(AF_UNSPEC, ctypes.byref(table))
        if result != 0:
            code = "permission_denied" if result == _ACCESS_DENIED else "os_error"
            raise DiscoveryError(
                code, f"Windows could not read the neighbor table (error {result})."
            )
        try:
            if not table.value:
                return []
            (count,) = struct.unpack("<I", ctypes.string_at(table.value, 4))
            entries: list[NeighborEntry] = []
            for i in range(min(count, _MAX_ROWS)):
                raw = ctypes.string_at(table.value + _TABLE_HEADER + i * ROW_SIZE, ROW_SIZE)
                if (entry := parse_neighbor_row(raw)) is not None:
                    entries.append(entry)
            return entries
        finally:
            free_table(table)

    def arp_probe(
        self, source: str, target: str, *, timeout: float, interface: str | None = None
    ) -> str | None:
        src, dst = ensure_scannable(source, target)
        api = self._iphlpapi()
        send_arp = api.SendARP
        send_arp.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        send_arp.restype = ctypes.c_uint32
        buffer = (ctypes.c_ubyte * 8)()
        length = ctypes.c_uint32(8)
        # IPAddr is the four address bytes in memory order, read as a little-endian integer.
        code = send_arp(
            struct.unpack("<I", dst.packed)[0],
            struct.unpack("<I", src.packed)[0],
            buffer,
            ctypes.byref(length),
        )
        return interpret_sendarp(code, bytes(buffer), length.value)

    def nudge_ipv6(self, *, if_index: int | None, if_name: str, timeout: float) -> None:
        if if_index is None or if_index <= 0:
            raise DiscoveryError("no_interface_index", "The interface has no usable index.")
        args = [_ping_path(), "-6", "-n", "2", "-w", "1000", f"ff02::1%{int(if_index)}"]
        try:
            subprocess.run(  # noqa: S603 - absolute path, fixed arguments, integer index, no shell
                args,
                capture_output=True,
                timeout=timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            raise DiscoveryError("tool_missing", "ping.exe was not found.") from None
        except subprocess.TimeoutExpired:
            raise DiscoveryError("timeout", "The IPv6 neighbor probe timed out.") from None
        except OSError as exc:
            raise DiscoveryError("os_error", f"Running ping failed: {exc.strerror or exc}") from exc
