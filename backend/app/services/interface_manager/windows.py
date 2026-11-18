"""Windows interface provider: the IP Helper API (GetAdaptersAddresses) through ctypes.

No dependency and no subprocess: one in-process call returns the adapter GUID, names, MAC, link
type, operational status, addresses with prefix lengths, gateways and DNS servers. The hardware
class (physical / USB / virtual) comes from the adapter's PnP instance id in the registry
(read-only).

Only the leading fields of IP_ADAPTER_ADDRESSES that are needed are declared. The structure is
read through pointers into the OS-owned buffer and never allocated or copied, and the
OS-reported `Length` of every entry is checked against the declared size first.
"""

import ctypes
import struct
import sys
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from app.services.interface_manager.raw import (
    InterfaceProvider,
    InterfaceProviderError,
    RawInterface,
)
from app.services.netutil import normalize_mac

AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23  # Windows value (it is 10 on Linux)

GAA_FLAG_SKIP_ANYCAST = 0x2
GAA_FLAG_SKIP_MULTICAST = 0x4
GAA_FLAG_INCLUDE_PREFIX = 0x10
GAA_FLAG_INCLUDE_GATEWAYS = 0x80

ERROR_BUFFER_OVERFLOW = 111
ERROR_ACCESS_DENIED = 5
IP_ADAPTER_DHCP_ENABLED = 0x4
DAD_DEPRECATED = 3
DAD_PREFERRED = 4
_MAX_LIST = 512  # a corrupt linked list must not loop forever

_NETWORK_CLASS_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
)

_OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}
_VIRTUAL_WORDS = (
    "virtual",
    "vmware",
    "hyper-v",
    "vethernet",
    "vpn",
    "tap-",
    "wireguard",
    "loopback",
    "tunnel",
    "wan miniport",
    "miniport",
    "tailscale",
    "zerotier",
)


_DOT11_PHY_NAMES = {
    1: "802.11 FHSS",
    2: "802.11 DSSS",
    3: "802.11 IR",
    4: "802.11a",
    5: "802.11b",
    6: "802.11g",
    7: "802.11n",
    8: "802.11ac",
    9: "802.11ad",
    10: "802.11ax",
    11: "802.11be",
}


class _Dot11Ssid(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_ulong), ("ucSSID", ctypes.c_char * 32)]


class _WlanInterfaceGuid(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WlanInterfaceInfo(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", _WlanInterfaceGuid),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", ctypes.c_uint),
    ]


class _WlanInterfaceInfoList(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", ctypes.c_ulong),
        ("dwIndex", ctypes.c_ulong),
        ("InterfaceInfo", _WlanInterfaceInfo * 1),
    ]


class _WlanConnectionAttributes(ctypes.Structure):
    _fields_ = [
        ("isState", ctypes.c_uint),
        ("wlanConnectionMode", ctypes.c_uint),
        ("strProfileName", ctypes.c_wchar * 256),
        ("dot11Ssid", _Dot11Ssid),
        ("dot11BssType", ctypes.c_uint),
        ("dot11MacAddress", ctypes.c_ubyte * 6),
        ("dot11PhyType", ctypes.c_ulong),
        ("uDot11PhyIndex", ctypes.c_ulong),
        ("wlanSignalQuality", ctypes.c_ulong),
        ("ulRxRate", ctypes.c_ulong),
        ("ulTxRate", ctypes.c_ulong),
    ]


def _band_from_channel(channel: int | None) -> str | None:
    if channel is None or channel <= 0:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 36 <= channel <= 177:
        return "5 GHz"
    if channel >= 180:
        return "6 GHz"
    return None


def query_wlan_all() -> dict[str, dict[str, Any]]:
    """Query Windows WLAN service via wlanapi.dll for active wireless attributes keyed by normalized GUID."""
    if sys.platform != "win32":
        return {}
    results: dict[str, dict[str, Any]] = {}
    try:
        wlan = ctypes.WinDLL("wlanapi", use_last_error=True)
    except OSError:
        return {}

    handle = ctypes.c_void_p()
    negotiated = ctypes.c_ulong()
    try:
        ret = wlan.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle))
    except (AttributeError, OSError):
        return {}
    if ret != 0 or not handle.value:
        return {}

    try:
        info_list_ptr = ctypes.c_void_p()
        ret = wlan.WlanEnumInterfaces(handle, None, ctypes.byref(info_list_ptr))
        if ret != 0 or not info_list_ptr.value:
            return {}
        try:
            info_list = ctypes.cast(info_list_ptr, ctypes.POINTER(_WlanInterfaceInfoList)).contents
            count = int(info_list.dwNumberOfItems)
            for i in range(count):
                item = _WlanInterfaceInfo.from_address(
                    ctypes.addressof(info_list.InterfaceInfo[0]) + i * ctypes.sizeof(_WlanInterfaceInfo)
                )
                g = item.InterfaceGuid
                d4_1 = "".join(f"{b:02x}" for b in g.Data4[:2])
                d4_2 = "".join(f"{b:02x}" for b in g.Data4[2:])
                guid_str = f"{g.Data1:08x}-{g.Data2:04x}-{g.Data3:04x}-{d4_1}-{d4_2}".lower()

                is_connected = (item.isState == 1)
                data_size = ctypes.c_ulong()
                data_ptr = ctypes.c_void_p()
                opcode_val = ctypes.c_uint()

                ssid: str | None = None
                bssid: str | None = None
                signal: int | None = None
                radio_type: str | None = None
                profile: str | None = None
                channel: int | None = None

                # wlan_intf_opcode_current_connection = 7
                qret = wlan.WlanQueryInterface(
                    handle, ctypes.byref(g), 7, None, ctypes.byref(data_size), ctypes.byref(data_ptr), ctypes.byref(opcode_val)
                )
                if qret == 0 and data_ptr.value:
                    try:
                        conn = ctypes.cast(data_ptr, ctypes.POINTER(_WlanConnectionAttributes)).contents
                        ssid_raw = conn.dot11Ssid.ucSSID[:conn.dot11Ssid.uSSIDLength]
                        ssid = ssid_raw.decode("utf-8", "replace") or None
                        bssid = ":".join(f"{b:02x}" for b in conn.dot11MacAddress)
                        signal = int(conn.wlanSignalQuality)
                        radio_type = _DOT11_PHY_NAMES.get(int(conn.dot11PhyType), f"802.11 (PHY {conn.dot11PhyType})")
                        profile = str(conn.strProfileName) or None
                    finally:
                        wlan.WlanFreeMemory(data_ptr)

                # wlan_intf_opcode_channel_number = 8
                qret_ch = wlan.WlanQueryInterface(
                    handle, ctypes.byref(g), 8, None, ctypes.byref(data_size), ctypes.byref(data_ptr), ctypes.byref(opcode_val)
                )
                if qret_ch == 0 and data_ptr.value:
                    try:
                        channel = int(ctypes.cast(data_ptr, ctypes.POINTER(ctypes.c_ulong)).contents.value) or None
                    finally:
                        wlan.WlanFreeMemory(data_ptr)

                results[guid_str] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal_percent": signal,
                    "radio_type": radio_type,
                    "profile_name": profile,
                    "channel": channel,
                    "band": _band_from_channel(channel),
                    "connection_state": "connected" if is_connected else "disconnected",
                }
        finally:
            wlan.WlanFreeMemory(info_list_ptr)
    finally:
        wlan.WlanCloseHandle(handle, None)
    return results


class _SocketAddress(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int32)]


class _AddressNode(ctypes.Structure):
    """IP_ADAPTER_DNS_SERVER_ADDRESS and IP_ADAPTER_GATEWAY_ADDRESS share this layout."""

    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("Next", ctypes.c_void_p),
        ("Address", _SocketAddress),
    ]


class _UnicastAddress(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Next", ctypes.c_void_p),
        ("Address", _SocketAddress),
        ("PrefixOrigin", ctypes.c_int32),
        ("SuffixOrigin", ctypes.c_int32),
        ("DadState", ctypes.c_int32),
        ("ValidLifetime", ctypes.c_uint32),
        ("PreferredLifetime", ctypes.c_uint32),
        ("LeaseLifetime", ctypes.c_uint32),
        ("OnLinkPrefixLength", ctypes.c_uint8),
    ]


class _Adapter(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("IfIndex", ctypes.c_uint32),
        ("Next", ctypes.c_void_p),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Mtu", ctypes.c_uint32),
        ("IfType", ctypes.c_uint32),
        ("OperStatus", ctypes.c_int32),
        ("Ipv6IfIndex", ctypes.c_uint32),
        ("ZoneIndices", ctypes.c_uint32 * 16),
        ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.c_void_p),
    ]


# --- pure helpers (unit-tested without Windows) ----------------------------------------------


def kind_from_if_type(code: int | None) -> str:
    return {6: "ethernet", 71: "wifi", 24: "loopback", 131: "tunnel"}.get(code or -1, "other")


def oper_status_name(code: int) -> str:
    return _OPER_STATUS.get(code, "unknown")


def hardware_from_pnp(pnp_instance_id: str | None, description: str | None) -> str:
    """physical | usb | virtual | unknown, from the PnP bus prefix, else from the adapter's name."""
    if pnp_instance_id:
        bus = pnp_instance_id.split("\\", 1)[0].upper()
        if bus == "USB":
            return "usb"
        if bus in ("ROOT", "SWD"):
            return "virtual"
        if bus in ("PCI", "BTH", "ACPI", "SD", "PCMCIA"):
            return "physical"
    text = (description or "").lower()
    return "virtual" if any(word in text for word in _VIRTUAL_WORDS) else "unknown"


def parse_sockaddr(raw: bytes) -> str | None:
    """Text of the IP address inside a SOCKADDR_IN / SOCKADDR_IN6 byte string (zone id dropped)."""
    if len(raw) < 2:
        return None
    (family,) = struct.unpack("<H", raw[:2])
    if family == AF_INET and len(raw) >= 8:
        return str(IPv4Address(raw[4:8]))
    if family == AF_INET6 and len(raw) >= 24:
        return str(IPv6Address(raw[8:24]))
    return None


# --- operating-system access -----------------------------------------------------------------


def _address_text(sock: _SocketAddress) -> str | None:
    if not sock.lpSockaddr or sock.iSockaddrLength < 2:
        return None
    return parse_sockaddr(ctypes.string_at(sock.lpSockaddr, sock.iSockaddrLength))


def _walk(pointer: int | None, structure: type[ctypes.Structure]):  # type: ignore[no-untyped-def]
    count = 0
    while pointer and count < _MAX_LIST:
        node = ctypes.cast(pointer, ctypes.POINTER(structure)).contents
        yield node
        pointer = node.Next
        count += 1


def _pnp_instance_id(adapter_name: str) -> tuple[str | None, bool]:
    """(PnpInstanceID or None, access_denied)."""
    import winreg

    path = rf"{_NETWORK_CLASS_KEY}\{adapter_name}\Connection"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            value, _ = winreg.QueryValueEx(key, "PnpInstanceID")
            return str(value), False
    except PermissionError:
        return None, True
    except OSError:
        return None, False  # no such key (for example the loopback pseudo-interface)


class WindowsInterfaceProvider(InterfaceProvider):
    name = "windows-iphlpapi"

    def list_interfaces(self) -> tuple[list[RawInterface], list[str]]:
        if sys.platform != "win32":
            raise InterfaceProviderError(
                "unsupported_platform", "The Windows provider only runs on Windows."
            )
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        function = iphlpapi.GetAdaptersAddresses
        function.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        function.restype = ctypes.c_uint32
        flags = (
            GAA_FLAG_INCLUDE_PREFIX
            | GAA_FLAG_INCLUDE_GATEWAYS
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
        )

        size = ctypes.c_uint32(32 * 1024)
        buffer = ctypes.create_string_buffer(size.value)
        for _ in range(5):  # the adapter set can change between sizing and reading
            buffer = ctypes.create_string_buffer(size.value)
            result = function(AF_UNSPEC, flags, None, buffer, ctypes.byref(size))
            if result == 0:
                break
            if result != ERROR_BUFFER_OVERFLOW:
                code = "permission_denied" if result == ERROR_ACCESS_DENIED else "os_error"
                raise InterfaceProviderError(
                    code, f"Windows could not list network adapters (error {result})."
                )
        else:
            raise InterfaceProviderError(
                "os_error", "The set of network adapters kept changing; try again."
            )

        # `buffer` owns the memory every pointer below refers to; it stays alive until we return.
        wlan_map = query_wlan_all()
        interfaces: list[RawInterface] = []
        denied = 0
        first = ctypes.addressof(buffer)
        for adapter in _walk(first, _Adapter):
            if adapter.Length < ctypes.sizeof(_Adapter):
                raise InterfaceProviderError(
                    "os_error", "This Windows version reports adapters in an unsupported format."
                )
            guid = (adapter.AdapterName or b"").decode("ascii", "replace")
            if not guid:
                continue
            description = adapter.Description or None
            pnp, was_denied = _pnp_instance_id(guid)
            denied += was_denied

            ipv4: list[tuple[str, int]] = []
            ipv6: list[tuple[str, int]] = []
            for unicast in _walk(adapter.FirstUnicastAddress, _UnicastAddress):
                if unicast.DadState not in (DAD_PREFERRED, DAD_DEPRECATED):
                    continue  # tentative, duplicate or invalid: not really configured
                text = _address_text(unicast.Address)
                if text is None:
                    continue
                target = ipv4 if "." in text else ipv6
                if (text, unicast.OnLinkPrefixLength) not in target:
                    target.append((text, int(unicast.OnLinkPrefixLength)))

            gateways = [
                t
                for node in _walk(adapter.FirstGatewayAddress, _AddressNode)
                if (t := _address_text(node.Address))
            ]
            dns = [
                t
                for node in _walk(adapter.FirstDnsServerAddress, _AddressNode)
                if (t := _address_text(node.Address))
            ]
            mac = None
            if adapter.PhysicalAddressLength == 6:
                mac = normalize_mac(bytes(adapter.PhysicalAddress[:6]))
            speed = int(adapter.TransmitLinkSpeed) or None

            interfaces.append(
                RawInterface(
                    id=guid.strip("{}").lower(),
                    name=adapter.FriendlyName or guid,
                    description=description,
                    os_index=int(adapter.IfIndex) or None,
                    if_type=int(adapter.IfType),
                    kind=kind_from_if_type(int(adapter.IfType)),
                    hardware=hardware_from_pnp(pnp, description),
                    mac=mac,
                    oper_status=oper_status_name(int(adapter.OperStatus)),
                    ipv4=ipv4,
                    ipv6=ipv6,
                    gateways=gateways,
                    dns_servers=dns,
                    mtu=int(adapter.Mtu)
                    if 0 < adapter.Mtu < 0xFFFFFFFF
                    else None,  # -1 = unlimited (loopback)
                    link_speed_bps=speed,
                    dhcp_enabled=bool(adapter.Flags & IP_ADAPTER_DHCP_ENABLED),
                    wireless=wlan_map.get(guid.strip("{}").lower()),
                )
            )
        warnings = (
            [f"Hardware details could not be read for {denied} adapter(s): access denied."]
            if denied
            else []
        )
        interfaces.sort(key=lambda i: (i.os_index or 0, i.id))
        return interfaces, warnings
