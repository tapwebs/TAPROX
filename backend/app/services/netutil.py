"""Small, pure helpers for addresses, shared by interfaces, discovery and the inventory."""

import re
from ipaddress import IPv4Address, IPv6Address, IPv6Network, ip_address
from typing import Literal

_UNIQUE_LOCAL = IPv6Network("fc00::/7")
_MAC_DIGITS = re.compile(r"[0-9a-f]{12}")


def normalize_mac(value: str | bytes | None) -> str | None:
    """Canonical lowercase colon form, or None when the value is not a 48-bit MAC address."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return ":".join(f"{b:02x}" for b in value) if len(value) == 6 else None
    digits = re.sub(r"[\s:.\-]", "", value).lower()
    if not _MAC_DIGITS.fullmatch(digits):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_unicast_mac(mac: str) -> bool:
    """False for broadcast, multicast (group bit set) and the all-zero address."""
    first = int(mac[:2], 16)
    return not (first & 0x01) and mac != "00:00:00:00:00:00"


def is_locally_administered(mac: str) -> bool:
    """True when the 'locally administered' bit is set.

    Such addresses are not assigned by a manufacturer. They are used by virtual adapters and by
    privacy features that randomise the address, so they cannot be attributed to a vendor and may
    change for the same physical device.
    """
    return bool(int(mac[:2], 16) & 0x02)


def _parse(ip: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None


def is_unicast_ip(ip: str) -> bool:
    """A usable single-host address: not multicast, unspecified, loopback or limited broadcast."""
    parsed = _parse(ip)
    if parsed is None:
        return False
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        return False
    return not (isinstance(parsed, IPv4Address) and parsed == IPv4Address("255.255.255.255"))


def ip_sort_key(ip: str) -> str:
    """A string that sorts addresses numerically (IPv4 first); used for the indexed sort column."""
    parsed = _parse(ip)
    if isinstance(parsed, IPv4Address):
        return f"4:{int(parsed):08x}"
    if isinstance(parsed, IPv6Address):
        return f"6:{int(parsed):032x}"
    return f"9:{ip}"


def address_scope(ip: str) -> Literal["private", "link_local", "loopback", "global", "other"]:
    """Coarse scope of an address, for display and filtering."""
    parsed = _parse(ip)
    if parsed is None:
        return "other"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    if isinstance(parsed, IPv6Address) and parsed.is_site_local:
        return "other"
    if isinstance(parsed, IPv4Address):
        return "private" if parsed.is_private else "global"
    # Python's IPv6 `is_private` also covers reserved blocks such as 2001::/23 (which contains
    # real Teredo addresses), so test for unique-local addresses (fc00::/7) explicitly.
    return "private" if parsed in _UNIQUE_LOCAL else "global"
