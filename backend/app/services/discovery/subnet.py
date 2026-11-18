"""Which networks active discovery may touch.

This is the safety boundary for "never scan outside the connected private LAN": targets are always
derived from an interface's own network, never from free-form input, and only RFC 1918 and
link-local ranges below a size limit are accepted.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_network

# Explicit allow-list. Python's `is_private` would also accept loopback, 0.0.0.0/8 and test nets.
SCANNABLE_RANGES = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("169.254.0.0/16"),
)
MAX_ACTIVE_PREFIX = 22  # /22 = 1022 hosts


class SubnetError(ValueError):
    """The requested scan target is not allowed. `code` is stable and machine-readable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Verdict:
    ok: bool
    code: str | None = None
    message: str | None = None


def classify_network(network: IPv4Network) -> Verdict:
    if not any(network.subnet_of(allowed) for allowed in SCANNABLE_RANGES):
        return Verdict(
            False,
            "not_private",
            f"{network} is not a private (RFC 1918) or link-local network. TAPROX only "
            "scans the local network it is connected to.",
        )
    if network.prefixlen < MAX_ACTIVE_PREFIX:
        return Verdict(
            False,
            "too_large",
            f"{network} has {network.num_addresses} addresses. Active discovery is limited to "
            f"/{MAX_ACTIVE_PREFIX} (1022 hosts); enter a narrower subnet inside it.",
        )
    if network.prefixlen >= 31:
        return Verdict(False, "no_hosts", f"{network} has no host addresses to probe.")
    return Verdict(True)


def _parse_requested(text: str) -> IPv4Network:
    if not text or text != text.strip() or "/" not in text:
        raise SubnetError(
            "invalid_cidr", "Enter a network in CIDR form, for example 192.168.1.0/24."
        )
    try:
        loose = ip_network(text, strict=False)
    except ValueError as exc:
        raise SubnetError("invalid_cidr", f"{text!r} is not a valid network in CIDR form.") from exc
    if not isinstance(loose, IPv4Network):
        raise SubnetError("not_ipv4", "Active discovery supports IPv4 networks only.")
    try:
        return IPv4Network(text, strict=True)
    except ValueError as exc:
        raise SubnetError(
            "host_bits_set", f"{text} has host bits set; did you mean {loose}?"
        ) from exc


def validate_scan_target(connected: Sequence[IPv4Network], requested: str | None) -> IPv4Network:
    """Pick or validate the network to scan on an interface whose connected networks are given."""
    if not connected:
        raise SubnetError("no_ipv4", "This interface has no IPv4 network to scan.")

    if requested is None:
        for candidate in connected:
            if classify_network(candidate).ok:
                return candidate
        verdict = classify_network(connected[0])
        raise SubnetError(verdict.code or "not_private", verdict.message or "Network not allowed.")

    target = _parse_requested(requested)
    if not any(target.subnet_of(network) for network in connected):
        raise SubnetError(
            "outside_interface_network",
            f"{target} is not inside a network this interface is connected to "
            f"({', '.join(str(n) for n in connected)}).",
        )
    verdict = classify_network(target)
    if not verdict.ok:
        raise SubnetError(verdict.code or "not_private", verdict.message or "Network not allowed.")
    return target


def scan_targets(network: IPv4Network, own: set[IPv4Address]) -> list[IPv4Address]:
    """Host addresses to probe: not the network or broadcast address, and not ourselves."""
    return [host for host in network.hosts() if host not in own]
