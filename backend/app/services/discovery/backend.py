"""What discovery needs from the operating system, kept small for Windows and Linux to supply.

The scan logic (limits, cancellation, progress, persistence) lives in the service and is the same on
every platform. A backend only answers three questions:

* what is in the OS neighbor table (ARP for IPv4, NDP for IPv6);
* does this one IPv4 address answer an ARP request (the probe);
* can the OS be nudged to learn its IPv6 neighbors.

A backend sends only: ARP requests (on Linux, a one-byte UDP datagram to the discard port that makes
the kernel send the ARP request) to addresses the service already validated as part of the connected
private network, and (best effort) one multicast ping on the local link.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address

from app.services.discovery.subnet import SCANNABLE_RANGES


class DiscoveryError(RuntimeError):
    """The OS could not do what discovery asked. `code` is stable; the text is safe to show."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class NeighborEntry:
    ip: str
    mac: str
    state: str  # reachable | stale | delay | probe | permanent | incomplete | unreachable | unknown
    if_index: int | None = None
    if_name: str | None = None


def ensure_scannable(source: str, target: str) -> tuple[IPv4Address, IPv4Address]:
    """Second safety net, independent of the service: a probe may only ever go to a private host.

    The service already restricts targets to the interface's own private network; this makes the
    backends refuse anything else even if they were called directly.
    """
    try:
        src, dst = IPv4Address(source), IPv4Address(target)
    except ValueError:
        raise DiscoveryError("invalid_address", "Probe addresses must be plain IPv4.") from None
    if not any(dst in network for network in SCANNABLE_RANGES):
        raise DiscoveryError(
            "target_not_allowed", "Active discovery only probes private network addresses."
        )
    return src, dst


class DiscoveryBackend:
    name = "unknown"

    def preflight(self) -> None:
        """Raise DiscoveryError when discovery cannot work here (wrong platform, missing tool)."""
        raise NotImplementedError

    def read_neighbors(self) -> list[NeighborEntry]:
        """The OS neighbor table, unfiltered. Must not send network traffic."""
        raise NotImplementedError

    def arp_probe(
        self, source: str, target: str, *, timeout: float, interface: str | None = None
    ) -> str | None:
        """Ask who has `target`, from `source`. The MAC if it answered, None if nobody did.

        `interface` is the operating-system name of the chosen interface. Backends that cannot pin
        the probe by source address use it to keep the probe and its answer on that interface.

        Raises DiscoveryError only for failures that are not simply "no answer".
        """
        raise NotImplementedError

    def nudge_ipv6(self, *, if_index: int | None, if_name: str, timeout: float) -> None:
        """Best effort: make on-link IPv6 neighbors announce themselves. Failure is not fatal."""
        raise NotImplementedError
