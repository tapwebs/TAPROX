import sys

from app.services.discovery.backend import DiscoveryBackend, DiscoveryError, NeighborEntry
from app.services.discovery.linux import LinuxDiscoveryBackend
from app.services.discovery.windows import WindowsDiscoveryBackend


class _UnsupportedBackend(DiscoveryBackend):
    name = "unsupported"

    def preflight(self) -> None:
        raise DiscoveryError(
            "unsupported_platform", f"Device discovery is not available on '{sys.platform}'."
        )

    def read_neighbors(self) -> list[NeighborEntry]:
        self.preflight()
        return []

    def arp_probe(
        self, source: str, target: str, *, timeout: float, interface: str | None = None
    ) -> str | None:
        self.preflight()
        return None

    def nudge_ipv6(self, *, if_index: int | None, if_name: str, timeout: float) -> None:
        self.preflight()


def default_backend() -> DiscoveryBackend:
    """The discovery backend for this operating system (Windows and Linux are supported)."""
    if sys.platform == "win32":
        return WindowsDiscoveryBackend()
    if sys.platform.startswith("linux"):
        return LinuxDiscoveryBackend()
    return _UnsupportedBackend()
