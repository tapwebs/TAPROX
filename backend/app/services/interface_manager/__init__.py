import sys

from app.services.interface_manager.linux import LinuxInterfaceProvider
from app.services.interface_manager.raw import (
    InterfaceProvider,
    InterfaceProviderError,
    RawInterface,
)
from app.services.interface_manager.windows import WindowsInterfaceProvider

__all__ = ["InterfaceProvider", "InterfaceProviderError", "RawInterface", "default_provider"]


class _UnsupportedProvider(InterfaceProvider):
    name = "unsupported"

    def list_interfaces(self) -> tuple[list[RawInterface], list[str]]:
        raise InterfaceProviderError(
            "unsupported_platform", f"Network interfaces cannot be listed on '{sys.platform}'."
        )


def default_provider() -> InterfaceProvider:
    """The provider for this operating system (Windows and Linux are supported)."""
    if sys.platform == "win32":
        return WindowsInterfaceProvider()
    if sys.platform.startswith("linux"):
        return LinuxInterfaceProvider()
    return _UnsupportedProvider()
