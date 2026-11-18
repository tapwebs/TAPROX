"""What an operating-system provider reports, before any interpretation."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RawInterface:
    id: str
    name: str
    description: str | None
    os_index: int | None
    if_type: int | None
    kind: str  # wifi | ethernet | loopback | tunnel | other
    hardware: str  # physical | usb | virtual | unknown
    mac: str | None
    oper_status: str  # up | down | dormant | testing | unknown | not_present | lower_layer_down
    ipv4: list[tuple[str, int]] = field(default_factory=list)
    ipv6: list[tuple[str, int]] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    mtu: int | None = None
    link_speed_bps: int | None = None
    dhcp_enabled: bool | None = None
    wireless: dict[str, Any] | None = None


class InterfaceProviderError(RuntimeError):
    """The operating system could not list interfaces. `code` is stable; the text is user-safe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class InterfaceProvider:
    """Platform abstraction: Windows and Linux each supply one."""

    name = "unknown"

    def list_interfaces(self) -> tuple[list[RawInterface], list[str]]:
        """Return interfaces and any non-fatal warnings (for example unreadable hardware info)."""
        raise NotImplementedError
