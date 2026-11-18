from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

InterfaceKind = Literal["wifi", "ethernet", "loopback", "tunnel", "other"]
HardwareClass = Literal["physical", "usb", "virtual", "unknown"]
ConnectionState = Literal["connected", "disconnected", "unknown"]
AddressScope = Literal["private", "link_local", "loopback", "global", "other"]


class AddressInfo(BaseModel):
    address: str
    prefix_length: int = Field(ge=0, le=128)
    network: str
    scope: AddressScope


class CaptureSupport(BaseModel):
    """Whether packet capture can work on this interface. Never assumed; Phase 2 verifies it."""

    status: Literal["unverified", "unsupported"]
    note: str
    managed_mode: str | None = None
    monitor_mode: Literal["available", "driver_limitation", "unsupported", "unknown"] | None = None
    visibility_scope: str | None = None


class WirelessInfo(BaseModel):
    """Metadata for Wi-Fi (802.11) network interfaces."""

    ssid: str | None = Field(default=None, description="Connected Wi-Fi network SSID.")
    bssid: str | None = Field(default=None, description="MAC address of connected Access Point.")
    band: str | None = Field(default=None, description="Wireless frequency band (e.g. 2.4 GHz, 5 GHz, 6 GHz).")
    channel: int | None = Field(default=None, description="Operating Wi-Fi channel number.")
    signal_percent: int | None = Field(default=None, description="Signal quality percentage (0-100).")
    radio_type: str | None = Field(default=None, description="802.11 standard (e.g. 802.11ac, 802.11ax).")
    profile_name: str | None = Field(default=None, description="Configured profile name.")
    connection_state: Literal["connected", "disconnected", "unknown"] = "unknown"


class DiscoveryAvailability(BaseModel):
    """What device discovery may do on this interface right now, and why not if it may not."""

    passive: bool = Field(description="Reading the operating system's neighbor table is possible.")
    active: bool = Field(description="ARP probing of the connected network is possible.")
    needs_subnet: bool = Field(
        description="The connected network is larger than the active-scan limit; a narrower "
        "subnet inside it must be chosen."
    )
    network: str | None = Field(description="CIDR of the network active discovery would scan.")
    host_count: int | None
    reason_code: str | None
    reason: str | None


class NetworkInterface(BaseModel):
    id: str = Field(
        description="Stable identifier: the adapter GUID on Windows, the name on Linux."
    )
    name: str
    description: str | None
    os_index: int | None
    kind: InterfaceKind
    if_type: int | None = Field(description="Raw operating-system link type code, when known.")
    hardware: HardwareClass
    mac: str | None
    mac_locally_administered: bool | None = Field(
        description="True when the MAC is not manufacturer-assigned (virtual adapter or "
        "privacy-randomised address)."
    )
    connection: ConnectionState
    oper_status: str = Field(description="The operating system's own status word.")
    present: bool = Field(
        description="False for an adapter seen earlier in this session that has since vanished."
    )
    last_seen_at: datetime | None
    support: Literal["supported", "unsupported"]
    support_reason: str | None
    ipv4: list[AddressInfo]
    ipv6: list[AddressInfo]
    gateways: list[str]
    dns_servers: list[str]
    mtu: int | None
    link_speed_mbps: int | None
    dhcp_enabled: bool | None
    discovery: DiscoveryAvailability
    capture: CaptureSupport
    wireless: WirelessInfo | None = None


class InterfaceEvent(BaseModel):
    """A change noticed between two refreshes. Detection happens when interfaces are read."""

    sequence: int
    at: datetime
    kind: Literal["appeared", "removed", "connected", "disconnected", "address_changed"]
    interface_id: str
    interface_name: str
    detail: str | None


class InterfaceList(BaseModel):
    interfaces: list[NetworkInterface]
    collected_at: datetime
    provider: str
    stale: bool = Field(description="True when the last refresh failed and old data is shown.")
    warnings: list[str]
    new_events: list[InterfaceEvent] = Field(
        description="Changes detected by this refresh (empty when nothing changed)."
    )


class InterfaceEventList(BaseModel):
    events: list[InterfaceEvent]
