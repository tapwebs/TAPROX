"""Turn a provider's RawInterface into the API model.

All classification lives here, once, so Windows and Linux providers only report facts.
Two questions are kept apart on purpose: is it *connected*, and is it *supported*.
"""

from datetime import datetime
from ipaddress import IPv4Network, ip_address, ip_interface

from app.schemas.interfaces import (
    AddressInfo,
    CaptureSupport,
    DiscoveryAvailability,
    NetworkInterface,
    WirelessInfo,
)
from app.services.discovery.subnet import classify_network
from app.services.interface_manager.raw import RawInterface
from app.services.netutil import address_scope, is_locally_administered

_CONNECTED = {"up"}
_DISCONNECTED = {"down", "not_present", "lower_layer_down"}

_UNSUPPORTED_REASONS = {
    "loopback": "Loopback adapter: it only carries this computer's own traffic, so there is no "
    "network to discover.",
    "tunnel": "Tunnel or VPN adapter: it has no link-layer neighbors to discover.",
}

_CAPTURE_UNVERIFIED = (
    "Capture support is verified when a capture starts (Phase 2). A connected link and "
    "installed tools do not guarantee it."
)


def _connection(oper_status: str, present: bool) -> str:
    if not present or oper_status in _DISCONNECTED:
        return "disconnected"
    return "connected" if oper_status in _CONNECTED else "unknown"


def _support(raw: RawInterface) -> tuple[str, str | None]:
    if raw.kind in ("wifi", "ethernet"):
        return "supported", None
    if raw.kind in _UNSUPPORTED_REASONS:
        return "unsupported", _UNSUPPORTED_REASONS[raw.kind]
    code = f" {raw.if_type}" if raw.if_type is not None else ""
    return "unsupported", f"Link type{code} is not supported: it has no Ethernet-style neighbors."


def _addresses(pairs: list[tuple[str, int]]) -> list[AddressInfo]:
    result: list[AddressInfo] = []
    for address, prefix in pairs:
        try:
            network = str(ip_interface(f"{address}/{prefix}").network)
        except ValueError:
            continue  # a malformed address from the OS is dropped rather than shown wrongly
        result.append(
            AddressInfo(
                address=address, prefix_length=prefix, network=network, scope=address_scope(address)
            )
        )
    return result


def _usable(addresses: list[str]) -> list[str]:
    kept: list[str] = []
    for text in addresses:
        try:
            if not ip_address(text.split("%", 1)[0]).is_unspecified:
                kept.append(text)
        except ValueError:
            continue
    return kept


def _link_speed_mbps(bps: int | None) -> int | None:
    # Windows reports 0xFFFFFFFFFFFFFFFF (or 0) when the speed is unknown.
    if bps is None or bps <= 0 or bps >= 2**63:
        return None
    return bps // 1_000_000


def _discovery(
    raw: RawInterface, connection: str, support: str, ipv4: list[AddressInfo], present: bool
) -> DiscoveryAvailability:
    def blocked(code: str, reason: str) -> DiscoveryAvailability:
        return DiscoveryAvailability(
            passive=False,
            active=False,
            needs_subnet=False,
            network=None,
            host_count=None,
            reason_code=code,
            reason=reason,
        )

    if not present:
        return blocked("absent", "This adapter is no longer present (removed or disabled).")
    if support != "supported":
        return blocked("unsupported", "This interface type is not supported for discovery.")
    if connection == "disconnected":
        return blocked("disconnected", "The interface is not connected to a network.")
    if connection == "unknown":
        return blocked("state_unknown", "The operating system did not report a clear link state.")

    networks = [IPv4Network(a.network) for a in ipv4]
    if not networks:
        return DiscoveryAvailability(
            passive=True,
            active=False,
            needs_subnet=False,
            network=None,
            host_count=None,
            reason_code="no_ipv4",
            reason="No IPv4 address: only the neighbor table can be read.",
        )
    for network in networks:
        if classify_network(network).ok:
            return DiscoveryAvailability(
                passive=True,
                active=True,
                needs_subnet=False,
                network=str(network),
                host_count=network.num_addresses - 2,
                reason_code=None,
                reason=None,
            )
    first = classify_network(networks[0])
    if first.code == "too_large":
        return DiscoveryAvailability(
            passive=True,
            active=True,
            needs_subnet=True,
            network=str(networks[0]),
            host_count=networks[0].num_addresses - 2,
            reason_code="too_large",
            reason=first.message,
        )
    return DiscoveryAvailability(
        passive=True,
        active=False,
        needs_subnet=False,
        network=str(networks[0]),
        host_count=None,
        reason_code=first.code,
        reason=first.message,
    )


def build_interface(
    raw: RawInterface, *, present: bool = True, last_seen_at: datetime | None = None
) -> NetworkInterface:
    connection = _connection(raw.oper_status, present)
    support, support_reason = _support(raw)
    ipv4 = _addresses(raw.ipv4)
    if support == "unsupported":
        capture = CaptureSupport(
            status="unsupported",
            note=support_reason or "Unsupported interface.",
            managed_mode="unsupported",
            monitor_mode="unsupported",
            visibility_scope="None",
        )
    elif raw.kind == "wifi":
        capture = CaptureSupport(
            status="unverified",
            note="Managed-mode Wi-Fi capture decapsulates 802.11 to Ethernet frames. Monitor mode is not supported by the Npcap/NDIS driver on this adapter.",
            managed_mode="supported",
            monitor_mode="driver_limitation",
            visibility_scope="Host unicast, broadcast, and multicast (managed mode - third-party wireless unicast filtered by adapter)",
        )
    else:
        capture = CaptureSupport(
            status="unverified",
            note=_CAPTURE_UNVERIFIED,
            managed_mode="supported",
            monitor_mode="unsupported",
            visibility_scope="Host unicast & LAN broadcast/multicast (managed mode)",
        )

    wireless: WirelessInfo | None = None
    if raw.wireless:
        try:
            wireless = WirelessInfo(**raw.wireless)
        except Exception:
            wireless = None

    return NetworkInterface(
        id=raw.id,
        name=raw.name,
        description=raw.description,
        os_index=raw.os_index,
        kind=raw.kind,  # type: ignore[arg-type]
        if_type=raw.if_type,
        hardware=raw.hardware,  # type: ignore[arg-type]
        mac=raw.mac,
        mac_locally_administered=is_locally_administered(raw.mac) if raw.mac else None,
        connection=connection,  # type: ignore[arg-type]
        oper_status=raw.oper_status,
        present=present,
        last_seen_at=last_seen_at,
        support=support,  # type: ignore[arg-type]
        support_reason=support_reason,
        ipv4=ipv4,
        ipv6=_addresses(raw.ipv6),
        gateways=_usable(raw.gateways),
        dns_servers=_usable(raw.dns_servers),
        mtu=raw.mtu,
        link_speed_mbps=_link_speed_mbps(raw.link_speed_bps),
        dhcp_enabled=raw.dhcp_enabled,
        discovery=_discovery(raw, connection, support, ipv4, present),
        capture=capture,
        wireless=wireless,
    )
