"""Linking flow endpoints to the Phase 1 device inventory, without trusting an old IP address.

An IP address says little about WHO has it: DHCP moves addresses between devices, and a device can
change MAC address. So a link is made only on evidence that still holds:

  * ip_and_mac - the address is on the capturing computer's own network, so the Ethernet address in
                 its packets IS that host's. If it equals the inventory's MAC the link is certain; if
                 it differs the link is refused and the contradiction is reported.
  * ip_only    - no such check is possible (an opened file, or an address reached through the
                 router). Used only when the inventory saw that address within IP_ONLY_MAX_AGE of
                 the traffic, and always labelled.

Off-link addresses never use the Ethernet address of a packet: that is the router's.
Unknown endpoints stay plain endpoints. Nothing here says anything about trust or intent.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.models.device import Device, DeviceAddress
from app.services.flows.engine import FlowRecord

IP_ONLY_MAX_AGE = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class DeviceLink:
    device_id: int
    mac: str
    vendor: str | None
    hostname: str | None
    mac_randomized: bool
    first_seen: datetime
    last_seen: datetime
    address_last_seen: datetime
    match: str  # ip_and_mac | ip_only


@dataclass(frozen=True, slots=True)
class EndpointInfo:
    address: str
    port: int | None
    is_local_computer: bool
    device: DeviceLink | None
    note: str | None


@dataclass(frozen=True, slots=True)
class _DeviceSnapshot:
    id: int
    mac: str
    vendor: str | None
    hostname: str | None
    mac_randomized: bool
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True, slots=True)
class _Candidate:
    device: _DeviceSnapshot
    address_last_seen: datetime


def _networks(texts: list[str]) -> list[IPv4Network | IPv6Network]:
    result: list[IPv4Network | IPv6Network] = []
    for text in texts:
        try:
            result.append(ip_network(text, strict=False))
        except ValueError:
            continue
    return result


class DeviceResolver:
    def __init__(
        self,
        engine: Engine,
        *,
        local_addresses: frozenset[str],
        local_networks: list[str],
    ) -> None:
        self._engine = engine
        self._local = local_addresses
        self._networks = _networks(local_networks)
        self._cache: dict[str, list[_Candidate]] = {}

    # --- inventory lookups ------------------------------------------------------------------------

    def prefetch(self, addresses: set[str]) -> None:
        """One query for every address not looked up yet."""
        missing = [a for a in addresses if a not in self._cache]
        for start in range(0, len(missing), 400):
            chunk = missing[start : start + 400]
            found: dict[str, list[_Candidate]] = {a: [] for a in chunk}
            with Session(self._engine) as db:
                rows = db.execute(
                    select(
                        DeviceAddress.ip,
                        DeviceAddress.last_seen,
                        Device.id,
                        Device.mac,
                        Device.vendor,
                        Device.hostname,
                        Device.mac_randomized,
                        Device.first_seen,
                        Device.last_seen,
                    )
                    .join(Device, Device.id == DeviceAddress.device_id)
                    .where(DeviceAddress.ip.in_(chunk))
                    .order_by(DeviceAddress.last_seen.desc())
                ).all()
                for (
                    ip,
                    addr_last,
                    dev_id,
                    mac,
                    vendor,
                    hostname,
                    mac_rand,
                    dev_first,
                    dev_last,
                ) in rows:
                    snap = _DeviceSnapshot(
                        id=dev_id,
                        mac=mac,
                        vendor=vendor,
                        hostname=hostname,
                        mac_randomized=mac_rand,
                        first_seen=dev_first,
                        last_seen=dev_last,
                    )
                    found[ip].append(_Candidate(snap, addr_last))
            self._cache.update(found)

    def addresses_of(self, device_id: int) -> set[str]:
        with Session(self._engine) as db:
            return set(
                db.scalars(select(DeviceAddress.ip).where(DeviceAddress.device_id == device_id))
            )

    # --- the rules --------------------------------------------------------------------------------

    def _on_link(self, address: str) -> bool:
        try:
            value = ip_address(address)
        except ValueError:
            return False
        return any(value in net for net in self._networks if net.version == value.version)

    def endpoints(self, flow: FlowRecord) -> tuple[EndpointInfo, EndpointInfo]:
        self.prefetch({flow.src_ip, flow.dst_ip})
        when = datetime.fromtimestamp(flow.last_seen, UTC)
        responder_mac = flow.mac_dst or flow.mac_dst_hint
        return (
            self.endpoint(flow.src_ip, flow.src_port, flow.mac_src, when),
            self.endpoint(flow.dst_ip, flow.dst_port, responder_mac, when),
        )

    def endpoint(
        self, address: str, port: int | None, mac: str | None, when: datetime
    ) -> EndpointInfo:
        local = address in self._local
        candidates = self._cache.get(address, [])
        on_link = self._on_link(address)
        observed = mac.lower() if mac and (on_link or local) else None
        note: str | None = None
        chosen: _Candidate | None = None
        how = "ip_only"
        if observed:
            chosen, how = (
                next((c for c in candidates if c.device.mac == observed), None),
                "ip_and_mac",
            )
            if chosen is None and candidates:
                note = (
                    f"The packets came from MAC {observed}, but the inventory lists "
                    f"{candidates[0].device.mac} for {address}. Not linked."
                )
        elif candidates:
            best = candidates[0]  # the most recently seen holder of this address
            if abs(when - best.address_last_seen) <= IP_ONLY_MAX_AGE:
                chosen = best
            else:
                note = (
                    f"The inventory last saw {address} on {best.address_last_seen:%Y-%m-%d}; "
                    "the address may have changed hands. Not linked."
                )
        link = None
        if chosen is not None:
            d = chosen.device
            link = DeviceLink(
                d.id, d.mac, d.vendor, d.hostname, d.mac_randomized, d.first_seen, d.last_seen,
                chosen.address_last_seen, how,
            )  # fmt: skip
        return EndpointInfo(address, port, local, link, note)
