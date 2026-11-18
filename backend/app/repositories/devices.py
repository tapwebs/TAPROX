"""Reads and writes for the device inventory.

Rules that live here (and nowhere else):

* A device is its MAC address. A new IP for a known MAC adds an address-history row; the same IP
  for a different MAC is a different device.
* ``last_seen`` never moves backwards, and the "current" fields (ip, interface, source,
  confidence) always describe the most recent observation. With equal timestamps the stronger
  evidence wins.
* A device that was not observed is not "offline"; its state is derived from how long ago it was
  last seen.
* Observation history is bounded per device so a long-lived inventory cannot grow without limit.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import ColumnElement, Select, delete, func, or_, select
from sqlalchemy.orm import QueryableAttribute, Session

from app.models.device import Device, DeviceAddress, DeviceObservation
from app.services.discovery.oui import OuiDatabase
from app.services.netutil import (
    ip_sort_key,
    is_locally_administered,
    is_unicast_mac,
    normalize_mac,
)

ACTIVE_WINDOW = timedelta(minutes=15)
INACTIVE_WINDOW = timedelta(days=7)
DEFAULT_OBSERVATION_CAP = 200

DeviceState = Literal["active", "inactive", "previously_observed"]
SortField = Literal["last_seen", "first_seen", "ip", "hostname", "vendor", "mac"]
SortOrder = Literal["asc", "desc"]

_STRENGTH = {"confirmed": 3, "probable": 2, "stale": 1}
_HEX = re.compile(r"[0-9a-f]+")


@dataclass(frozen=True)
class Observation:
    """One sighting of a MAC address. Everything here was observed, nothing inferred."""

    mac: str
    ip: str | None
    interface_id: str | None
    source: str
    confidence: str
    observed_at: datetime
    neighbor_state: str | None = None
    hostname: str | None = None
    scan_id: str | None = None


@dataclass(frozen=True)
class DeviceQuery:
    search: str | None = None
    state: DeviceState | None = None
    interface_id: str | None = None
    ip: str | None = None
    scan_id: str | None = None
    sort: SortField = "last_seen"
    order: SortOrder = "desc"
    limit: int = 100
    offset: int = 0


def device_state(last_seen: datetime, now: datetime, confidence: str | None = None) -> DeviceState:
    """Recency of the evidence. A device known only from a stale cache entry is never `active`:
    the operating system remembering an address says nothing about when the device last spoke."""
    age = now - last_seen
    if age <= ACTIVE_WINDOW:
        return "inactive" if confidence == "stale" else "active"
    return "inactive" if age <= INACTIVE_WINDOW else "previously_observed"


def _strength(confidence: str) -> int:
    return _STRENGTH.get(confidence, 0)


# --- writing -------------------------------------------------------------------------------------


def record_observation(
    session: Session,
    obs: Observation,
    *,
    oui: OuiDatabase,
    observation_cap: int = DEFAULT_OBSERVATION_CAP,
) -> tuple[Device, bool]:
    """Fold one sighting into the inventory. Returns the device and whether it was just created."""
    mac = normalize_mac(obs.mac)
    if mac is None or not is_unicast_mac(mac):
        raise ValueError(f"Not a unicast MAC address: {obs.mac!r}")
    if obs.observed_at.tzinfo is None:
        raise ValueError("Naive datetime: timestamps must be timezone-aware")
    if obs.confidence not in _STRENGTH:
        raise ValueError(f"Unknown confidence {obs.confidence!r}")

    device = session.scalar(select(Device).where(Device.mac == mac))
    created = device is None
    if device is None:
        device = Device(
            mac=mac,
            vendor=oui.lookup(mac),
            mac_randomized=is_locally_administered(mac),
            first_seen=obs.observed_at,
            last_seen=obs.observed_at,
            last_ip=obs.ip,
            last_ip_sort=ip_sort_key(obs.ip) if obs.ip else None,
            last_interface_id=obs.interface_id,
            confidence=obs.confidence,
            last_source=obs.source,
            hostname=obs.hostname,
            hostname_source=obs.source if obs.hostname else None,
        )
        session.add(device)
        session.flush()
    else:
        _fold_into(device, obs)

    if obs.ip and obs.interface_id:
        _touch_address(session, device.id, obs.ip, obs.interface_id, obs.observed_at)
    session.add(
        DeviceObservation(
            device_id=device.id,
            observed_at=obs.observed_at,
            source=obs.source,
            ip=obs.ip,
            interface_id=obs.interface_id,
            confidence=obs.confidence,
            neighbor_state=obs.neighbor_state,
            hostname=obs.hostname,
            scan_id=obs.scan_id,
        )
    )
    session.flush()
    _prune_observations(session, device.id, observation_cap)
    return device, created


def _fold_into(device: Device, obs: Observation) -> None:
    newer = obs.observed_at > device.last_seen
    tie_but_stronger = obs.observed_at == device.last_seen and _strength(
        obs.confidence
    ) > _strength(device.confidence)
    if obs.observed_at < device.first_seen:
        device.first_seen = obs.observed_at

    if obs.confidence == "stale":
        # The operating system merely remembers this address. That is not evidence the device is
        # present now, so it never moves last_seen. If nothing better is known the address is still
        # kept current (the entry is all we have); otherwise the better evidence stays.
        if device.confidence == "stale" and newer:
            _take_current_fields(device, obs)
    elif newer or tie_but_stronger:
        device.last_seen = obs.observed_at
        # An IPv6 sighting that does not replace the IPv4 address must not overwrite the evidence
        # behind it: ip, interface, source and confidence always describe one sighting.
        if not obs.ip or _takes_over(device.last_ip, obs.ip):
            _take_current_fields(device, obs)
    # A name is only replaced by another observed name; failing to resolve one must not erase it.
    if obs.hostname and (newer or device.hostname is None):
        device.hostname = obs.hostname
        device.hostname_source = obs.source


def _take_current_fields(device: Device, obs: Observation) -> None:
    device.confidence = obs.confidence
    device.last_source = obs.source
    if obs.ip and _takes_over(device.last_ip, obs.ip):
        device.last_ip = obs.ip
        device.last_ip_sort = ip_sort_key(obs.ip)
    if obs.interface_id:
        device.last_interface_id = obs.interface_id


def _takes_over(current: str | None, new: str) -> bool:
    """IPv4 is the address people recognise: an IPv6 sighting only fills in when none is known."""
    return current is None or ":" not in new or ":" in current


def set_hostname(session: Session, mac: str, name: str, *, source: str) -> bool:
    """Attach a resolved name to a known device. Not a sighting, so no history row is added.

    Returns True when the stored name changed. Unusable names are ignored rather than stored.
    """
    cleaned = name.strip().rstrip(".")
    if not cleaned or len(cleaned) > 253 or any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
        return False
    canonical = normalize_mac(mac)
    device = session.scalar(select(Device).where(Device.mac == canonical)) if canonical else None
    if device is None or device.hostname == cleaned:
        return False
    device.hostname = cleaned
    device.hostname_source = source
    return True


def _touch_address(
    session: Session, device_id: int, ip: str, interface_id: str, at: datetime
) -> None:
    row = session.scalar(
        select(DeviceAddress).where(
            DeviceAddress.device_id == device_id,
            DeviceAddress.ip == ip,
            DeviceAddress.interface_id == interface_id,
        )
    )
    if row is None:
        session.add(
            DeviceAddress(
                device_id=device_id,
                ip=ip,
                ip_sort=ip_sort_key(ip),
                family=6 if ":" in ip else 4,
                interface_id=interface_id,
                first_seen=at,
                last_seen=at,
            )
        )
        return
    row.first_seen = min(row.first_seen, at)
    row.last_seen = max(row.last_seen, at)


def _prune_observations(session: Session, device_id: int, cap: int) -> None:
    surplus = (
        select(DeviceObservation.id)
        .where(DeviceObservation.device_id == device_id)
        .order_by(DeviceObservation.observed_at.desc(), DeviceObservation.id.desc())
        .limit(
            -1
        )  # SQLite: no limit, so that OFFSET alone selects everything after the newest `cap`
        .offset(cap)
    )
    session.execute(delete(DeviceObservation).where(DeviceObservation.id.in_(surplus)))


# --- reading -------------------------------------------------------------------------------------


def get_device(session: Session, device_id: int) -> Device | None:
    return session.get(Device, device_id)


def list_addresses(session: Session, device_id: int) -> list[DeviceAddress]:
    return list(
        session.scalars(
            select(DeviceAddress)
            .where(DeviceAddress.device_id == device_id)
            .order_by(DeviceAddress.last_seen.desc(), DeviceAddress.id.desc())
        )
    )


def list_observations(
    session: Session, device_id: int, *, limit: int, offset: int
) -> tuple[list[DeviceObservation], int]:
    where = DeviceObservation.device_id == device_id
    total = session.scalar(select(func.count()).select_from(DeviceObservation).where(where)) or 0
    rows = session.scalars(
        select(DeviceObservation)
        .where(where)
        .order_by(DeviceObservation.observed_at.desc(), DeviceObservation.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(rows), total


def _like(column: ColumnElement[Any] | QueryableAttribute[Any], term: str) -> ColumnElement[bool]:
    # autoescape makes %, _ and the escape character match literally: the term is only ever text.
    return column.contains(term, autoescape=True)


def _search_clause(term: str) -> ColumnElement[bool]:
    clauses = [
        _like(Device.last_ip, term),
        _like(Device.hostname, term),
        _like(Device.vendor, term),
        Device.id.in_(select(DeviceAddress.device_id).where(_like(DeviceAddress.ip, term))),
    ]
    # MACs are typed with ':', '-' or nothing; compare without separators. Dots are not stripped,
    # so an IP-looking term such as "10.0" is never reinterpreted as the hex digits "100".
    digits = re.sub(r"[\s:\-]", "", term).lower()
    if _HEX.fullmatch(digits):
        clauses.append(_like(func.replace(Device.mac, ":", ""), digits))
    return or_(*clauses)


def _filters(query: DeviceQuery, now: datetime) -> list[ColumnElement[bool]]:
    where: list[ColumnElement[bool]] = []
    if query.search and (term := query.search.strip()):
        where.append(_search_clause(term))
    if query.state == "active":
        where.append(Device.last_seen >= now - ACTIVE_WINDOW)
        where.append(Device.confidence != "stale")
    elif query.state == "inactive":
        where.append(or_(Device.last_seen < now - ACTIVE_WINDOW, Device.confidence == "stale"))
        where.append(Device.last_seen >= now - INACTIVE_WINDOW)
    elif query.state == "previously_observed":
        where.append(Device.last_seen < now - INACTIVE_WINDOW)
    if query.interface_id:
        seen_on = select(DeviceAddress.device_id).where(
            DeviceAddress.interface_id == query.interface_id
        )
        where.append(or_(Device.last_interface_id == query.interface_id, Device.id.in_(seen_on)))
    if query.ip:
        held = select(DeviceAddress.device_id).where(DeviceAddress.ip == query.ip)
        where.append(or_(Device.last_ip == query.ip, Device.id.in_(held)))
    if query.scan_id:
        where.append(
            Device.id.in_(
                select(DeviceObservation.device_id).where(
                    DeviceObservation.scan_id == query.scan_id
                )
            )
        )
    return where


_SORT_COLUMNS: dict[str, QueryableAttribute[Any]] = {
    "last_seen": Device.last_seen,
    "first_seen": Device.first_seen,
    "ip": Device.last_ip_sort,
    "hostname": Device.hostname,
    "vendor": Device.vendor,
    "mac": Device.mac,
}


def list_statement(query: DeviceQuery, *, now: datetime) -> Select[Device]:
    column: ColumnElement[Any] | QueryableAttribute[Any] = _SORT_COLUMNS[query.sort]
    nullable = query.sort in ("ip", "hostname", "vendor")
    if query.sort in ("hostname", "vendor"):
        column = _SORT_COLUMNS[query.sort].collate("NOCASE")
    ordered = column.asc() if query.order == "asc" else column.desc()
    if nullable:
        ordered = ordered.nulls_last()
    tie_break = Device.id.asc() if query.order == "asc" else Device.id.desc()
    return (
        select(Device)
        .where(*_filters(query, now))
        .order_by(ordered, tie_break)
        .limit(query.limit)
        .offset(query.offset)
    )


def list_devices(
    session: Session, query: DeviceQuery, *, now: datetime
) -> tuple[list[Device], int]:
    total = (
        session.scalar(select(func.count()).select_from(Device).where(*_filters(query, now))) or 0
    )
    return list(session.scalars(list_statement(query, now=now))), total
