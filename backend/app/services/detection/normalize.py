"""Event validation. A malformed event is counted by reason and dropped; it never reaches a rule."""

import math
from functools import lru_cache
from ipaddress import ip_address

from app.services.detection.events import (
    ArpObserved,
    DnsObserved,
    FlowOpened,
    FlowResponded,
    FlowRetired,
    IcmpObserved,
    InventoryDevicesNew,
    TickSummary,
)

REASONS = ("unknown_event", "bad_time", "bad_address", "bad_port", "bad_field")


@lru_cache(maxsize=8192)
def _valid_ip_text(value: str) -> bool:
    # The same few hundred addresses recur in every event; parsing each one afresh was a third of the cost of a DNS event.
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _ip(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 45:
        return False
    return _valid_ip_text(value)


MAX_QNAME = 1_024


def _small_int(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _port(value: object) -> bool:
    return value is None or (
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535
    )


def _time(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def check(event: object) -> str | None:
    """None when the event is usable, otherwise the reason it is not."""
    if isinstance(event, FlowOpened):
        if not _time(event.t):
            return "bad_time"
        if not (_ip(event.src_ip) and _ip(event.dst_ip)):
            return "bad_address"
        if not (_port(event.src_port) and _port(event.dst_port)):
            return "bad_port"
        if not isinstance(event.flow_seq, int) or not isinstance(event.transport, str):
            return "bad_field"
        return None
    if isinstance(event, FlowResponded):
        if not _time(event.t):
            return "bad_time"
        if not isinstance(event.flow_seq, int) or event.kind not in (
            "established",
            "refused",
            "answered",
        ):
            return "bad_field"
        return None
    if isinstance(event, FlowRetired):
        if not (_time(event.t) and _time(event.first_seen) and _time(event.last_seen)):
            return "bad_time"
        if not (_ip(event.src_ip) and _ip(event.dst_ip)):
            return "bad_address"
        if not (_port(event.src_port) and _port(event.dst_port)):
            return "bad_port"
        counters = (event.packets_fwd, event.packets_rev, event.bytes_fwd, event.bytes_rev)
        if not isinstance(event.flow_seq, int) or any(
            not isinstance(c, int) or isinstance(c, bool) or c < 0 for c in counters
        ):
            return "bad_field"
        return None
    if isinstance(event, TickSummary):
        if not _time(event.t):
            return "bad_time"
        if not isinstance(event.dropped_events, int) or event.dropped_events < 0:
            return "bad_field"
        return None
    if isinstance(event, DnsObserved):
        if not _time(event.t):
            return "bad_time"
        if not (_ip(event.client_ip) and _ip(event.server_ip)):
            return "bad_address"
        if not _port(event.server_port):
            return "bad_port"
        if not isinstance(event.qname, str) or len(event.qname) > MAX_QNAME:
            return "bad_field"  # a name longer than the parser ever produces is not a name
        if event.transport is not None and not isinstance(event.transport, str):
            return "bad_field"
        if event.qtype is not None and not _small_int(event.qtype, 0, 65535):
            return "bad_field"
        if event.rcode is not None and not _small_int(event.rcode, 0, 15):
            return "bad_field"
        return None
    if isinstance(event, IcmpObserved):
        if not _time(event.t):
            return "bad_time"
        return None if _ip(event.src_ip) and _ip(event.dst_ip) else "bad_address"
    if isinstance(event, ArpObserved):
        return None if _time(event.t) else "bad_time"
    if isinstance(event, InventoryDevicesNew):
        if not _time(event.t):
            return "bad_time"
        return (
            None if isinstance(event.devices, tuple) and len(event.devices) <= 500 else "bad_field"
        )
    return "unknown_event"
