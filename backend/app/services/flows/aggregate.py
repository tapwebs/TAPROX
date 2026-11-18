"""Searching, sorting and summarising flow records. Pure functions: no I/O, no shared state.

Every figure is added up from the flow records, so a number on the dashboard can always be traced to
the flows that make it. Nothing here guesses: a flow with no identified application is counted as
"Unclassified".
"""

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.services.flows.engine import FlowRecord

UNCLASSIFIED = "Unclassified"
SORT_KEYS = (
    "first_seen",
    "last_seen",
    "duration",
    "packets",
    "bytes",
    "source",
    "destination",
    "src_port",
    "dst_port",
    "protocol",
    "application",
    "state",
)


def app_name(flow: FlowRecord) -> str:
    return flow.application or UNCLASSIFIED


# --- filtering, sorting, paging --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FlowFilter:
    state: str | None = None
    transport: str | None = None
    protocol: str | None = None
    application: str | None = None
    confidence: str | None = None
    port: int | None = None
    ips: frozenset[str] | None = None  # a flow matches when either endpoint is one of these
    search: str | None = None


def _haystack(flow: FlowRecord) -> str:
    parts = [
        flow.src_ip,
        flow.dst_ip,
        str(flow.src_port or ""),
        str(flow.dst_port or ""),
        flow.transport,
        flow.protocol,
        app_name(flow),
        flow.category,
        flow.sni or "",
        flow.http_host or "",
        flow.dns_hostname or "",
        *flow.dns_names,
    ]
    return "\n".join(parts).lower()


def matches(flow: FlowRecord, f: FlowFilter) -> bool:
    if f.state and flow.state != f.state:
        return False
    if f.transport and flow.transport != f.transport.lower():
        return False
    if f.protocol and flow.protocol.lower() != f.protocol.lower():
        return False
    if f.application and app_name(flow).lower() != f.application.lower():
        return False
    if f.confidence and flow.confidence != f.confidence:
        return False
    if f.port is not None and f.port not in (flow.src_port, flow.dst_port):
        return False
    if f.ips is not None and flow.src_ip not in f.ips and flow.dst_ip not in f.ips:
        return False
    return not (f.search and f.search.lower() not in _haystack(flow))


def _address_key(ip: str) -> tuple[int, int | str]:
    from ipaddress import ip_address

    try:
        value = ip_address(ip)
    except ValueError:
        return (2, ip)
    return (value.version, int(value))


_SORTERS: dict[str, Callable[[FlowRecord], object]] = {
    "first_seen": lambda f: (f.first_seen, f.seq),
    "last_seen": lambda f: (f.last_seen, f.seq),
    "duration": lambda f: (f.duration, f.seq),
    "packets": lambda f: (f.packets, f.seq),
    "bytes": lambda f: (f.bytes, f.seq),
    "source": lambda f: (_address_key(f.src_ip), f.seq),
    "destination": lambda f: (_address_key(f.dst_ip), f.seq),
    "src_port": lambda f: (-1 if f.src_port is None else f.src_port, f.seq),
    "dst_port": lambda f: (-1 if f.dst_port is None else f.dst_port, f.seq),
    "protocol": lambda f: (f.protocol.lower(), f.seq),
    "application": lambda f: (app_name(f).lower(), f.seq),
    "state": lambda f: (f.state, f.seq),
}


def page(
    flows: Iterable[FlowRecord], f: FlowFilter, sort: str, order: str, offset: int, limit: int
) -> tuple[list[FlowRecord], int]:
    """The requested page of matching flows, and how many flows match in total."""
    if sort not in _SORTERS:
        raise ValueError(f"Cannot sort by {sort!r}; use one of: {', '.join(SORT_KEYS)}.")
    selected = [flow for flow in flows if matches(flow, f)]
    selected.sort(key=_SORTERS[sort], reverse=order == "desc")  # type: ignore[arg-type]
    return selected[offset : offset + limit], len(selected)


# --- statistics ------------------------------------------------------------------------------------


def remote_ip(flow: FlowRecord, local: frozenset[str]) -> str:
    """The far end of the flow from this computer; the responder when no local address is known."""
    if flow.dst_ip in local and flow.src_ip not in local:
        return flow.src_ip
    return flow.dst_ip


def best_name(flow: FlowRecord) -> tuple[str | None, str | None]:
    """The most trustworthy name this flow gives for its remote side, and where it came from."""
    if flow.sni:
        return flow.sni, "tls_sni"
    if flow.http_host:
        return flow.http_host, "http_host"
    if flow.dns_hostname:
        return flow.dns_hostname, "dns_answer"
    return None, None


@dataclass(slots=True)
class ProtocolStat:
    protocol: str
    flows: int = 0
    packets: int = 0
    bytes: int = 0


def protocol_stats(flows: Iterable[FlowRecord]) -> list[ProtocolStat]:
    groups: dict[str, ProtocolStat] = {}
    for flow in flows:
        stat = groups.setdefault(flow.protocol, ProtocolStat(flow.protocol))
        stat.flows += 1
        stat.packets += flow.packets
        stat.bytes += flow.bytes
    return sorted(groups.values(), key=lambda s: (-s.bytes, s.protocol))


@dataclass(slots=True)
class Destination:
    address: str
    hostname: str | None = None
    hostname_source: str | None = None
    flows: int = 0
    packets: int = 0
    bytes: int = 0


def destination_stats(flows: Iterable[FlowRecord], local: frozenset[str]) -> list[Destination]:
    groups: dict[str, Destination] = {}
    for flow in flows:
        address = remote_ip(flow, local)
        dest = groups.setdefault(address, Destination(address))
        dest.flows += 1
        dest.packets += flow.packets
        dest.bytes += flow.bytes
        if dest.hostname is None:
            dest.hostname, dest.hostname_source = best_name(flow)
    return sorted(groups.values(), key=lambda d: (-d.bytes, d.address))


@dataclass(slots=True)
class DeviceAppStat:
    address: str
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    last_seen: float = 0.0


@dataclass(slots=True)
class ApplicationStat:
    application: str
    category: str
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    confidence: str = "unknown"
    confirmed_flows: int = 0
    probable_flows: int = 0
    unknown_flows: int = 0
    methods: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    device_stats: list[DeviceAppStat] = field(default_factory=list)
    destinations: list[Destination] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def application_stats(flows: Iterable[FlowRecord], local: frozenset[str]) -> list[ApplicationStat]:
    groups: dict[str, list[FlowRecord]] = defaultdict(list)
    for flow in flows:
        groups[app_name(flow)].append(flow)
    result: list[ApplicationStat] = []
    for name, members in groups.items():
        stat = ApplicationStat(name, members[0].category)
        dev_map: dict[str, DeviceAppStat] = {}
        for flow in members:
            stat.flows += 1
            stat.packets += flow.packets
            stat.bytes += flow.bytes
            if flow.confidence == "confirmed":
                stat.confirmed_flows += 1
            elif flow.confidence == "probable":
                stat.probable_flows += 1
            else:
                stat.unknown_flows += 1

            initiator = flow.src_ip
            d_stat = dev_map.get(initiator)
            if d_stat is None:
                d_stat = dev_map[initiator] = DeviceAppStat(initiator)
            d_stat.flows += 1
            d_stat.packets += flow.packets
            d_stat.bytes += flow.bytes
            d_stat.last_seen = max(d_stat.last_seen, flow.last_seen)

        stat.confidence = (
            "confirmed"
            if stat.confirmed_flows == stat.flows
            else "unknown"
            if stat.confirmed_flows + stat.probable_flows == 0
            else "probable"
        )
        stat.methods = sorted({f.method for f in members if f.method != "none"})
        stat.protocols = sorted({f.protocol for f in members})
        stat.devices = sorted(dev_map.keys(), key=_address_key)[:10]
        stat.device_stats = sorted(dev_map.values(), key=lambda d: -d.bytes)[:10]
        stat.destinations = destination_stats(members, local)[:5]
        biggest = sorted(members, key=lambda f: -f.bytes)
        seen: list[str] = []
        for flow in biggest:
            for line in flow.evidence:
                if line not in seen and len(seen) < 4:
                    seen.append(line)
        stat.evidence = seen
        result.append(stat)
    return sorted(result, key=lambda s: (-s.bytes, s.application))


@dataclass(slots=True)
class EndpointStat:
    address: str
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    sent_bytes: int = 0
    received_bytes: int = 0


def endpoint_stats(flows: Iterable[FlowRecord]) -> list[EndpointStat]:
    groups: dict[str, EndpointStat] = {}
    for flow in flows:
        for ip, sent, received in (
            (flow.src_ip, flow.bytes_fwd, flow.bytes_rev),
            (flow.dst_ip, flow.bytes_rev, flow.bytes_fwd),
        ):
            stat = groups.setdefault(ip, EndpointStat(ip))
            stat.flows += 1
            stat.packets += flow.packets
            stat.bytes += flow.bytes
            stat.sent_bytes += sent
            stat.received_bytes += received
    return sorted(groups.values(), key=lambda s: (-s.bytes, s.address))


@dataclass(slots=True)
class ConversationStat:
    a: str
    b: str
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    applications: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


def conversation_stats(flows: Iterable[FlowRecord]) -> list[ConversationStat]:
    groups: dict[tuple[str, str], ConversationStat] = {}
    for flow in flows:
        a, b = sorted((flow.src_ip, flow.dst_ip), key=_address_key)
        stat = groups.setdefault((a, b), ConversationStat(a, b))
        stat.flows += 1
        stat.packets += flow.packets
        stat.bytes += flow.bytes
        if flow.application and flow.application not in stat.applications:
            stat.applications.append(flow.application)
        if flow.protocol not in stat.protocols:
            stat.protocols.append(flow.protocol)
    return sorted(groups.values(), key=lambda s: (-s.bytes, s.a, s.b))


@dataclass(slots=True)
class Summary:
    observed_flows: int = 0
    active_flows: int = 0
    flows_with_application: int = 0
    one_sided_flows: int = 0
    confirmed_flows: int = 0
    probable_flows: int = 0
    unknown_flows: int = 0


def summarize(flows: Iterable[FlowRecord]) -> Summary:
    s = Summary()
    for flow in flows:
        s.observed_flows += 1
        s.active_flows += flow.state == "active"
        s.flows_with_application += flow.application is not None
        s.one_sided_flows += flow.one_sided
        s.confirmed_flows += flow.confidence == "confirmed"
        s.probable_flows += flow.confidence == "probable"
        s.unknown_flows += flow.confidence == "unknown"
    return s
