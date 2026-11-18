"""Typed telemetry events handed from the flow engine to whatever analyses them (Phase 4).

Plain immutable values, built from fields the existing tshark pass already decoded. All times are
**packet time** (epoch seconds), never the wall clock, so a replayed file behaves like the live run.
Nothing here reads a database, a socket or a clock.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FlowOpened:
    """The first packet of a new flow was seen."""

    t: float
    session_id: int
    flow_seq: int
    transport: str
    src_ip: str  # the initiator, as chosen by the flow engine
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    basis: str  # syn | syn_ack | first_packet (how the initiator was chosen)
    src_mac: str | None
    dst_mac_hint: str | None
    tcp_syn_only: bool  # the first packet was a bare SYN


@dataclass(frozen=True, slots=True)
class FlowRetired:
    """A flow left the active table: it closed, was reset, went idle, ended with the capture, or was evicted."""

    t: float  # packet time of the newest packet the engine had seen when it retired
    session_id: int
    flow_seq: int
    state: str  # closed | reset | idle_timeout | capture_ended | evicted
    transport: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    packets_fwd: int
    packets_rev: int
    bytes_fwd: int
    bytes_rev: int
    syn: bool
    synack: bool
    rst: bool
    first_seen: float
    last_seen: float
    protocol: str
    application: str | None
    confidence: str
    sni: str | None
    http_host: str | None
    layers: frozenset[str]


@dataclass(frozen=True, slots=True)
class FlowResponded:
    """The first reply to a TCP connection attempt (one whose bare SYN was seen), published when it is seen.

    `kind`: `established` (a SYN-ACK), `refused` (a reset in answer to the SYN), or `answered` (some other reply, so the
    responder is reachable but the SYN-ACK was not captured). A SYN that nobody answers publishes nothing.
    """

    t: float
    session_id: int
    flow_seq: int
    kind: str


@dataclass(frozen=True, slots=True)
class DnsObserved:
    """One DNS question or its answer. `rcode` is set on responses only (tshark prints it only there)."""

    t: float
    client_ip: str
    server_ip: str
    client_mac: str | None
    is_response: bool
    qname: str  # the original text, control characters removed and length limited by the packet parser; inert text only
    qtype: int | None
    rcode: int | None
    server_port: int | None = (
        None  # the port of the server end: where a query went, or where an answer came from
    )
    transport: str | None = None  # "udp" or "tcp"


@dataclass(frozen=True, slots=True)
class IcmpObserved:
    t: float
    src_ip: str
    dst_ip: str
    icmp_type: int
    icmp_code: int | None
    length: int


@dataclass(frozen=True, slots=True)
class ArpObserved:
    t: float
    op: int
    sender_mac: str
    sender_ip: str | None  # "0.0.0.0" for an address-conflict probe
    target_ip: str | None


@dataclass(slots=True)
class HostCounters:
    """What one address did during one second of packet time."""

    packets_out: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    bytes_in: int = 0
    new_flows_out: int = 0
    failed_flows_out: int = 0  # TCP flows it started that ended with a SYN and no SYN-ACK


@dataclass(frozen=True, slots=True)
class TickSummary:
    """Per-address activity for the second of packet time that ended at `t`."""

    t: float
    hosts: Mapping[str, HostCounters] = field(default_factory=dict)
    hosts_omitted: int = 0  # quieter addresses folded into the "*other*" entry
    dropped_events: int = 0  # events the queue has refused since it was created (cumulative)


@dataclass(frozen=True, slots=True)
class NewDevice:
    """One device a finished discovery scan added to the inventory."""

    mac: str
    ip: str | None
    vendor: str | None
    randomized: bool
    first_seen: float  # epoch seconds


@dataclass(frozen=True, slots=True)
class InventoryDevicesNew:
    """Devices recorded for the first time by a discovery scan that finished (rule TT-DEV-001). Not packet telemetry."""

    t: float
    scan_id: str
    inventory_size: int
    devices: tuple[NewDevice, ...]


Event = (
    FlowOpened
    | FlowResponded
    | FlowRetired
    | DnsObserved
    | IcmpObserved
    | ArpObserved
    | InventoryDevicesNew
    | TickSummary
)

OTHER_HOSTS = "*other*"
