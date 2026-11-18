from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

FlowState = Literal["active", "closed", "reset", "idle_timeout", "capture_ended"]
Confidence = Literal["confirmed", "probable", "unknown"]
FlowSort = Literal[
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
]
StartedBy = Literal["this_computer", "another_device", "neither", "unknown"]


class DeviceRef(BaseModel):
    """An inventory device linked to a flow endpoint, and how sure that link is."""

    id: int
    mac: str
    vendor: str | None
    hostname: str | None
    mac_randomized: bool = Field(
        description="The MAC is locally administered, so the same device may appear under other MACs."
    )
    first_seen: datetime
    last_seen: datetime
    match: Literal["ip_and_mac", "ip_only"] = Field(
        description="ip_and_mac: the packets' own Ethernet address agrees with the inventory. "
        "ip_only: matched by IP address alone, which can be out of date."
    )


class EndpointRef(BaseModel):
    address: str
    port: int | None
    is_local_computer: bool = Field(description="An address of the interface being captured on.")
    hostname: str | None = Field(
        default=None,
        description="A name this flow revealed for the remote side (never a reverse lookup).",
    )
    hostname_source: Literal["tls_sni", "http_host", "dns_answer"] | None = None
    device: DeviceRef | None
    device_note: str | None = Field(
        description="Why a likely inventory match was not linked, when that happened."
    )


class FlowSessionInfo(BaseModel):
    id: int
    source: Literal["live", "file"]
    interface_name: str | None
    file_name: str | None
    started_at: datetime
    ended_at: datetime | None
    status: Literal["running", "completed", "failed"]
    current: bool = Field(description="This is the session shown by the Packet Explorer now.")
    packets: int
    bytes: int
    flows: int
    direction_known: bool = Field(
        description="The capturing computer's addresses are known, so sent/received can be told."
    )
    warnings: list[str]


class FlowSessionList(BaseModel):
    sessions: list[FlowSessionInfo]
    total: int
    limit: int
    offset: int


class Flow(BaseModel):
    id: str = Field(description="session-flow, usable with GET /flows/{id}.")
    session_id: int
    source: EndpointRef = Field(description="The side that started the flow (see initiator_basis).")
    destination: EndpointRef
    transport: str
    protocol: str = Field(description="The most specific protocol tshark decoded in the flow.")
    application: str | None
    category: str
    confidence: Confidence
    method: str
    state: FlowState
    packets: int
    bytes: int
    packets_forward: int
    packets_reverse: int
    bytes_forward: int
    bytes_reverse: int
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    one_sided: bool = Field(description="Packets were seen in one direction only.")
    started_by: StartedBy = Field(
        description="From the capturing computer's point of view; unknown when its addresses are not."
    )


class TcpInfo(BaseModel):
    handshake: Literal["complete", "partial", "not_seen"]
    syn: bool
    syn_ack: bool
    fin_from_source: bool
    fin_from_destination: bool
    reset: bool


class FlowDetail(Flow):
    initiator_basis: Literal["syn", "syn_ack", "first_packet"] = Field(
        description="How the source side was chosen: the SYN sender, the SYN-ACK's receiver, or "
        "(a guess) whoever sent the first packet we saw."
    )
    tcp: TcpInfo | None
    protocols: list[str] = Field(description="Protocol layers tshark decoded in this flow.")
    dns_names: list[str]
    server_name: str | None = Field(description="TLS/QUIC server name, when visible.")
    http_host: str | None
    encrypted_client_hello: bool
    dns_hostname: str | None = Field(
        description="A name an earlier DNS answer gave for the remote address."
    )
    evidence: list[str]
    limitations: list[str]
    first_packet: int
    last_packet: int
    packet_explorer_filter: str | None = Field(
        description="A display filter for the Packet Explorer; only while this session's packets "
        "are still the ones loaded there."
    )


class FlowPage(BaseModel):
    flows: list[Flow]
    total: int
    limit: int
    offset: int
    session_id: int | None


class TopEndpoint(BaseModel):
    endpoint: EndpointRef
    flows: int
    packets: int
    bytes: int
    sent_bytes: int
    received_bytes: int


class ProtocolStat(BaseModel):
    protocol: str
    flows: int
    packets: int
    bytes: int


class ProtocolStats(BaseModel):
    session_id: int | None
    protocols: list[ProtocolStat]


class Destination(BaseModel):
    address: str
    hostname: str | None
    hostname_source: Literal["tls_sni", "http_host", "dns_answer"] | None
    flows: int
    packets: int
    bytes: int


class DeviceApplicationStat(BaseModel):
    endpoint: EndpointRef
    flows: int
    packets: int
    bytes: int
    last_seen: datetime | None = None


class ApplicationStat(BaseModel):
    application: str = Field(description="'Unclassified' collects flows nothing identified.")
    category: str
    flows: int
    packets: int
    bytes: int
    confidence: Confidence
    confirmed_flows: int
    probable_flows: int
    unknown_flows: int
    methods: list[str]
    protocols: list[str]
    devices: list[EndpointRef] = Field(description="Endpoints that started these flows.")
    device_stats: list[DeviceApplicationStat] = Field(
        default_factory=list,
        description="Per-device breakdown of this application's observed traffic.",
    )
    destinations: list[Destination]
    evidence: list[str]
    capture_source: str | None = Field(
        default=None,
        description="Capture interface or source type that recorded these flows.",
    )


class ApplicationStats(BaseModel):
    session_id: int | None
    applications: list[ApplicationStat]
    identified_flows: int
    unclassified_flows: int
    capture_source: str | None = Field(
        default=None,
        description="Active capture interface or vantage name.",
    )
    interface_name: str | None = None
    is_wifi: bool = False


class Conversation(BaseModel):
    a: EndpointRef
    b: EndpointRef
    flows: int
    packets: int
    bytes: int
    applications: list[str]
    protocols: list[str]


class ConversationList(BaseModel):
    session_id: int | None
    conversations: list[Conversation]
    total: int


class TimelinePoint(BaseModel):
    start: datetime
    packets: int
    sent_bytes: int
    received_bytes: int
    other_bytes: int


class Timeline(BaseModel):
    session_id: int | None
    width_seconds: int
    points: list[TimelinePoint]
    direction_known: bool


class FlowLimits(BaseModel):
    max_flows: int
    tcp_idle_seconds: float
    tcp_half_open_idle_seconds: float
    udp_idle_seconds: float
    other_idle_seconds: float
    close_linger_seconds: float
    sessions_kept: int


class FlowSummary(BaseModel):
    session: FlowSessionInfo | None
    active_flows: int
    observed_flows: int
    packets: int
    bytes: int
    non_ip_packets: int
    non_ip_bytes: int
    sent_bytes: int
    received_bytes: int
    other_bytes: int
    direction_known: bool
    flows_evicted: int
    flows_with_application: int
    one_sided_flows: int
    confirmed_flows: int
    probable_flows: int
    unknown_flows: int
    top_endpoints: list[TopEndpoint]
    top_protocols: list[ProtocolStat]
    top_destinations: list[Destination]
    top_applications: list[ApplicationStat]
    limits: FlowLimits
    generated_at: datetime
