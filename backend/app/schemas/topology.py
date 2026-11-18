"""Schemas of the network topology API (Phase 4 / M7). Captured names are text only."""

from typing import Literal

from pydantic import BaseModel, Field

NodeType = Literal[
    "this_computer", "device", "gateway", "unresolved_host", "remote_host", "remote_group", "group"
]
EdgeKind = Literal["communication", "via_gateway", "name_service", "on_link"]
Basis = Literal["observed", "inferred", "inventory"]
Confidence = Literal["confirmed", "probable", "unknown"]


class NodeAlertSummary(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    status: str
    why: str
    created_at: str
    observed_start: str | None = None
    observed_end: str | None = None


class TopologyNode(BaseModel):
    key: str = Field(
        description="Stable key, for example device:12, gateway:192.168.1.1 or remote:93.184.216.34."
    )
    type: NodeType
    label: str
    basis: Basis
    ips: list[str]
    mac: str | None
    device_id: int | None
    vendor: str | None
    role: str | None
    trust: str | None
    members: int = Field(
        description="Hosts a remote_group or devices a group stands for; 1 for every other node."
    )
    flows: int
    bytes: int
    first_seen: float | None = Field(
        description="Packet time, seconds since the epoch (history: wall time)."
    )
    last_seen: float | None
    alerts: int = Field(description="Open alerts whose entity is one of this node's addresses.")
    alert_severity: Literal["critical", "high", "medium", "low", "info"] | None = Field(
        default=None,
        description="Highest severity among active alerts on this node, or None if no open alerts."
    )
    alerts_by_severity: dict[str, int] = Field(
        default_factory=dict,
        description="Count of active alerts broken down by severity level."
    )
    alert_details: list[NodeAlertSummary] = Field(
        default_factory=list,
        description="List of active alert summaries for this node."
    )
    visibility_status: Literal[
        "discovered", "partial_visibility", "traffic_observed", "application_identified", "visibility_unavailable", "insufficient_evidence"
    ] | None = Field(
        default=None,
        description="Network capture and traffic visibility status for this node."
    )
    visibility_note: str | None = Field(
        default=None,
        description="Explanation of what traffic can and cannot be observed for this device."
    )
    applications: list[str]
    protocols: list[str]


class TopologyEdge(BaseModel):
    id: str
    kind: EdgeKind
    a: str
    b: str
    basis: Basis
    confidence: Confidence
    reason: str = Field(description="Why this relationship is drawn and how sure it is, in words.")
    flows: int
    bytes: int
    first_seen: float
    last_seen: float
    protocols: list[str]
    applications: list[str]
    evidence: list[str]
    alerts: int
    new: bool = Field(description="History only: first seen inside the chosen window.")


class TopologyCoverage(BaseModel):
    source: Literal["live", "file"]
    vantage_recorded: bool
    interface_name: str | None
    promiscuous: bool | None
    local_addresses: list[str]
    gateways: list[str]
    dns_servers: list[str]
    direction_known: bool
    visibility: Literal["own_traffic_and_broadcast", "promiscuous_switched", "unknown"]
    statement: str
    cannot_see: list[str]


class TopologyGraph(BaseModel):
    session_id: int | None
    window: str
    source: Literal["live", "file"]
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    coverage: TopologyCoverage
    total_nodes: int
    total_edges: int
    reduced: str | None
    grouped_remote_hosts: int
    grouped_by: Literal["role", "vendor", "segment"] | None = Field(
        default=None,
        description="How devices were merged into groups, or null when they are shown one by one.",
    )


class TopologyDay(BaseModel):
    day: str
    flows: int
    bytes: int


class TopologyNodeDetail(BaseModel):
    node: TopologyNode
    edges: list[TopologyEdge] = Field(
        description="The node's relationships, busiest first (at most 25)."
    )
    more_edges: int
    coverage: TopologyCoverage


class TopologyEdgeDetail(BaseModel):
    edge: TopologyEdge
    a: TopologyNode
    b: TopologyNode
    days: list[TopologyDay] = Field(description="History only: flows and bytes per day.")
    coverage: TopologyCoverage
