"""The values the topology builder produces. Plain data: no database, no clock, no thread."""

from dataclasses import dataclass, field

NODE_TYPES = (
    "this_computer",
    "device",
    "gateway",
    "unresolved_host",
    "remote_host",
    "remote_group",
    "group",
)
GROUP_MODES = ("auto", "none", "role", "vendor", "segment")
GROUPABLE = ("device", "unresolved_host")  # this computer and the gateway are never grouped
AUTO_GROUP_ABOVE = (
    150  # more devices than this are grouped by segment unless grouping was switched off
)
EDGE_KINDS = ("communication", "via_gateway", "name_service", "on_link")
MAX_NODES = 400
MAX_EDGES = 1_200
REMOTE_INDIVIDUAL_MAX = (
    40  # more remote hosts than this are grouped by name, then application, then "other"
)
MAX_EDGE_EVIDENCE = 5
MAX_LISTED = 8

CANNOT_SEE = (
    "Communication between other devices on this network cannot be seen from this position unless it reaches this capture point.",
    "A relationship is drawn only when a flow between its two ends was observed. A missing line is not proof that nothing happened.",
    "Devices that do not answer discovery and do not appear in traffic are not shown.",
)  # fmt: skip
FILE_NOTE = (
    "Opened file: the vantage point is unknown, local and remote cannot be told apart, "
    "and the relationships shown are only those in the file."
)


@dataclass(frozen=True, slots=True)
class Resident:
    """A device of the inventory, as far as the topology needs it."""

    device_id: int
    mac: str
    hostname: str | None = None
    vendor: str | None = None
    role: str = "unspecified"
    trust: str = "unreviewed"
    last_ip: str | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    last_source: str | None = None


@dataclass(slots=True)
class NodeAlertItem:
    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    why: str
    created_at: str
    observed_start: str | None = None
    observed_end: str | None = None


@dataclass(slots=True)
class Node:
    key: str
    type: str
    label: str
    basis: str  # observed | inventory | inferred
    ips: list[str] = field(default_factory=list)
    mac: str | None = None
    device_id: int | None = None
    vendor: str | None = None
    role: str | None = None
    trust: str | None = None
    members: int = 1
    flows: int = 0
    bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    alerts: int = 0
    alert_severity: str | None = None
    alerts_by_severity: dict[str, int] = field(default_factory=dict)
    alert_details: list[NodeAlertItem] = field(default_factory=list)
    visibility_status: str | None = None
    visibility_note: str | None = None
    applications: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Edge:
    id: str
    kind: str
    a: str
    b: str
    basis: str
    confidence: str  # confirmed | probable
    reason: str
    flows: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    protocols: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    alerts: int = 0
    new: bool = False
    days: list[tuple[str, int, int]] = field(
        default_factory=list
    )  # history only: (day, flows, bytes)


@dataclass(slots=True)
class Coverage:
    source: str
    vantage_recorded: bool
    interface_name: str | None
    promiscuous: bool | None
    local_addresses: list[str]
    gateways: list[str]
    dns_servers: list[str]
    direction_known: bool
    visibility: str  # own_traffic_and_broadcast | promiscuous_switched | unknown
    statement: str
    cannot_see: list[str]


@dataclass(slots=True)
class Graph:
    session_id: int | None
    window: str
    source: str
    nodes: list[Node]
    edges: list[Edge]
    coverage: Coverage
    total_nodes: int
    total_edges: int
    reduced: str | None = None
    grouped_remote_hosts: int = 0
    grouped_by: str | None = None  # role | vendor | segment when devices were merged into groups
