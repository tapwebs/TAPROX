"""What a rule is: metadata, parameters, and the finding it may return.

A finding cannot exist without evidence, a plain-words explanation, at least one benign explanation and at
least one known blind spot, and none of its text may use the words the wording policy bans. Those checks live
here, in the types, so no rule can skip them.
"""

import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from app.services.detection.baseline import BaselineView
from app.services.detection.events import Event, TickSummary

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Basis = Literal["observed", "inferred", "inventory"]
SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")
CONFIDENCES: tuple[Confidence, ...] = ("low", "medium", "high")

MAX_EVIDENCE = 30  # items kept per alert; more are counted, not kept
MAX_EVIDENCE_TEXT = 300
MAX_EVIDENCE_DATA_BYTES = 4096

# The wording policy (PHASE4_ARCHITECTURE.md section 9.4): a finding is a pattern, never a verdict.
_BANNED = re.compile(
    r"\b(attack\w*|malicious|compromis\w+|infect\w+|hack\w*|safe|clean|threat actor)\b",
    re.IGNORECASE,
)


class WordingError(ValueError):
    """Text that breaks the wording policy."""


def check_wording(*texts: str) -> None:
    for text in texts:
        found = _BANNED.search(text)
        if found:
            raise WordingError(
                f"The word {found.group(0)!r} is not allowed in finding text: {text[:80]!r}"
            )


@dataclass(frozen=True, slots=True)
class ParamSpec:
    """One setting of a rule, with the bounds the server enforces."""

    name: str
    kind: Literal["int", "float"]
    default: int | float
    minimum: int | float
    maximum: int | float
    unit: str
    description: str

    def __post_init__(self) -> None:
        if not self.minimum <= self.default <= self.maximum:
            raise ValueError(f"The default of {self.name} is outside its own bounds.")


@dataclass(frozen=True, slots=True)
class RuleMeta:
    id: str
    name: str
    category: str  # recon | traffic | dns | device | app
    version: int
    severity: Severity  # the base severity; escalation conditions are in the rule
    default_enabled: bool
    needs: frozenset[str]  # event class names the rule consumes
    params: tuple[ParamSpec, ...]
    description: str
    benign: tuple[str, ...]
    blind_spots: tuple[str, ...]
    requires_baseline: bool = False  # such a rule never runs until a baseline is ready
    requires_direction: bool = (
        False  # such a rule needs a live session (a file has no local address)
    )
    supports: str | None = (
        None  # the id of the rule whose alert this rule's findings are merged into, when that rule fires too
    )

    def __post_init__(self) -> None:
        if not self.benign or not self.blind_spots:
            raise ValueError(f"{self.id} needs at least one benign explanation and one blind spot.")
        check_wording(self.name, self.description, *self.benign, *self.blind_spots)


@dataclass(frozen=True, slots=True)
class Entity:
    kind: Literal["ip", "mac", "device", "domain", "network"]
    key: str


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    kind: str  # counter | port_ranges | flow | note | ...
    basis: Basis
    observed_at: float | None  # packet time
    text: str  # a line made from a fixed template and validated values
    data: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.text) > MAX_EVIDENCE_TEXT:
            raise ValueError("Evidence text is too long.")
        if len(json.dumps(self.data, default=str)) > MAX_EVIDENCE_DATA_BYTES:
            raise ValueError("Evidence data is too large.")
        check_wording(self.text)


@dataclass(frozen=True, slots=True)
class ScoreFactor:
    """One named adjustment of the context multiplier, in hundredths (+10 means +0.10)."""

    name: str
    pct: int
    reason: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    entity: Entity
    secondary: str  # the target, parent domain, port-set hash...: the rest of the dedup key
    window: tuple[float, float]  # packet time
    severity: Severity
    confidence: Confidence
    title: str
    summary: str
    why: str
    benign_explanations: tuple[str, ...]
    blind_spots: tuple[str, ...]
    evidence: tuple[EvidenceItem, ...]
    observed: Mapping[str, object]  # the key measured numbers
    category: str = ""
    target: str | None = (
        None  # an address that makes the finding more sensitive (gateway, resolver, this computer)
    )
    evidence_total: int | None = None  # how many items existed before the cap, when known
    fingerprint: tuple[object, ...] = ()  # changes when the finding's content changes

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("A finding without evidence is not allowed.")
        if not self.benign_explanations or not self.blind_spots:
            raise ValueError("A finding needs a benign explanation and a blind spot.")
        if not (math.isfinite(self.window[0]) and math.isfinite(self.window[1])):
            raise ValueError("A finding needs a finite time window.")
        check_wording(
            self.title, self.summary, self.why, *self.benign_explanations, *self.blind_spots
        )


@dataclass(frozen=True, slots=True)
class LocalScope:
    addresses: frozenset[str] = frozenset()
    networks: tuple[str, ...] = ()
    gateways: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()
    interface_mac: str | None = None
    gateway_mac: str | None = (
        None  # the gateway MAC stored for this network by an earlier live session
    )
    direction_known: bool = False  # a live capture knows which addresses are this computer


def _never(_address: str | None, _t: float) -> bool:
    return False


@dataclass(frozen=True, slots=True)
class RuleContext:
    """The read-only view a rule gets. It never touches a database, a socket or a clock."""

    params: Mapping[str, int | float]
    local: LocalScope
    is_self_activity: Callable[
        [str | None, float], bool
    ]  # (source MAC, packet time) -> made by TAPNETTRACK itself
    count_self_activity: Callable[[], None]
    # (source address, packet time) -> this computer's own address while its own discovery scan ran. ICMP events carry
    # no MAC, so the address is what can be matched.
    is_self_ip: Callable[[str | None, float], bool] = _never
    # True once this capture has shown any reply to a TCP connection attempt. Without that, a SYN with no reply may only
    # mean the capture cannot see replies, so silence is not evidence of failure. Defaults to "not shown".
    responses_visible: Callable[[], bool] = lambda: False
    baseline: BaselineView = field(
        default_factory=BaselineView
    )  # stored behaviour of this network's devices; not ready by default
    inventory_macs: frozenset[str] = frozenset()  # MACs in the device inventory (lower case)
    # The inventory's hardware address for each address it knows (lower case), for contradiction checks.
    inventory_ip_macs: Mapping[str, str] = field(default_factory=dict)


class Rule(Protocol):
    meta: RuleMeta

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]: ...

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]: ...

    def finish(self, ctx: RuleContext) -> list[Finding]: ...

    def diagnostics(self) -> Mapping[str, int]: ...
