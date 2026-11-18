"""The detection engine: events in, alerts out. Deterministic, bounded, and safe against a misbehaving rule.

`DetectionEngine` is synchronous and has no thread, clock or I/O of its own, so a test can feed it events and
read the alerts. `DetectionWorker` (service.py) runs it on a thread behind the bounded queue.
"""

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from app.services.detection import normalize
from app.services.detection.alerts import MAX_ALERTS_PER_RUN, Alert, AlertBook
from app.services.detection.baseline import BaselineLearner, BaselineView
from app.services.detection.correlate import CorrelationIndex
from app.services.detection.events import (
    ArpObserved,
    FlowOpened,
    FlowResponded,
    FlowRetired,
    IcmpObserved,
    TickSummary,
)
from app.services.detection.registry import Registry, RuleConfigError, RuleSettings
from app.services.detection.risk import context_factors, score
from app.services.detection.rules.base import (
    CONFIDENCES,
    Confidence,
    Finding,
    LocalScope,
    Rule,
    RuleContext,
)
from app.services.detection.rules.common import normalize_mac
from app.services.detection.windows import CoverageTracker

log = logging.getLogger(__name__)

MAX_HELD = 1_000  # findings of a supporting rule waiting to see whether the rule they support fires
MAX_RULE_ERRORS = 50  # a rule that fails this often in one run is switched off for the rest of it
RULE_STATES = ("evaluating", "disabled", "not_evaluated")


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class RunInfo:
    run_id: int
    session_id: int
    source: str  # live | file
    local: LocalScope


@dataclass(slots=True)
class Counters:
    events: dict[str, int] = field(default_factory=dict)
    malformed: dict[str, int] = field(default_factory=dict)
    findings: int = 0
    self_activity_excluded: int = 0
    rule_errors: dict[str, int] = field(default_factory=dict)
    rejected_findings: int = 0
    sink_errors: int = 0
    held_released_early: int = 0
    findings_suppressed: int = 0


@dataclass(slots=True)
class _Active:
    rule: Rule
    ctx: RuleContext
    window: float
    errors: int = 0


@dataclass(slots=True)
class _Held:
    finding: Finding
    active: _Active
    release_at: float  # packet time


class DetectionEngine:
    def __init__(
        self,
        registry: Registry,
        settings: RuleSettings,
        run: RunInfo,
        *,
        clock: Callable[[], datetime] = utcnow,
        own_activity: Callable[[float], bool] | None = None,
        known_entities: frozenset[str] = frozenset(),
        baseline_ready: bool = False,
        baseline: BaselineView | None = None,
        learner: BaselineLearner | None = None,
        suppressed: frozenset[tuple[str, str, str]] = frozenset(),
        inventory_macs: frozenset[str] = frozenset(),
        inventory_ip_macs: Mapping[str, str] | None = None,
        max_alerts: int = MAX_ALERTS_PER_RUN,
        on_alert: Callable[[Alert, str], None] | None = None,
    ) -> None:
        self.run = run
        self._on_alert = on_alert
        self._clock = clock
        self._own_activity = own_activity or (lambda _t: False)
        self._known = known_entities
        self._suppressed = suppressed
        self._learner = learner
        self._baseline = baseline or BaselineView(ready=baseline_ready)
        baseline_ready = baseline_ready or self._baseline.ready
        self._lock = threading.Lock()
        self.counters = Counters()
        self.processed = 0
        self._event_no = 0
        self._counted_event = -1
        self._replies_seen = (
            0  # TCP replies the capture has shown (for the rules' unanswered-versus-unknown call)
        )
        self.packet_clock = 0.0
        self.gateway_mac_seen: str | None = None
        self.finished = False
        self.coverage = CoverageTracker()
        self.book = AlertBook(run.run_id, max_alerts=max_alerts)
        self.correlation = CorrelationIndex(f"r{run.run_id}")
        self.rule_states: dict[str, tuple[str, str]] = {}
        self._active: dict[str, _Active] = {}
        self._dispatch: dict[str, list[str]] = {}
        self._held: dict[tuple[str, str, str, str], _Held] = {}
        self._next_release = float("inf")
        self._metas = {}
        for spec in registry.specs():
            meta = spec.meta
            self._metas[meta.id] = meta
            if not settings.is_enabled(meta):
                self.rule_states[meta.id] = ("disabled", "switched off")
                continue
            try:
                params = registry.validate(meta.id, settings.overrides.get(meta.id, {}))
            except RuleConfigError as exc:
                self.rule_states[meta.id] = ("not_evaluated", f"invalid setting: {exc}")
                continue
            if meta.requires_baseline and not baseline_ready:
                self.rule_states[meta.id] = ("not_evaluated", "baseline not ready")
                continue
            if meta.requires_direction and not run.local.direction_known:
                self.rule_states[meta.id] = (
                    "not_evaluated",
                    "needs a live capture with a known local address",
                )
                continue
            ctx = RuleContext(
                params=params,
                local=run.local,
                is_self_activity=self._is_self,
                count_self_activity=self._count_self,
                is_self_ip=self._is_self_ip,
                responses_visible=self._responses_visible,
                baseline=self._baseline,
                inventory_macs=inventory_macs,
                inventory_ip_macs=inventory_ip_macs or {},
            )
            self._active[meta.id] = _Active(
                spec.factory(params), ctx, float(params.get("window_s", 60))
            )
            self.rule_states[meta.id] = ("evaluating", "")
            for kind in meta.needs:
                self._dispatch.setdefault(kind, []).append(meta.id)

    # --- hooks given to rules ----------------------------------------------------------------------------------

    def _is_self(self, mac: str | None, t: float) -> bool:
        # Only a live capture shares the wall clock that the scan record uses; an opened file's times mean nothing here.
        own = self.run.local.interface_mac
        return bool(
            self.run.source == "live" and own and mac and mac == own and self._own_activity(t)
        )

    def _is_self_ip(self, ip: str | None, t: float) -> bool:
        return bool(
            self.run.source == "live"
            and ip
            and ip in self.run.local.addresses
            and self._own_activity(t)
        )

    def _responses_visible(self) -> bool:
        return self._replies_seen > 0

    def _count_self(self) -> None:
        # Counted once per event, however many rules excluded it.
        if self._counted_event != self._event_no:
            self._counted_event = self._event_no
            self.counters.self_activity_excluded += 1

    # --- feeding -------------------------------------------------------------------------------------------------

    def process_batch(self, events: Iterable[object]) -> None:
        with self._lock:
            for event in events:
                self._one(event)

    def process(self, event: object) -> None:
        self.process_batch((event,))

    def _one(self, event: object) -> None:
        if self.finished:
            return
        reason = normalize.check(event)
        if reason is not None:
            self.counters.malformed[reason] = self.counters.malformed.get(reason, 0) + 1
            return
        kind = type(event).__name__
        self.counters.events[kind] = self.counters.events.get(kind, 0) + 1
        self.processed += 1
        self._event_no += 1
        t = getattr(event, "t", 0.0)
        self.packet_clock = max(self.packet_clock, t)
        self._see_gateway_mac(event)
        if (
            isinstance(event, FlowResponded)
            or (
                isinstance(event, FlowRetired)
                and event.transport == "tcp"
                and event.packets_rev > 0
            )
            or (isinstance(event, IcmpObserved) and event.icmp_type in (0, 129))  # an echo reply
        ):
            self._replies_seen += 1
        if isinstance(event, TickSummary):
            self.coverage.record(event.t, event.dropped_events, self.processed)
        if self._learner is not None:
            self._learn(event)
        for rule_id in list(self._dispatch.get(kind, ())):
            active = self._active.get(rule_id)
            if active is None:
                continue
            try:
                if isinstance(event, TickSummary):
                    findings = active.rule.on_tick(event, active.ctx)
                else:
                    findings = active.rule.on_event(event, active.ctx)  # type: ignore[arg-type]
                for finding in findings:
                    self._raise(finding, rule_id, active)
            except Exception as exc:
                self._rule_failed(rule_id, active, exc)
        if self._held and self.packet_clock >= self._next_release:
            self._release_due()

    def finish(self) -> None:
        """The run is over: let every rule report what it still holds. Idempotent."""
        with self._lock:
            if self.finished:
                return
            for rule_id, active in list(self._active.items()):
                try:
                    for finding in active.rule.finish(active.ctx):
                        self._raise(finding, rule_id, active)
                except Exception as exc:
                    self._rule_failed(rule_id, active, exc)
            self._release_due(everything=True)
            self.finished = True

    def _rule_failed(self, rule_id: str, active: _Active, exc: Exception) -> None:
        active.errors += 1
        self.counters.rule_errors[rule_id] = self.counters.rule_errors.get(rule_id, 0) + 1
        log.warning(
            "Detection rule %s failed (%s)", rule_id, type(exc).__name__
        )  # the type only: no packet content
        if active.errors >= MAX_RULE_ERRORS:
            self._active.pop(rule_id, None)
            for ids in self._dispatch.values():
                if rule_id in ids:
                    ids.remove(rule_id)
            self.rule_states[rule_id] = (
                "not_evaluated",
                f"switched off after {MAX_RULE_ERRORS} errors in this run",
            )

    # --- from finding to alert -----------------------------------------------------------------------------------

    def _raise(self, finding: Finding, rule_id: str, active: _Active) -> None:
        if finding.rule_id != rule_id:
            self.counters.rejected_findings += 1
            raise ValueError("A rule returned a finding that is not its own.")
        self.counters.findings += 1
        supported = self._metas[rule_id].supports
        if supported is not None:
            self._support(finding, rule_id, active, supported)
            return
        self._raise_alert(finding, rule_id, active)

    # --- a supporting rule: its finding is evidence for another rule's alert, or waits, then stands alone ----------

    def _support(self, finding: Finding, rule_id: str, active: _Active, target: str) -> None:
        alert = self.book.find_active(
            target, finding.entity.kind, finding.entity.key, finding.secondary, finding.window[0]
        )
        if alert is not None:
            self._merge(alert, rule_id, finding)
            return
        key = (rule_id, finding.entity.kind, finding.entity.key, finding.secondary)
        self._held.pop(key, None)  # a newer finding of the same pattern replaces the older one
        release_at = finding.window[1] + active.window
        self._held[key] = _Held(finding, active, release_at)
        self._next_release = min(self._next_release, release_at)
        while len(self._held) > MAX_HELD:
            oldest = self._held.pop(next(iter(self._held)))
            self.counters.held_released_early += 1
            self._raise_alert(oldest.finding, oldest.finding.rule_id, oldest.active)

    def _merge(self, alert: Alert, rule_id: str, finding: Finding) -> None:
        self.book.attach(alert, rule_id, finding.evidence, self._clock())
        self._emit(alert, "updated")

    def _claim_held(self, alert: Alert) -> None:
        # ponytail: a scan of at most MAX_HELD entries per alert raised; index by entity if alerts and holds both grow.
        for key in [
            k
            for k in self._held
            if self._metas[k[0]].supports == alert.rule_id
            and k[1:] == (alert.entity_kind, alert.entity_key, alert.secondary_key)
        ]:
            self._merge(alert, key[0], self._held.pop(key).finding)

    def _release_due(self, *, everything: bool = False) -> None:
        """Report, on their own, the held findings whose hold has passed (all of them when the run ends)."""
        due = [
            (h.release_at, k)
            for k, h in self._held.items()
            if everything or h.release_at <= self.packet_clock
        ]
        for _, key in sorted(due):
            held = self._held.pop(key)
            try:
                self._raise_alert(held.finding, key[0], held.active)
            except Exception as exc:
                self._rule_failed(key[0], held.active, exc)
        self._next_release = min((h.release_at for h in self._held.values()), default=float("inf"))

    def _see_gateway_mac(self, event: object) -> None:
        """The first hardware address a live session saw for its gateway; stored at the end of the run."""
        if self.gateway_mac_seen is not None or self.run.source != "live":
            return
        ip: str | None
        raw: str | None
        if isinstance(event, ArpObserved):
            ip, raw = event.sender_ip, event.sender_mac
        elif isinstance(event, FlowOpened):
            ip, raw = event.src_ip, event.src_mac
        else:
            return
        if ip is not None and ip in self.run.local.gateways:
            self.gateway_mac_seen = normalize_mac(raw)

    def _learn(self, event: object) -> None:
        """Live runs only: what devices normally do, kept for the baseline at the end of the run."""
        learner = self._learner
        if learner is None:
            return
        if isinstance(event, TickSummary):
            learner.tick(event.t, event.hosts)
        elif isinstance(event, FlowRetired) and event.transport in ("tcp", "udp"):
            learner.flow(
                event.t, event.src_ip, event.dst_ip, event.dst_port, event.protocol, event.application,
                event.confidence, event.synack,
            )  # fmt: skip

    def _raise_alert(self, finding: Finding, rule_id: str, active: _Active) -> None:
        meta = self._metas[rule_id]
        if (rule_id, finding.entity.kind, finding.entity.key) in self._suppressed:
            self.counters.findings_suppressed += (
                1  # the user suppressed this rule for this entity: counted, not alerted
            )
            return
        if meta.requires_baseline and self._learner is not None:
            self._learner.exclude_minute(finding.window[1])
        local = self.run.local
        entity_key = f"{finding.entity.kind}:{finding.entity.key}"
        corr = self.correlation.observe(entity_key, rule_id, finding.window[1])
        reduced = self.coverage.reduced(finding.window[0])
        confidence: Confidence = finding.confidence
        if reduced and CONFIDENCES.index(confidence) > CONFIDENCES.index("medium"):
            confidence = "medium"
        sensitive = None
        if finding.target:
            if finding.target in local.gateways:
                sensitive = "the target is the default gateway"
            elif finding.target in local.dns_servers:
                sensitive = "the target is a configured DNS server"
            elif finding.target in local.addresses:
                sensitive = "the target is this computer"
        factors = context_factors(
            other_rules=corr.other_rules,
            recurrences=self.book.recurrences_for(finding),
            sensitive_target=sensitive,
            known_entity=finding.entity.key in self._known,
            reduced_coverage=reduced,
        )
        risk = score(finding.severity, confidence, factors)
        alert, outcome = self.book.upsert(
            finding,
            rule_version=meta.version,
            risk=risk,
            confidence=confidence,
            group_id=corr.group_id,
            source=self.run.source,
            session_id=self.run.session_id,
            params=active.ctx.params,
            now=self._clock(),
            bucket_seconds=active.window,
        )
        if self._on_alert is not None:
            self._emit(alert, outcome)
        if self._held:
            self._claim_held(alert)

    def _emit(self, alert: Alert, outcome: str) -> None:
        """Hand a private snapshot of the alert to the persistence hook. It must be quick, and it cannot hurt detection."""
        hook = self._on_alert
        if hook is None:
            return
        try:
            hook(replace(alert), outcome)
        except Exception as exc:
            self.counters.sink_errors += 1
            log.warning("The alert hook failed (%s)", type(exc).__name__)

    # --- reading ------------------------------------------------------------------------------------------------

    def alerts(self) -> list[Alert]:
        with self._lock:
            return self.book.all()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            diagnostics = {rid: dict(a.rule.diagnostics()) for rid, a in self._active.items()}
            return {
                "processed": self.processed,
                "events": dict(self.counters.events),
                "malformed": dict(self.counters.malformed),
                "findings": self.counters.findings,
                "alerts_created": self.book.counters.created,
                "alerts_updated": self.book.counters.updated,
                "alerts_unchanged": self.book.counters.unchanged,
                "alerts_evicted": self.book.counters.evicted,
                "alerts_in_memory": len(self.book),
                "alerts_by_severity": dict(self.book.counters.by_severity),
                "self_activity_excluded": self.counters.self_activity_excluded,
                "rule_errors": dict(self.counters.rule_errors),
                "rejected_findings": self.counters.rejected_findings,
                "sink_errors": self.counters.sink_errors,
                "findings_suppressed": self.counters.findings_suppressed,
                "held_findings": len(self._held),
                "held_released_early": self.counters.held_released_early,
                "rule_states": dict(self.rule_states),
                "rule_diagnostics": diagnostics,
                "packet_clock": self.packet_clock,
                "finished": self.finished,
            }
