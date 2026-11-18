"""Alerts held in memory for one analysis run: deduplicated, grouped, bounded.

M2 keeps alerts in memory only (no database table, no persistent API; those are a later step). An alert
copies its evidence by value, so it never depends on flow rows that the flow store later prunes.
"""

from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from app.services.detection.risk import RiskResult
from app.services.detection.rules.base import MAX_EVIDENCE, EvidenceItem, Finding, Severity

MAX_ALERTS_PER_RUN = 1_000
EPISODE_GAP_SECONDS = 60.0  # findings closer together than this belong to one alert
MAX_EPISODES_REMEMBERED = 10_000
MERGED_ITEMS_PER_RULE = (
    3  # a merged rule adds at most this many evidence items to the alert it joins
)


def compose_evidence(
    own: tuple[EvidenceItem, ...],
    own_dropped: int,
    merged: tuple[tuple[str, tuple[EvidenceItem, ...]], ...],
) -> tuple[tuple[EvidenceItem, ...], int]:
    """The alert's evidence: merged items are kept whole and the rule's own items give way, up to the cap of 30."""
    extra = tuple(item for _, items in merged for item in items)
    room = max(0, MAX_EVIDENCE - len(extra))
    visible = own[:room]
    return visible + extra, own_dropped + len(own) - len(visible)


@dataclass(slots=True)
class Alert:
    id: int
    run_id: int
    rule_id: str
    rule_version: int
    category: str
    title: str
    summary: str
    why: str
    benign_explanations: tuple[str, ...]
    blind_spots: tuple[str, ...]
    severity: Severity
    confidence: str
    risk: RiskResult
    status: str  # "open" in M2; the lifecycle comes with persistence
    entity_kind: str
    entity_key: str
    secondary_key: str
    dedup_key: str
    correlation_group_id: str
    observed_start: float  # packet time
    observed_end: float
    created_at: datetime  # wall clock
    updated_at: datetime
    source: str  # live | file
    session_id: int
    occurrence_count: int
    recurrence_count: int
    evidence: tuple[EvidenceItem, ...]
    evidence_dropped: int
    observed: Mapping[str, object]
    params: Mapping[str, int | float]
    fingerprint: tuple[object, ...] = ()
    last_finding_t: float = 0.0
    # The rule's own evidence (at most 30 items) and what other rules merged into this alert (rule id -> items).
    # `evidence` is the two put together, capped at 30 in all. Tuples, so a snapshot never changes underneath a reader.
    own_evidence: tuple[EvidenceItem, ...] = ()
    own_dropped: int = 0
    merged_evidence: tuple[tuple[str, tuple[EvidenceItem, ...]], ...] = ()


@dataclass(slots=True)
class BookCounters:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    evicted: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)


class AlertBook:
    """Create-or-update by dedup key. One alert per (rule, entity, secondary, episode)."""

    def __init__(
        self,
        run_id: int,
        *,
        max_alerts: int = MAX_ALERTS_PER_RUN,
        episode_gap: float = EPISODE_GAP_SECONDS,
    ) -> None:
        self.run_id = run_id
        self._max = max_alerts
        self._gap = episode_gap
        self._alerts: OrderedDict[int, Alert] = OrderedDict()
        self._active: OrderedDict[str, int] = (
            OrderedDict()
        )  # base key -> id of the alert whose episode is open
        self._episodes: OrderedDict[str, int] = OrderedDict()  # base key -> episodes seen so far
        self._next_id = 1
        self.counters = BookCounters()

    def __len__(self) -> int:
        return len(self._alerts)

    def upsert(
        self,
        finding: Finding,
        *,
        rule_version: int,
        risk: RiskResult,
        confidence: str,
        group_id: str,
        source: str,
        session_id: int,
        params: Mapping[str, int | float],
        now: datetime,
        bucket_seconds: float,
    ) -> tuple[Alert, str]:
        """Returns the alert and what happened to it: created, updated or unchanged."""
        base = f"{finding.rule_id}|{finding.entity.kind}:{finding.entity.key}|{finding.secondary}"
        start, end = finding.window
        existing_id = self._active.get(base)
        existing = self._alerts.get(existing_id) if existing_id is not None else None
        if existing is not None and start - existing.observed_end <= self._gap:
            return existing, self._update(existing, finding, risk, confidence, group_id, now, end)
        episodes = self._episodes.get(base, 0)
        self._episodes[base] = episodes + 1
        self._episodes.move_to_end(base)
        while len(self._episodes) > MAX_EPISODES_REMEMBERED:
            self._episodes.popitem(last=False)
        bucket = int(start // bucket_seconds) if bucket_seconds > 0 else 0
        kept = finding.evidence[:MAX_EVIDENCE]
        total = (
            finding.evidence_total if finding.evidence_total is not None else len(finding.evidence)
        )
        own_dropped = max(0, total - len(kept))
        alert = Alert(
            id=self._next_id,
            run_id=self.run_id,
            rule_id=finding.rule_id,
            rule_version=rule_version,
            category=finding.category,
            title=finding.title,
            summary=finding.summary,
            why=finding.why,
            benign_explanations=finding.benign_explanations,
            blind_spots=finding.blind_spots,
            severity=finding.severity,
            confidence=confidence,
            risk=risk,
            status="open",
            entity_kind=finding.entity.kind,
            entity_key=finding.entity.key,
            secondary_key=finding.secondary,
            dedup_key=f"{base}|{bucket}",
            correlation_group_id=group_id,
            observed_start=start,
            observed_end=end,
            created_at=now,
            updated_at=now,
            source=source,
            session_id=session_id,
            occurrence_count=1,
            recurrence_count=episodes,  # earlier episodes of the same key
            evidence=kept,
            evidence_dropped=own_dropped,
            own_evidence=kept,
            own_dropped=own_dropped,
            observed=finding.observed,
            params=params,
            fingerprint=finding.fingerprint,
            last_finding_t=end,
        )
        self._next_id += 1
        self._alerts[alert.id] = alert
        self._active[base] = alert.id
        self._active.move_to_end(base)
        self.counters.created += 1
        self.counters.by_severity[alert.severity] = (
            self.counters.by_severity.get(alert.severity, 0) + 1
        )
        while len(self._alerts) > self._max:
            old_id, _ = self._alerts.popitem(last=False)
            self.counters.evicted += 1
            for key, active_id in list(self._active.items()):
                if active_id == old_id:
                    del self._active[key]
        return alert, "created"

    def _update(
        self,
        alert: Alert,
        finding: Finding,
        risk: RiskResult,
        confidence: str,
        group_id: str,
        now: datetime,
        end: float,
    ) -> str:
        alert.observed_end = max(alert.observed_end, end)
        alert.last_finding_t = max(alert.last_finding_t, end)
        if finding.fingerprint == alert.fingerprint and risk.value == alert.risk.value:
            self.counters.unchanged += 1
            return "unchanged"
        kept = finding.evidence[:MAX_EVIDENCE]
        total = (
            finding.evidence_total if finding.evidence_total is not None else len(finding.evidence)
        )
        if finding.severity != alert.severity:
            self.counters.by_severity[alert.severity] = max(
                0, self.counters.by_severity.get(alert.severity, 0) - 1
            )
            self.counters.by_severity[finding.severity] = (
                self.counters.by_severity.get(finding.severity, 0) + 1
            )
        alert.severity = finding.severity
        alert.confidence = confidence
        alert.risk = risk
        alert.summary = finding.summary
        alert.why = finding.why
        alert.own_evidence = kept
        alert.own_dropped = max(0, total - len(kept))
        alert.evidence, alert.evidence_dropped = compose_evidence(
            kept, alert.own_dropped, alert.merged_evidence
        )
        alert.observed = (
            {**finding.observed, "merged_rules": sorted(k for k, _ in alert.merged_evidence)}
            if alert.merged_evidence
            else finding.observed
        )
        alert.fingerprint = finding.fingerprint
        alert.correlation_group_id = group_id
        alert.updated_at = now
        alert.occurrence_count += 1
        self.counters.updated += 1
        return "updated"

    def find_active(
        self, rule_id: str, entity_kind: str, entity_key: str, secondary: str, start: float
    ) -> Alert | None:
        """The alert of `rule_id` for this entity and secondary key whose episode is still open at packet time `start`."""
        base = f"{rule_id}|{entity_kind}:{entity_key}|{secondary}"
        alert_id = self._active.get(base)
        alert = self._alerts.get(alert_id) if alert_id is not None else None
        if alert is not None and start - alert.observed_end <= self._gap:
            return alert
        return None

    def attach(
        self, alert: Alert, rule_id: str, items: tuple[EvidenceItem, ...], now: datetime
    ) -> None:
        """Merge another rule's evidence into `alert` (replacing what that rule merged before). No second alert."""
        merged = dict(alert.merged_evidence)
        merged[rule_id] = items[:MERGED_ITEMS_PER_RULE]
        alert.merged_evidence = tuple(merged.items())
        alert.evidence, alert.evidence_dropped = compose_evidence(
            alert.own_evidence, alert.own_dropped, alert.merged_evidence
        )
        alert.observed = {**alert.observed, "merged_rules": sorted(merged)}
        alert.updated_at = now
        alert.occurrence_count += 1
        self.counters.updated += 1

    def recurrences_for(self, finding: Finding) -> int:
        """Earlier episodes of the same key, as the new or continuing alert will count them."""
        base = f"{finding.rule_id}|{finding.entity.kind}:{finding.entity.key}|{finding.secondary}"
        active_id = self._active.get(base)
        active = self._alerts.get(active_id) if active_id is not None else None
        if active is not None and finding.window[0] - active.observed_end <= self._gap:
            return active.recurrence_count
        return self._episodes.get(base, 0)

    def all(self) -> list[Alert]:
        return list(self._alerts.values())

    def get(self, alert_id: int) -> Alert | None:
        return self._alerts.get(alert_id)
