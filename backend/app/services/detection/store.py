"""Alert storage (SQLite, through the project's existing engine).

Writing: `write` stores a batch in ONE transaction that takes the database write lock up front (BEGIN IMMEDIATE),
so a read-then-write sequence cannot lose an update to another writer. A batch either lands completely or not at
all. It is only ever called from the alert writer thread (and the API's status changes), never from capture code.

An alert is one row per dedup key. A repeat of a key (in the same run, or after a restart) updates that row. The
stored evidence is the rule's latest cumulative snapshot, copied by value, so flow pruning never touches it.
Reading: plain sessions, no joins on the list, evidence fetched for one alert at a time.
"""

import hashlib
import json
import logging
import math
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import ColumnElement, Engine, case, delete, func, insert, or_, select
from sqlalchemy.orm import Session, load_only

from app.models.alert import AlertEvent, AlertEvidence, AlertRow
from app.models.app_meta import AppMeta
from app.models.detection import DetectionRun
from app.models.device import Device
from app.models.flow import FlowSession
from app.schemas import alerts as api
from app.services.detection.alerts import Alert
from app.services.detection.lifecycle import check_transition, prune_priority
from app.services.detection.rules.base import MAX_EVIDENCE

log = logging.getLogger(__name__)

PRUNE_BATCH = 500
DEFAULT_DAYS, DEFAULT_ROWS = 180, 5_000
DAYS_BOUNDS, ROWS_BOUNDS = (7, 3_650), (100, 100_000)
RUNS_KEPT = 1_000  # finished runs; a run that is still running is never pruned
RELATED_LIMIT = 20
MAX_DAILY_DAYS = 120  # an all-time timeline longer than this is drawn in weeks
MAX_WEEKS = 520
OPEN_STATES = ("open", "investigating")  # deleting one of these is reported to the user
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> datetime:
    return datetime.now(UTC)


class AlertNotFound(LookupError):
    """There is no alert with that id."""


# --- what the writer hands over ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PendingAlert:
    run: int  # the in-memory run key
    alert: Alert  # a snapshot, safe to read from another thread
    occurrences: int  # new occurrences since the last successful write; 0 = only the window moved


@dataclass(frozen=True, slots=True)
class RunRecord:
    key: int
    session_id: int | None
    source: str
    started_at: datetime
    rules: list[dict[str, Any]]
    vantage: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RunFinish:
    key: int
    status: str
    ended_at: datetime
    events_processed: int
    events_dropped: int
    alerts_created: int
    alerts_updated: int
    warnings: list[str]
    findings_suppressed: int = 0
    baseline_updated: bool = False


@dataclass(frozen=True, slots=True)
class WriteResult:
    inserted: int
    updated: int
    run_ids: dict[int, int]  # in-memory run key -> stored run id, for runs started by this write


@dataclass(frozen=True, slots=True)
class PruneResult:
    alerts_deleted: int = 0
    open_deleted: int = 0
    runs_deleted: int = 0


@dataclass(frozen=True, slots=True)
class Retention:
    days: int
    rows: int
    problems: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AlertFilter:
    status: str | None = None
    severity: str | None = None
    category: str | None = None
    rule_id: str | None = None
    device_id: int | None = None
    ip: str | None = None
    min_risk: int | None = None
    since: datetime | None = None  # inclusive, on the last update
    until: datetime | None = None
    search: str | None = None


# --- small helpers ----------------------------------------------------------------------------------------------------


def _dumps(value: object) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def _loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def _clip(text: str, size: int) -> str:
    return text if len(text) <= size else text[:size]


def _fit_key(key: str, size: int) -> str:
    """A key that fits its column and stays unique: long ones keep a prefix and a hash of the whole."""
    if len(key) <= size:
        return key
    return (
        key[: size - 41] + "#" + hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest()
    )  # 41 = 1 + 40


def _packet_time(t: float, fallback: datetime) -> datetime:
    """Packet time as UTC; an impossible value (NaN, negative, beyond year 9999) falls back, never raises."""
    try:
        if not math.isfinite(t) or t < 0:
            return fallback
        return datetime.fromtimestamp(t, UTC)
    except (OverflowError, OSError, ValueError):
        return fallback


def _risk_json(alert: Alert) -> str:
    r = alert.risk
    return _dumps(
        {
            "value": r.value, "severity_pct": r.severity_pct, "confidence_pct": r.confidence_pct,
            "multiplier_pct": r.multiplier_pct, "explanation": r.explanation,
            "factors": [{"name": f.name, "pct": f.pct, "reason": f.reason} for f in r.factors],
        }
    )  # fmt: skip


def _evidence(alert: Alert) -> tuple[list[tuple[str, str, float | None, str, str]], int]:
    """(kind, basis, observed_at, text, data_json) per kept item, and how many were dropped in total."""
    kept = alert.evidence[:MAX_EVIDENCE]
    rows = [
        (_clip(e.kind, 16), _clip(e.basis, 10), e.observed_at, _clip(e.text, 300), _dumps(dict(e.data)))
        for e in kept
    ]  # fmt: skip
    return rows, alert.evidence_dropped + max(0, len(alert.evidence) - len(kept))


def _basis(value: str) -> Literal["observed", "inferred", "inventory"]:
    """Evidence is validated on the way in; an unexpected stored value is shown as the least certain kind."""
    if value == "observed":
        return "observed"
    if value == "inventory":
        return "inventory"
    return "inferred"


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# --- the store ---------------------------------------------------------------------------------------------------------


class AlertStore:
    def __init__(self, engine: Engine, *, clock: Any = _now) -> None:
        self._engine = engine
        self._clock = clock
        self._run_db: dict[
            int, int
        ] = {}  # in-memory run key -> stored run id; touched by the writer only

    @contextmanager
    def _write(self) -> Iterator[Session]:
        """One write transaction. BEGIN IMMEDIATE waits (busy_timeout) for the lock instead of failing later."""
        with Session(self._engine) as db:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    # --- writing (the alert writer thread) ---------------------------------------------------------------------

    def write(
        self,
        starts: Sequence[RunRecord],
        items: Sequence[PendingAlert],
        finishes: Sequence[RunFinish],
    ) -> WriteResult:
        new_ids: dict[int, int] = {}
        inserted = updated = 0
        with self._write() as db:
            now = self._clock()
            sessions = self._existing_sessions(
                db, {s.session_id for s in starts} | {i.alert.session_id for i in items}
            )
            for start in starts:
                if start.key in self._run_db or start.key in new_ids:
                    continue
                row = DetectionRun(
                    session_id=start.session_id if start.session_id in sessions else None,
                    source=start.source,
                    started_at=start.started_at,
                    status="running",
                    rules_json=_dumps(start.rules),
                    vantage_json=_dumps(start.vantage),
                    warnings_json="[]",
                )
                db.add(row)
                db.flush()
                new_ids[start.key] = row.id
            known = {**self._run_db, **new_ids}
            for item in items:
                run_db_id = known.get(item.run)
                session_id = item.alert.session_id if item.alert.session_id in sessions else None
                key = _fit_key(item.alert.dedup_key, 300)
                row = db.scalar(select(AlertRow).where(AlertRow.dedup_key == key))
                if row is None:
                    self._insert(db, item, run_db_id, session_id, now)
                    inserted += 1
                else:
                    self._update(db, row, item, run_db_id, session_id)
                    updated += 1
            for finish in finishes:
                run = db.get(DetectionRun, known[finish.key]) if finish.key in known else None
                if run is None:
                    continue
                run.status, run.ended_at = finish.status, finish.ended_at
                run.findings_suppressed = finish.findings_suppressed
                run.baseline_updated = finish.baseline_updated
                run.events_processed, run.events_dropped = (
                    finish.events_processed,
                    finish.events_dropped,
                )
                run.alerts_created, run.alerts_updated = (
                    finish.alerts_created,
                    finish.alerts_updated,
                )
                run.warnings_json = _dumps(finish.warnings)
        self._run_db.update(new_ids)  # only after the commit
        for finish in finishes:
            self._run_db.pop(finish.key, None)
        return WriteResult(inserted, updated, new_ids)

    def run_db_id(self, key: int) -> int | None:
        return self._run_db.get(key)

    @staticmethod
    def _existing_sessions(db: Session, ids: set[int | None]) -> set[int]:
        wanted = {i for i in ids if i}
        if not wanted:
            return set()
        return set(db.scalars(select(FlowSession.id).where(FlowSession.id.in_(wanted))))

    @staticmethod
    def _device_id(db: Session, kind: str, key: str) -> int | None:
        if kind == "ip":
            stmt = select(Device.id).where(Device.last_ip == key).order_by(Device.last_seen.desc())
        elif kind == "mac":
            stmt = select(Device.id).where(Device.mac == key.lower())
        elif kind == "device" and key.isascii() and key.isdigit():
            stmt = select(Device.id).where(Device.id == int(key))
        else:
            return None
        return db.scalar(stmt.limit(1))

    def _insert(
        self,
        db: Session,
        item: PendingAlert,
        run_db_id: int | None,
        session_id: int | None,
        now: datetime,
    ) -> None:
        a = item.alert
        evidence, dropped = _evidence(a)
        row = AlertRow(
            rule_id=_clip(a.rule_id, 16), rule_version=a.rule_version, category=_clip(a.category, 16),
            title=_clip(a.title, 160), summary=_clip(a.summary, 500), why=a.why,
            benign_json=_dumps(list(a.benign_explanations)), blind_spots_json=_dumps(list(a.blind_spots)),
            severity=a.severity, confidence=a.confidence, risk_score=a.risk.value, risk_json=_risk_json(a),
            status="open", status_changed_at=a.created_at, entity_kind=_clip(a.entity_kind, 10),
            entity_key=_clip(a.entity_key, 80), entity_device_id=self._device_id(db, a.entity_kind, a.entity_key),
            secondary_key=_clip(a.secondary_key, 120), dedup_key=_fit_key(a.dedup_key, 300),
            correlation_group_id=_clip(a.correlation_group_id, 36) if a.correlation_group_id else None,
            observed_start=_packet_time(a.observed_start, a.created_at),
            observed_end=_packet_time(a.observed_end, a.created_at),
            created_at=a.created_at, updated_at=a.updated_at, source=a.source, run_id=run_db_id,
            session_id=session_id, occurrence_count=max(1, item.occurrences),
            recurrence_count=a.recurrence_count, evidence_dropped=dropped,
            params_json=_dumps(dict(a.params)), observed_json=_dumps(dict(a.observed)),
        )  # fmt: skip
        db.add(row)
        db.flush()
        self._add_evidence(db, row.id, evidence)
        db.add(
            AlertEvent(
                alert_id=row.id, at=a.created_at, kind="created", to_status="open",
                data_json=_dumps({"severity": a.severity, "confidence": a.confidence, "risk": a.risk.value}),
            )
        )  # fmt: skip

    @staticmethod
    def _add_evidence(
        db: Session, alert_id: int, evidence: list[tuple[str, str, float | None, str, str]]
    ) -> None:
        if evidence:  # one executemany instead of one ORM object per item
            db.execute(
                insert(AlertEvidence),
                [
                    {
                        "alert_id": alert_id, "seq": seq, "kind": k, "basis": b,
                        "observed_at": t, "text": txt, "data_json": d,
                    }
                    for seq, (k, b, t, txt, d) in enumerate(evidence)
                ],
            )  # fmt: skip

    def _update(
        self,
        db: Session,
        row: AlertRow,
        item: PendingAlert,
        run_db_id: int | None,
        session_id: int | None,
    ) -> None:
        a = item.alert
        row.observed_start = min(row.observed_start, _packet_time(a.observed_start, a.created_at))
        row.observed_end = max(row.observed_end, _packet_time(a.observed_end, a.created_at))
        if item.occurrences <= 0:
            return  # the finding did not change: only the window moved
        before = (row.severity, row.confidence, row.risk_score)
        row.occurrence_count += item.occurrences
        row.updated_at = max(row.updated_at, a.updated_at)
        row.rule_version = a.rule_version
        row.severity, row.confidence, row.risk_score = a.severity, a.confidence, a.risk.value
        row.risk_json = _risk_json(a)
        row.summary, row.why = _clip(a.summary, 500), a.why
        row.observed_json, row.params_json = _dumps(dict(a.observed)), _dumps(dict(a.params))
        if a.correlation_group_id:
            row.correlation_group_id = _clip(a.correlation_group_id, 36)
        if run_db_id is not None:
            row.run_id = run_db_id
        if session_id is not None:
            row.session_id = session_id
        row.recurrence_count = max(row.recurrence_count, a.recurrence_count)
        self._replace_evidence(db, row, a)
        after = (row.severity, row.confidence, row.risk_score)
        if before != after:
            db.add(
                AlertEvent(
                    alert_id=row.id, at=row.updated_at, kind="updated",
                    data_json=_dumps({
                        "from": {"severity": before[0], "confidence": before[1], "risk": before[2]},
                        "to": {"severity": after[0], "confidence": after[1], "risk": after[2]},
                    }),
                )
            )  # fmt: skip
        if row.status == "resolved":  # the one automatic transition: it fired again
            row.status, row.status_changed_at = "open", row.updated_at
            row.recurrence_count += 1
            db.add(
                AlertEvent(
                    alert_id=row.id,
                    at=row.updated_at,
                    kind="reopened",
                    from_status="resolved",
                    to_status="open",
                )
            )
        elif row.status == "false_positive":  # stays closed, but the repeat is not hidden
            last = db.scalar(
                select(AlertEvent.kind)
                .where(AlertEvent.alert_id == row.id)
                .order_by(AlertEvent.id.desc())
                .limit(1)
            )
            if last != "suppressed":
                db.add(AlertEvent(alert_id=row.id, at=row.updated_at, kind="suppressed", from_status="false_positive", to_status="false_positive"))  # fmt: skip

    @staticmethod
    def _replace_evidence(db: Session, row: AlertRow, alert: Alert) -> None:
        """The rule's evidence is a cumulative snapshot: replace the stored set when it changed, never append to it."""
        new, dropped = _evidence(alert)
        old = [
            tuple(r)
            for r in db.execute(
                select(AlertEvidence.kind, AlertEvidence.basis, AlertEvidence.observed_at, AlertEvidence.text, AlertEvidence.data_json)
                .where(AlertEvidence.alert_id == row.id)
                .order_by(AlertEvidence.seq)
            )
        ]  # fmt: skip
        row.evidence_dropped = dropped
        if old == [tuple(n) for n in new]:
            return
        db.execute(delete(AlertEvidence).where(AlertEvidence.alert_id == row.id))
        AlertStore._add_evidence(db, row.id, new)

    # --- user actions --------------------------------------------------------------------------------------------

    def change_status(self, alert_id: int, status: str | None, note: str | None) -> api.AlertDetail:
        """Raises AlertNotFound, TransitionRefused (not in the lifecycle table) or ValueError (nothing to change)."""
        if status is None and note is None:
            raise ValueError("There is nothing to change.")
        now = self._clock()
        with self._write() as db:
            row = db.get(AlertRow, alert_id)
            if row is None:
                raise AlertNotFound(alert_id)
            if status is not None:
                check_transition(row.status, status)
                old = row.status
                row.status, row.status_changed_at, row.status_note = status, now, note
                db.add(AlertEvent(alert_id=row.id, at=now, kind="status_changed", from_status=old, to_status=status, note=note))  # fmt: skip
            else:
                row.status_note = note
                db.add(AlertEvent(alert_id=row.id, at=now, kind="note", from_status=row.status, to_status=row.status, note=note))  # fmt: skip
        detail = self.get_alert(alert_id)
        if detail is None:  # deleted by retention between the two statements
            raise AlertNotFound(alert_id)
        return detail

    # --- reading ------------------------------------------------------------------------------------------------

    @staticmethod
    def _where(flt: AlertFilter) -> list[ColumnElement[bool]]:
        out: list[ColumnElement[bool]] = []
        if flt.status:
            out.append(AlertRow.status == flt.status)
        if flt.severity:
            out.append(AlertRow.severity == flt.severity)
        if flt.category:
            out.append(AlertRow.category == flt.category)
        if flt.rule_id:
            out.append(AlertRow.rule_id == flt.rule_id)
        if flt.device_id is not None:
            out.append(AlertRow.entity_device_id == flt.device_id)
        if flt.ip:
            out.append(or_(AlertRow.entity_key == flt.ip, AlertRow.secondary_key == flt.ip))
        if flt.min_risk is not None:
            out.append(AlertRow.risk_score >= flt.min_risk)
        if flt.since is not None:
            out.append(AlertRow.updated_at >= flt.since)
        if flt.until is not None:
            out.append(AlertRow.updated_at <= flt.until)
        if flt.search:
            like = f"%{_escape_like(flt.search)}%"
            out.append(
                or_(*(col.ilike(like, escape="\\") for col in (
                    AlertRow.title, AlertRow.summary, AlertRow.entity_key, AlertRow.secondary_key, AlertRow.rule_id))
                )
            )  # fmt: skip
        return out

    def list_alerts(
        self, flt: AlertFilter, sort: str, order: str, limit: int, offset: int
    ) -> api.AlertPage:
        keys: list[Any]  # columns and a CASE expression
        if sort == "risk":
            keys = [AlertRow.risk_score, AlertRow.updated_at, AlertRow.id]
        elif sort == "severity":
            rank = case(_SEVERITY_ORDER, value=AlertRow.severity, else_=-1)
            keys = [rank, AlertRow.updated_at, AlertRow.id]
        else:
            keys = [AlertRow.updated_at, AlertRow.id]
        ordering = [k.desc() if order == "desc" else k.asc() for k in keys]
        where = self._where(flt)
        columns = (
            AlertRow.id, AlertRow.rule_id, AlertRow.rule_version, AlertRow.category, AlertRow.title,
            AlertRow.summary, AlertRow.severity, AlertRow.confidence, AlertRow.risk_score, AlertRow.status,
            AlertRow.status_changed_at, AlertRow.entity_kind, AlertRow.entity_key, AlertRow.secondary_key,
            AlertRow.entity_device_id, AlertRow.observed_start, AlertRow.observed_end, AlertRow.created_at,
            AlertRow.updated_at, AlertRow.source, AlertRow.run_id, AlertRow.session_id,
            AlertRow.occurrence_count, AlertRow.recurrence_count, AlertRow.correlation_group_id,
        )  # fmt: skip
        with Session(self._engine) as db:
            total = db.scalar(select(func.count()).select_from(AlertRow).where(*where)) or 0
            rows = db.scalars(
                select(AlertRow)
                .options(load_only(*columns))
                .where(*where)
                .order_by(*ordering)
                .limit(limit)
                .offset(offset)
            ).all()
            items = [api.AlertListItem.model_validate(r, from_attributes=True) for r in rows]
        return api.AlertPage(items=items, total=total, limit=limit, offset=offset)

    def get_alert(self, alert_id: int) -> api.AlertDetail | None:
        with Session(self._engine) as db:
            row = db.get(AlertRow, alert_id)
            if row is None:
                return None
            evidence = db.scalars(
                select(AlertEvidence)
                .where(AlertEvidence.alert_id == alert_id)
                .order_by(AlertEvidence.seq)
            ).all()
            related: list[api.AlertListItem] = []
            if row.correlation_group_id:
                related = [
                    api.AlertListItem.model_validate(r, from_attributes=True)
                    for r in db.scalars(
                        select(AlertRow)
                        .where(AlertRow.correlation_group_id == row.correlation_group_id, AlertRow.id != alert_id)
                        .order_by(AlertRow.updated_at.desc(), AlertRow.id.desc())
                        .limit(RELATED_LIMIT)
                    )
                ]  # fmt: skip
            base = api.AlertListItem.model_validate(row, from_attributes=True).model_dump()
            risk = _loads(row.risk_json, {})
            return api.AlertDetail(
                **base,
                why=row.why,
                benign_explanations=_loads(row.benign_json, []),
                blind_spots=_loads(row.blind_spots_json, []),
                risk=api.RiskBreakdown(
                    value=risk.get("value", row.risk_score),
                    severity_pct=risk.get("severity_pct", 0),
                    confidence_pct=risk.get("confidence_pct", 0),
                    multiplier_pct=risk.get("multiplier_pct", 100),
                    factors=[api.RiskFactorOut(**f) for f in risk.get("factors", [])],
                    explanation=risk.get("explanation", ""),
                ),
                params=_loads(row.params_json, {}),
                observed=_loads(row.observed_json, {}),
                evidence=[
                    api.EvidenceOut(
                        seq=e.seq,
                        kind=e.kind,
                        basis=_basis(e.basis),
                        observed_at=e.observed_at,
                        text=e.text,
                        data=_loads(e.data_json, {}),
                    )
                    for e in evidence
                ],
                evidence_dropped=row.evidence_dropped,
                status_note=row.status_note,
                related=related,
            )

    def events(self, alert_id: int, limit: int, offset: int) -> api.AlertEventPage | None:
        with Session(self._engine) as db:
            if db.scalar(select(AlertRow.id).where(AlertRow.id == alert_id)) is None:
                return None
            total = (
                db.scalar(
                    select(func.count())
                    .select_from(AlertEvent)
                    .where(AlertEvent.alert_id == alert_id)
                )
                or 0
            )
            rows = db.scalars(
                select(AlertEvent).where(AlertEvent.alert_id == alert_id)
                .order_by(AlertEvent.at, AlertEvent.id).limit(limit).offset(offset)
            ).all()  # fmt: skip
            items = [
                api.AlertEventOut(id=e.id, at=e.at, kind=e.kind, from_status=e.from_status, to_status=e.to_status, note=e.note, data=_loads(e.data_json, None))
                for e in rows
            ]  # fmt: skip
        return api.AlertEventPage(items=items, total=total, limit=limit, offset=offset)

    def summary(self, flt: AlertFilter, range_: str = "24h") -> api.AlertSummary:
        where = self._where(flt)
        now = self._clock()
        end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        start = end - timedelta(hours=24)

        def counts(column: Any) -> dict[str, int]:
            return {
                str(k): int(n)
                for k, n in db.execute(select(column, func.count()).where(*where).group_by(column))
            }

        with Session(self._engine) as db:
            total = db.scalar(select(func.count()).select_from(AlertRow).where(*where)) or 0
            by_severity = counts(AlertRow.severity)
            by_status = counts(AlertRow.status)
            by_category = counts(AlertRow.category)
            top = db.execute(
                select(AlertRow.rule_id, func.count().label("n")).where(*where)
                .group_by(AlertRow.rule_id).order_by(func.count().desc(), AlertRow.rule_id).limit(10)
            ).all()  # fmt: skip
            created = db.scalars(
                select(AlertRow.created_at).where(
                    *where, AlertRow.created_at >= start, AlertRow.created_at < end
                )
            ).all()
            step, line_start, width, count = self._timeline_shape(db, where, range_, now)
            stamps = (
                db.scalars(
                    select(AlertRow.created_at).where(*where, AlertRow.created_at >= line_start)
                ).all()
                if count
                else []
            )
        line = [0] * count
        for moment in stamps:
            slot = int((moment - line_start).total_seconds() // width.total_seconds())
            if 0 <= slot < count:
                line[slot] += 1
        buckets = [0] * 24
        for moment in created:
            buckets[min(23, int((moment - start).total_seconds() // 3600))] += 1
        return api.AlertSummary(
            total=total,
            by_severity={k: by_severity[k] for k in _SEVERITY_ORDER if k in by_severity},
            by_status=by_status,
            by_category=by_category,
            top_rules=[api.RuleCount(rule_id=r, count=n) for r, n in top],
            created_last_24h=[api.HourBucket(start=start + timedelta(hours=i), count=c) for i, c in enumerate(buckets)],
            timeline_step=step,  # type: ignore[arg-type]
            timeline=[api.HourBucket(start=line_start + width * i, count=c) for i, c in enumerate(line)],
        )  # fmt: skip

    @staticmethod
    def _timeline_shape(
        db: Session, where: list[Any], range_: str, now: datetime
    ) -> tuple[str, datetime, timedelta, int]:
        """(step name, first bucket start, bucket width, bucket count) for the chosen range. Count 0 means no alerts."""
        if range_ == "24h":
            end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            return "hour", end - timedelta(hours=24), timedelta(hours=1), 24
        end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        if range_ in ("7d", "30d"):
            days = 7 if range_ == "7d" else 30
            return "day", end - timedelta(days=days), timedelta(days=1), days
        first = db.scalar(select(func.min(AlertRow.created_at)).where(*where))
        if first is None:
            return "day", end, timedelta(days=1), 0
        span = max(1, (end - first.replace(hour=0, minute=0, second=0, microsecond=0)).days)
        if span <= MAX_DAILY_DAYS:
            return "day", end - timedelta(days=span), timedelta(days=1), span
        weeks = min(MAX_WEEKS, -(-span // 7))
        return "week", end - timedelta(weeks=weeks), timedelta(weeks=1), weeks

    def list_runs(self, limit: int, offset: int) -> api.StoredRunPage:
        with Session(self._engine) as db:
            total = db.scalar(select(func.count()).select_from(DetectionRun)) or 0
            rows = db.scalars(
                select(DetectionRun)
                .order_by(DetectionRun.started_at.desc(), DetectionRun.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            items = [
                api.StoredRun(
                    id=r.id, session_id=r.session_id, source=r.source,  # type: ignore[arg-type]
                    started_at=r.started_at, ended_at=r.ended_at, status=r.status,  # type: ignore[arg-type]
                    events_processed=r.events_processed, events_dropped=r.events_dropped,
                    alerts_created=r.alerts_created, alerts_updated=r.alerts_updated,
                    findings_suppressed=r.findings_suppressed, baseline_updated=r.baseline_updated,
                    warnings=_loads(r.warnings_json, []), rules=_loads(r.rules_json, []),
                    vantage=_loads(r.vantage_json, {}),
                )
                for r in rows
            ]  # fmt: skip
        return api.StoredRunPage(items=items, total=total, limit=limit, offset=offset)

    def count_alerts(self) -> int:
        with Session(self._engine) as db:
            return db.scalar(select(func.count()).select_from(AlertRow)) or 0

    # --- start-up, retention, delete-all ----------------------------------------------------------------------

    def recover(self) -> int:
        """Runs still marked running belong to a process that is gone: mark them aborted. Their alerts stay."""
        now = self._clock()
        with self._write() as db:
            rows = db.scalars(select(DetectionRun).where(DetectionRun.status == "running")).all()
            for run in rows:
                run.status, run.ended_at = "aborted", now
                warnings = _loads(run.warnings_json, [])
                warnings.append(
                    "The session did not finish: the application closed or stopped unexpectedly."
                )
                run.warnings_json = _dumps(warnings)
            return len(rows)

    def retention(self) -> Retention:
        keys = {
            "retention.alert_days": (DEFAULT_DAYS, DAYS_BOUNDS),
            "retention.alert_max": (DEFAULT_ROWS, ROWS_BOUNDS),
        }
        with Session(self._engine) as db:
            stored = dict(
                db.execute(select(AppMeta.key, AppMeta.value).where(AppMeta.key.in_(keys))).all()
            )
        values: dict[str, int] = {}
        problems: list[str] = []
        for key, (default, (low, high)) in keys.items():
            raw = stored.get(key)
            value = default
            if raw is not None:
                if raw.isascii() and raw.isdigit() and low <= int(raw) <= high:
                    value = int(raw)
                else:
                    problems.append(
                        f"{key} must be a whole number from {low} to {high}; the default {default} is used."
                    )
            values[key] = value
        return Retention(values["retention.alert_days"], values["retention.alert_max"], problems)

    def prune(self, *, days: int, rows: int) -> PruneResult:
        """Delete alerts past the age limit, then the oldest ones over the row limit (closed first), in small batches."""
        cutoff = self._clock() - timedelta(days=days)
        deleted = opened = 0
        while True:
            with self._write() as db:
                batch = db.execute(
                    select(AlertRow.id, AlertRow.status).where(AlertRow.created_at < cutoff)
                    .order_by(AlertRow.created_at, AlertRow.id).limit(PRUNE_BATCH)
                ).all()  # fmt: skip
                if not batch:
                    break
                db.execute(delete(AlertRow).where(AlertRow.id.in_([b.id for b in batch])))
            deleted += len(batch)
            opened += sum(1 for b in batch if b.status in OPEN_STATES)
        priority = case({s: prune_priority(s) for s in ("open", "acknowledged", "investigating", "resolved", "false_positive", "suppressed")}, value=AlertRow.status, else_=2)  # fmt: skip
        while True:
            with self._write() as db:
                excess = (db.scalar(select(func.count()).select_from(AlertRow)) or 0) - rows
                if excess <= 0:
                    break
                batch = db.execute(
                    select(AlertRow.id, AlertRow.status).order_by(priority, AlertRow.created_at, AlertRow.id)
                    .limit(min(excess, PRUNE_BATCH))
                ).all()  # fmt: skip
                db.execute(delete(AlertRow).where(AlertRow.id.in_([b.id for b in batch])))
            deleted += len(batch)
            opened += sum(1 for b in batch if b.status in OPEN_STATES)
        return PruneResult(deleted, opened, self._prune_runs())

    def _prune_runs(self) -> int:
        removed = 0
        while True:
            with self._write() as db:
                stale = db.scalars(
                    select(DetectionRun.id).where(DetectionRun.status != "running")
                    .order_by(DetectionRun.started_at.desc(), DetectionRun.id.desc())
                    .offset(RUNS_KEPT).limit(PRUNE_BATCH)
                ).all()  # fmt: skip
                if not stale:
                    return removed
                db.execute(delete(DetectionRun).where(DetectionRun.id.in_(stale)))
            removed += len(stale)

    def delete_history(self) -> api.DeleteHistoryResult:
        """Alerts (with their evidence and events) and finished runs. A run that is still running is kept so its
        live alerts still link to it. Rule settings, suppressions, inventory, flows and captures are not touched."""
        alerts = runs = 0
        while True:
            with self._write() as db:
                ids = db.scalars(select(AlertRow.id).order_by(AlertRow.id).limit(PRUNE_BATCH)).all()
                if not ids:
                    break
                db.execute(delete(AlertRow).where(AlertRow.id.in_(ids)))
            alerts += len(ids)
        while True:
            with self._write() as db:
                ids = db.scalars(
                    select(DetectionRun.id)
                    .where(DetectionRun.status != "running")
                    .order_by(DetectionRun.id)
                    .limit(PRUNE_BATCH)
                ).all()
                if not ids:
                    break
                db.execute(delete(DetectionRun).where(DetectionRun.id.in_(ids)))
            runs += len(ids)
        return api.DeleteHistoryResult(alerts_deleted=alerts, runs_deleted=runs)


__all__ = [
    "AlertFilter",
    "AlertNotFound",
    "AlertStore",
    "PendingAlert",
    "PruneResult",
    "Retention",
    "RunFinish",
    "RunRecord",
    "WriteResult",
]
