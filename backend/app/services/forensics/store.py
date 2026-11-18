"""SQLAlchemy persistence layer for Investigations & Forensics (Phase 6)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session

from app.models.app_meta import AppMeta
from app.models.forensics import (
    AuditEvent,
    Investigation,
    InvestigationCorrelation,
    InvestigationCustodyEvent,
    InvestigationEvidence,
    InvestigationNote,
    ReportExport,
)
from app.services.forensics.canonical import canonical_json_str, canonical_sha256
from app.services.forensics.correlate import CorrelationCandidate
from app.services.forensics.custody_chain import (
    GENESIS_HASH,
    ChainLinkInput,
    ChainVerificationResult,
    compute_chain_hash,
    verify_hash_chain,
)
from app.services.forensics.timeline import NoteInput, TimelineEvidenceInput


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class CaseRecord:
    id: int
    case_uid: str
    case_ref: str
    title: str
    summary: str
    classification: str
    severity: str
    status: str
    lead_actor: str
    scope_authorized: bool
    scope_note: str
    tags: list[str]
    evidence_count: int
    custody_head_seq: int
    custody_head_sha256: str
    created_at: datetime
    updated_at: datetime
    sealed_at: datetime | None
    closed_at: datetime | None
    closure_reason: str | None


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    id: int
    investigation_id: int
    evidence_ref: str
    artifact_kind: str
    title: str
    epistemic_basis: str
    storage_mode: str
    canonical_version: int
    hash_algorithm: str
    content_sha256: str
    snapshot: dict[str, Any]
    snapshot_json: str
    vault_relpath: str | None
    external_path_recorded: str | None
    file_size_bytes: int | None
    provenance: dict[str, Any]
    source_table: str | None
    source_record_id: str | None
    observed_start: datetime | None
    observed_end: datetime | None
    integrity_status: str
    last_verified_at: datetime | None
    acquired_by: str
    acquired_at: datetime


@dataclass(frozen=True, slots=True)
class NoteRecord:
    id: int
    investigation_id: int
    note_ref: str
    supersedes_note_id: int | None
    note_kind: str
    confidence: str
    title: str
    body: str
    cited_evidence_ids: list[int]
    content_sha256: str
    actor: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CorrelationRecord:
    id: int
    investigation_id: int
    run_seq: int
    rule_id: str
    indicator_kind: str
    indicator_value: str
    epistemic_basis: str
    confidence: str
    summary: str
    rationale: str
    limitations: list[str]
    evidence_ids: list[int]
    window_start: datetime | None
    window_end: datetime | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CustodyRecord:
    id: int
    investigation_id: int
    seq: int
    occurred_at: datetime
    actor: str
    client_surface: str
    action: str
    evidence_id: int | None
    note_id: int | None
    artifact_sha256: str | None
    details: dict[str, Any]
    prev_event_sha256: str
    event_sha256: str


@dataclass(frozen=True, slots=True)
class AuditRecord:
    id: int
    seq: int
    occurred_at: datetime
    actor: str
    client_surface: str
    category: str
    action: str
    outcome: str
    investigation_id: int | None
    resource_ref: str | None
    details: dict[str, Any]
    prev_audit_sha256: str
    audit_sha256: str


@dataclass(frozen=True, slots=True)
class ExportRecord:
    id: int
    investigation_id: int
    export_ref: str
    format: str
    include_vault_files: bool
    bundle_sha256: str
    byte_size: int
    custody_head_seq: int
    custody_head_sha256: str
    actor: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class PagedResult:
    items: list[Any]
    total: int


def _to_case(row: Investigation) -> CaseRecord:
    return CaseRecord(
        id=row.id,
        case_uid=row.case_uid,
        case_ref=row.case_ref,
        title=row.title,
        summary=row.summary,
        classification=row.classification,
        severity=row.severity,
        status=row.status,
        lead_actor=row.lead_actor,
        scope_authorized=row.scope_authorized,
        scope_note=row.scope_note,
        tags=json.loads(row.tags_json or "[]"),
        evidence_count=row.evidence_count,
        custody_head_seq=row.custody_head_seq,
        custody_head_sha256=row.custody_head_sha256,
        created_at=_utc(row.created_at),
        updated_at=_utc(row.updated_at),
        sealed_at=_utc(row.sealed_at) if row.sealed_at else None,
        closed_at=_utc(row.closed_at) if row.closed_at else None,
        closure_reason=row.closure_reason,
    )


def _to_evidence(row: InvestigationEvidence) -> EvidenceRecord:
    return EvidenceRecord(
        id=row.id,
        investigation_id=row.investigation_id,
        evidence_ref=row.evidence_ref,
        artifact_kind=row.artifact_kind,
        title=row.title,
        epistemic_basis=row.epistemic_basis,
        storage_mode=row.storage_mode,
        canonical_version=row.canonical_version,
        hash_algorithm=row.hash_algorithm,
        content_sha256=row.content_sha256,
        snapshot=json.loads(row.snapshot_json),
        snapshot_json=row.snapshot_json,
        vault_relpath=row.vault_relpath,
        external_path_recorded=row.external_path_recorded,
        file_size_bytes=row.file_size_bytes,
        provenance=json.loads(row.provenance_json),
        source_table=row.source_table,
        source_record_id=row.source_record_id,
        observed_start=_utc(row.observed_start) if row.observed_start else None,
        observed_end=_utc(row.observed_end) if row.observed_end else None,
        integrity_status=row.integrity_status,
        last_verified_at=_utc(row.last_verified_at) if row.last_verified_at else None,
        acquired_by=row.acquired_by,
        acquired_at=_utc(row.acquired_at),
    )


def _to_note(row: InvestigationNote) -> NoteRecord:
    return NoteRecord(
        id=row.id,
        investigation_id=row.investigation_id,
        note_ref=row.note_ref,
        supersedes_note_id=row.supersedes_note_id,
        note_kind=row.note_kind,
        confidence=row.confidence,
        title=row.title,
        body=row.body,
        cited_evidence_ids=json.loads(row.cited_evidence_ids_json or "[]"),
        content_sha256=row.content_sha256,
        actor=row.actor,
        created_at=_utc(row.created_at),
    )


def _to_corr(row: InvestigationCorrelation) -> CorrelationRecord:
    return CorrelationRecord(
        id=row.id,
        investigation_id=row.investigation_id,
        run_seq=row.run_seq,
        rule_id=row.rule_id,
        indicator_kind=row.indicator_kind,
        indicator_value=row.indicator_value,
        epistemic_basis=row.epistemic_basis,
        confidence=row.confidence,
        summary=row.summary,
        rationale=row.rationale,
        limitations=json.loads(row.limitations_json or "[]"),
        evidence_ids=json.loads(row.evidence_ids_json or "[]"),
        window_start=_utc(row.window_start) if row.window_start else None,
        window_end=_utc(row.window_end) if row.window_end else None,
        created_at=_utc(row.created_at),
    )


def _to_custody(row: InvestigationCustodyEvent) -> CustodyRecord:
    return CustodyRecord(
        id=row.id,
        investigation_id=row.investigation_id,
        seq=row.seq,
        occurred_at=_utc(row.occurred_at),
        actor=row.actor,
        client_surface=row.client_surface,
        action=row.action,
        evidence_id=row.evidence_id,
        note_id=row.note_id,
        artifact_sha256=row.artifact_sha256,
        details=json.loads(row.details_json or "{}"),
        prev_event_sha256=row.prev_event_sha256,
        event_sha256=row.event_sha256,
    )


def _to_audit(row: AuditEvent) -> AuditRecord:
    return AuditRecord(
        id=row.id,
        seq=row.seq,
        occurred_at=_utc(row.occurred_at),
        actor=row.actor,
        client_surface=row.client_surface,
        category=row.category,
        action=row.action,
        outcome=row.outcome,
        investigation_id=row.investigation_id,
        resource_ref=row.resource_ref,
        details=json.loads(row.details_json or "{}"),
        prev_audit_sha256=row.prev_audit_sha256,
        audit_sha256=row.audit_sha256,
    )


def _to_export(row: ReportExport) -> ExportRecord:
    return ExportRecord(
        id=row.id,
        investigation_id=row.investigation_id,
        export_ref=row.export_ref,
        format=row.format,
        include_vault_files=row.include_vault_files,
        bundle_sha256=row.bundle_sha256,
        byte_size=row.byte_size,
        custody_head_seq=row.custody_head_seq,
        custody_head_sha256=row.custody_head_sha256,
        actor=row.actor,
        created_at=_utc(row.created_at),
    )


class ForensicsStore:
    """Short-transaction SQLite store preserving append-only custody and case isolation."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @staticmethod
    def _require_case_row(db: Session, case_id: int) -> Investigation:
        row = db.get(Investigation, case_id)
        if row is None:
            raise LookupError(f"Investigation {case_id} does not exist.")
        return row

    def get_meta_int(self, key: str, default: int) -> int:
        with Session(self._engine) as db:
            row = db.get(AppMeta, key)
            if row is None:
                return default
            try:
                return int(row.value)
            except ValueError:
                return default

    def _append_audit_in_tx(
        self,
        db: Session,
        *,
        occurred_at: datetime,
        actor: str,
        client_surface: str,
        category: str,
        action: str,
        outcome: str,
        investigation_id: int | None,
        resource_ref: str | None,
        details: dict[str, Any],
    ) -> AuditEvent:
        last = db.scalars(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).first()
        seq = (last.seq + 1) if last is not None else 1
        prev_hash = last.audit_sha256 if last is not None else GENESIS_HASH
        details_json = canonical_json_str(details)[:2048]
        payload = {
            "seq": seq,
            "occurred_at": occurred_at,
            "actor": actor,
            "client_surface": client_surface,
            "category": category,
            "action": action,
            "outcome": outcome,
            "investigation_id": investigation_id,
            "resource_ref": resource_ref,
            "details_json": details_json,
        }
        event_hash = compute_chain_hash(payload, prev_hash)
        row = AuditEvent(
            seq=seq,
            occurred_at=occurred_at,
            actor=actor,
            client_surface=client_surface,
            category=category,
            action=action,
            outcome=outcome,
            investigation_id=investigation_id,
            resource_ref=resource_ref,
            details_json=details_json,
            prev_audit_sha256=prev_hash,
            audit_sha256=event_hash,
        )
        db.add(row)
        db.flush()
        return row

    def _append_custody_in_tx(
        self,
        db: Session,
        *,
        case_row: Investigation,
        occurred_at: datetime,
        actor: str,
        client_surface: str,
        action: str,
        evidence_id: int | None = None,
        note_id: int | None = None,
        artifact_sha256: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> InvestigationCustodyEvent:
        seq = case_row.custody_head_seq + 1
        prev_hash = case_row.custody_head_sha256 or GENESIS_HASH
        details_json = canonical_json_str(details or {})[:4096]
        payload = {
            "investigation_id": case_row.id,
            "seq": seq,
            "occurred_at": occurred_at,
            "actor": actor,
            "client_surface": client_surface,
            "action": action,
            "evidence_id": evidence_id,
            "note_id": note_id,
            "artifact_sha256": artifact_sha256,
            "details_json": details_json,
        }
        event_hash = compute_chain_hash(payload, prev_hash)
        row = InvestigationCustodyEvent(
            investigation_id=case_row.id,
            seq=seq,
            occurred_at=occurred_at,
            actor=actor,
            client_surface=client_surface,
            action=action,
            evidence_id=evidence_id,
            note_id=note_id,
            artifact_sha256=artifact_sha256,
            details_json=details_json,
            prev_event_sha256=prev_hash,
            event_sha256=event_hash,
        )
        db.add(row)
        case_row.custody_head_seq = seq
        case_row.custody_head_sha256 = event_hash
        case_row.updated_at = occurred_at
        db.flush()
        return row

    def record_audit_event(
        self,
        *,
        actor: str,
        client_surface: str,
        category: str,
        action: str,
        outcome: str,
        investigation_id: int | None = None,
        resource_ref: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        now = _utc_now()
        with Session(self._engine) as db:
            row = self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                category=category,
                action=action,
                outcome=outcome,
                investigation_id=investigation_id,
                resource_ref=resource_ref,
                details=details or {},
            )
            db.commit()
            db.refresh(row)
            return _to_audit(row)

    def create_case(
        self,
        *,
        title: str,
        summary: str,
        classification: str,
        severity: str,
        lead_actor: str,
        scope_note: str,
        tags: list[str],
        client_surface: str,
    ) -> CaseRecord:
        now = _utc_now()
        with Session(self._engine) as db:
            count = db.scalar(select(func.count(Investigation.id))) or 0
            next_num = int(count) + 1
            while db.scalar(
                select(Investigation.id).where(
                    Investigation.case_ref == f"CASE-{now.year}-{next_num:04d}"
                )
            ):
                next_num += 1
            case_uid = str(uuid.uuid4())
            case_ref = f"CASE-{now.year}-{next_num:04d}"
            row = Investigation(
                case_uid=case_uid,
                case_ref=case_ref,
                title=title.strip()[:160],
                summary=summary.strip()[:2000],
                classification=classification,
                severity=severity,
                status="open",
                lead_actor=lead_actor,
                scope_authorized=True,
                scope_note=scope_note.strip()[:500],
                tags_json=json.dumps(tags[:16]),
                evidence_count=0,
                custody_head_seq=0,
                custody_head_sha256=GENESIS_HASH,
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            db.flush()
            self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=lead_actor,
                client_surface=client_surface,
                category="case",
                action="case_create",
                outcome="allowed",
                investigation_id=row.id,
                resource_ref=row.case_ref,
                details={"classification": classification, "severity": severity},
            )
            db.commit()
            db.refresh(row)
            return _to_case(row)

    def get_case(self, case_id: int) -> CaseRecord | None:
        with Session(self._engine) as db:
            row = db.get(Investigation, case_id)
            return _to_case(row) if row is not None else None

    def list_cases(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        q: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> PagedResult:
        with Session(self._engine) as db:
            stmt = select(Investigation)
            if status:
                stmt = stmt.where(Investigation.status == status)
            if severity:
                stmt = stmt.where(Investigation.severity == severity)
            if q and q.strip():
                pat = f"%{_escape_like(q.strip())}%"
                stmt = stmt.where(
                    Investigation.title.ilike(pat, escape="\\")
                    | Investigation.case_ref.ilike(pat, escape="\\")
                    | Investigation.lead_actor.ilike(pat, escape="\\")
                )
            total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = db.scalars(
                stmt.order_by(Investigation.updated_at.desc(), Investigation.id.desc())
                .offset(offset)
                .limit(limit)
            ).all()
            return PagedResult(items=[_to_case(r) for r in rows], total=int(total))

    def purge_empty_draft_case(
        self, case_id: int, *, actor: str, client_surface: str
    ) -> tuple[bool, str | None]:
        now = _utc_now()
        with Session(self._engine) as db:
            row = db.get(Investigation, case_id)
            if row is None:
                return (False, "case_not_found")
            has_evidence = (
                db.scalar(
                    select(func.count(InvestigationEvidence.id)).where(
                        InvestigationEvidence.investigation_id == case_id
                    )
                )
                or 0
            )
            has_custody = (
                db.scalar(
                    select(func.count(InvestigationCustodyEvent.id)).where(
                        InvestigationCustodyEvent.investigation_id == case_id
                    )
                )
                or 0
            )
            has_notes = (
                db.scalar(
                    select(func.count(InvestigationNote.id)).where(
                        InvestigationNote.investigation_id == case_id
                    )
                )
                or 0
            )
            has_exports = (
                db.scalar(
                    select(func.count(ReportExport.id)).where(
                        ReportExport.investigation_id == case_id
                    )
                )
                or 0
            )
            if (
                row.status != "open"
                or row.evidence_count > 0
                or row.custody_head_seq > 0
                or has_evidence > 0
                or has_custody > 0
                or has_notes > 0
                or has_exports > 0
            ):
                self._append_audit_in_tx(
                    db,
                    occurred_at=now,
                    actor=actor,
                    client_surface=client_surface,
                    category="case",
                    action="refused_case_purge",
                    outcome="refused",
                    investigation_id=case_id,
                    resource_ref=row.case_ref,
                    details={"reason": "case_archival_only"},
                )
                db.commit()
                return (False, "case_archival_only")
            ref = row.case_ref
            db.delete(row)
            self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                category="case",
                action="case_purge_draft",
                outcome="allowed",
                investigation_id=case_id,
                resource_ref=ref,
                details={},
            )
            db.commit()
            return (True, None)

    def next_evidence_ref(self, case_id: int) -> str:
        with Session(self._engine) as db:
            cnt = (
                db.scalar(
                    select(func.count(InvestigationEvidence.id)).where(
                        InvestigationEvidence.investigation_id == case_id
                    )
                )
                or 0
            )
            return f"EV-{int(cnt) + 1:04d}"

    def add_evidence(
        self,
        *,
        case_id: int,
        evidence_ref: str,
        artifact_kind: str,
        title: str,
        epistemic_basis: str,
        storage_mode: str,
        content_sha256: str,
        snapshot_json: str,
        vault_relpath: str | None,
        external_path_recorded: str | None,
        file_size_bytes: int | None,
        provenance: dict[str, Any],
        source_table: str | None,
        source_record_id: str | None,
        observed_start: datetime | None,
        observed_end: datetime | None,
        actor: str,
        client_surface: str,
    ) -> EvidenceRecord:
        now = _utc_now()
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            ev_row = InvestigationEvidence(
                investigation_id=case_id,
                evidence_ref=evidence_ref,
                artifact_kind=artifact_kind,
                title=title[:200],
                epistemic_basis=epistemic_basis,
                storage_mode=storage_mode,
                canonical_version=1,
                hash_algorithm="sha256",
                content_sha256=content_sha256,
                snapshot_json=snapshot_json,
                vault_relpath=vault_relpath,
                external_path_recorded=external_path_recorded,
                file_size_bytes=file_size_bytes,
                provenance_json=canonical_json_str(provenance),
                source_table=source_table,
                source_record_id=source_record_id,
                observed_start=observed_start,
                observed_end=observed_end,
                integrity_status="verified",
                last_verified_at=now,
                acquired_by=actor,
                acquired_at=now,
            )
            db.add(ev_row)
            db.flush()
            case_row.evidence_count += 1
            if case_row.status == "open":
                case_row.status = "active"
            self._append_custody_in_tx(
                db,
                case_row=case_row,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                action="vault_copied" if storage_mode == "vault_file" else "evidence_acquired",
                evidence_id=ev_row.id,
                artifact_sha256=content_sha256,
                details={
                    "evidence_ref": evidence_ref,
                    "artifact_kind": artifact_kind,
                    "storage_mode": storage_mode,
                },
            )
            self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                category="evidence",
                action="evidence_attach",
                outcome="allowed",
                investigation_id=case_id,
                resource_ref=evidence_ref,
                details={"artifact_kind": artifact_kind, "sha256": content_sha256},
            )
            db.commit()
            db.refresh(ev_row)
            return _to_evidence(ev_row)

    def list_evidence(self, case_id: int) -> list[EvidenceRecord]:
        with Session(self._engine) as db:
            rows = db.scalars(
                select(InvestigationEvidence)
                .where(InvestigationEvidence.investigation_id == case_id)
                .order_by(InvestigationEvidence.id.asc())
            ).all()
            return [_to_evidence(r) for r in rows]

    def get_evidence(self, case_id: int, evidence_id: int) -> EvidenceRecord | None:
        with Session(self._engine) as db:
            row = db.scalar(
                select(InvestigationEvidence).where(
                    InvestigationEvidence.investigation_id == case_id,
                    InvestigationEvidence.id == evidence_id,
                )
            )
            return _to_evidence(row) if row is not None else None

    def add_note(
        self,
        *,
        case_id: int,
        note_kind: str,
        confidence: str,
        title: str,
        body: str,
        cited_evidence_ids: list[int],
        supersedes_note_id: int | None,
        actor: str,
        client_surface: str,
    ) -> NoteRecord:
        now = _utc_now()
        content_sha = canonical_sha256(
            {
                "note_kind": note_kind,
                "title": title,
                "body": body,
                "cited_evidence_ids": cited_evidence_ids,
                "supersedes_note_id": supersedes_note_id,
            }
        )
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            cnt = (
                db.scalar(
                    select(func.count(InvestigationNote.id)).where(
                        InvestigationNote.investigation_id == case_id
                    )
                )
                or 0
            )
            note_ref = f"NOTE-{int(cnt) + 1:04d}"
            row = InvestigationNote(
                investigation_id=case_id,
                note_ref=note_ref,
                supersedes_note_id=supersedes_note_id,
                note_kind=note_kind,
                confidence=confidence,
                title=title.strip()[:160],
                body=body[:16384],
                cited_evidence_ids_json=json.dumps(cited_evidence_ids),
                content_sha256=content_sha,
                actor=actor,
                created_at=now,
            )
            db.add(row)
            db.flush()
            self._append_custody_in_tx(
                db,
                case_row=case_row,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                action="note_added",
                note_id=row.id,
                artifact_sha256=content_sha,
                details={"note_ref": note_ref, "supersedes_note_id": supersedes_note_id},
            )
            db.commit()
            db.refresh(row)
            return _to_note(row)

    def get_note(self, case_id: int, note_id: int) -> NoteRecord | None:
        with Session(self._engine) as db:
            row = db.scalar(
                select(InvestigationNote).where(
                    InvestigationNote.investigation_id == case_id,
                    InvestigationNote.id == note_id,
                )
            )
            return _to_note(row) if row is not None else None

    def list_notes(self, case_id: int) -> list[NoteRecord]:
        with Session(self._engine) as db:
            rows = db.scalars(
                select(InvestigationNote)
                .where(InvestigationNote.investigation_id == case_id)
                .order_by(InvestigationNote.id.asc())
            ).all()
            return [_to_note(r) for r in rows]

    def save_correlations(
        self,
        *,
        case_id: int,
        candidates: list[CorrelationCandidate],
        actor: str,
        client_surface: str,
    ) -> list[CorrelationRecord]:
        now = _utc_now()
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            prev_seq = (
                db.scalar(
                    select(func.max(InvestigationCorrelation.run_seq)).where(
                        InvestigationCorrelation.investigation_id == case_id
                    )
                )
                or 0
            )
            run_seq = int(prev_seq) + 1
            created: list[InvestigationCorrelation] = []
            for cand in candidates:
                row = InvestigationCorrelation(
                    investigation_id=case_id,
                    run_seq=run_seq,
                    rule_id=cand.rule_id,
                    indicator_kind=cand.indicator_kind,
                    indicator_value=cand.indicator_value,
                    epistemic_basis=cand.epistemic_basis,
                    confidence=cand.confidence,
                    summary=cand.summary[:500],
                    rationale=cand.rationale,
                    limitations_json=json.dumps(cand.limitations),
                    evidence_ids_json=json.dumps(cand.evidence_ids),
                    window_start=cand.window_start,
                    window_end=cand.window_end,
                    created_at=now,
                )
                db.add(row)
                created.append(row)
            db.flush()
            self._append_custody_in_tx(
                db,
                case_row=case_row,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                action="correlation_run",
                details={"run_seq": run_seq, "matches": len(created)},
            )
            db.commit()
            return [_to_corr(r) for r in created]

    def list_latest_correlations(self, case_id: int) -> list[CorrelationRecord]:
        with Session(self._engine) as db:
            max_seq = db.scalar(
                select(func.max(InvestigationCorrelation.run_seq)).where(
                    InvestigationCorrelation.investigation_id == case_id
                )
            )
            if max_seq is None:
                return []
            rows = db.scalars(
                select(InvestigationCorrelation)
                .where(
                    InvestigationCorrelation.investigation_id == case_id,
                    InvestigationCorrelation.run_seq == int(max_seq),
                )
                .order_by(InvestigationCorrelation.id.asc())
            ).all()
            return [_to_corr(r) for r in rows]

    def update_case_status(
        self,
        *,
        case_id: int,
        target_status: str,
        reason: str,
        actor: str,
        client_surface: str,
    ) -> CaseRecord:
        now = _utc_now()
        action_map = {
            "sealed": "case_sealed",
            "closed": "case_closed",
            "active": "case_reopened",
        }
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            prev_status = case_row.status
            case_row.status = target_status
            if target_status == "sealed":
                case_row.sealed_at = now
                case_row.closure_reason = reason.strip()[:500]
            elif target_status == "closed":
                case_row.closed_at = now
                case_row.closure_reason = reason.strip()[:500]
            else:
                case_row.sealed_at = None
                case_row.closed_at = None
                case_row.closure_reason = reason.strip()[:500]
            self._append_custody_in_tx(
                db,
                case_row=case_row,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                action=action_map[target_status],
                details={"from_status": prev_status, "to_status": target_status, "reason": reason},
            )
            self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                category="case",
                action=action_map[target_status],
                outcome="allowed",
                investigation_id=case_id,
                resource_ref=case_row.case_ref,
                details={"from_status": prev_status, "to_status": target_status},
            )
            db.commit()
            db.refresh(case_row)
            return _to_case(case_row)

    def list_custody_events(self, case_id: int) -> list[CustodyRecord]:
        with Session(self._engine) as db:
            rows = db.scalars(
                select(InvestigationCustodyEvent)
                .where(InvestigationCustodyEvent.investigation_id == case_id)
                .order_by(InvestigationCustodyEvent.seq.asc())
            ).all()
            return [_to_custody(r) for r in rows]

    def verify_custody_chain(self, case_id: int) -> ChainVerificationResult:
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            rows = db.scalars(
                select(InvestigationCustodyEvent)
                .where(InvestigationCustodyEvent.investigation_id == case_id)
                .order_by(InvestigationCustodyEvent.seq.asc())
            ).all()
            links = [
                ChainLinkInput(
                    seq=r.seq,
                    payload={
                        "investigation_id": r.investigation_id,
                        "seq": r.seq,
                        "occurred_at": _utc(r.occurred_at),
                        "actor": r.actor,
                        "client_surface": r.client_surface,
                        "action": r.action,
                        "evidence_id": r.evidence_id,
                        "note_id": r.note_id,
                        "artifact_sha256": r.artifact_sha256,
                        "details_json": r.details_json,
                    },
                    prev_sha256=r.prev_event_sha256,
                    event_sha256=r.event_sha256,
                )
                for r in rows
            ]
            return verify_hash_chain(links, expected_head_sha256=case_row.custody_head_sha256)

    def record_verification_results(
        self,
        *,
        case_id: int,
        statuses: list[tuple[int, str]],
        chain_valid: bool,
        all_verified: bool,
        actor: str,
        client_surface: str,
    ) -> None:
        now = _utc_now()
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            for ev_id, st in statuses:
                db.execute(
                    update(InvestigationEvidence)
                    .where(
                        InvestigationEvidence.id == ev_id,
                        InvestigationEvidence.investigation_id == case_id,
                    )
                    .values(integrity_status=st, last_verified_at=now)
                )
            self._append_custody_in_tx(
                db,
                case_row=case_row,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                action="integrity_verified" if all_verified else "integrity_failed",
                details={"chain_valid": chain_valid, "checked_items": len(statuses)},
            )
            self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                category="integrity",
                action="case_verify",
                outcome="allowed" if all_verified else "mismatch",
                investigation_id=case_id,
                resource_ref=case_row.case_ref,
                details={"chain_valid": chain_valid, "checked_items": len(statuses)},
            )
            db.commit()

    def record_export(
        self,
        *,
        case_id: int,
        export_format: str,
        include_vault_files: bool,
        bundle_sha256: str,
        byte_size: int,
        actor: str,
        client_surface: str,
    ) -> ExportRecord:
        now = _utc_now()
        with Session(self._engine) as db:
            case_row = self._require_case_row(db, case_id)
            cnt = (
                db.scalar(
                    select(func.count(ReportExport.id)).where(
                        ReportExport.investigation_id == case_id
                    )
                )
                or 0
            )
            export_ref = f"RPT-{int(cnt) + 1:04d}"
            cust = self._append_custody_in_tx(
                db,
                case_row=case_row,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                action="report_exported",
                artifact_sha256=bundle_sha256,
                details={
                    "export_ref": export_ref,
                    "format": export_format,
                    "include_vault_files": include_vault_files,
                },
            )
            row = ReportExport(
                investigation_id=case_id,
                export_ref=export_ref,
                format=export_format,
                include_vault_files=include_vault_files,
                bundle_sha256=bundle_sha256,
                byte_size=byte_size,
                custody_head_seq=cust.seq,
                custody_head_sha256=cust.event_sha256,
                actor=actor,
                created_at=now,
            )
            db.add(row)
            self._append_audit_in_tx(
                db,
                occurred_at=now,
                actor=actor,
                client_surface=client_surface,
                category="export",
                action="report_export",
                outcome="allowed",
                investigation_id=case_id,
                resource_ref=export_ref,
                details={"format": export_format, "bundle_sha256": bundle_sha256},
            )
            db.commit()
            db.refresh(row)
            return _to_export(row)

    def list_exports(
        self, *, case_id: int | None = None, limit: int = 50, offset: int = 0
    ) -> PagedResult:
        with Session(self._engine) as db:
            stmt = select(ReportExport)
            if case_id is not None:
                stmt = stmt.where(ReportExport.investigation_id == case_id)
            total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = db.scalars(
                stmt.order_by(ReportExport.created_at.desc(), ReportExport.id.desc())
                .offset(offset)
                .limit(limit)
            ).all()
            return PagedResult(items=[_to_export(r) for r in rows], total=int(total))

    def list_audit_events(
        self,
        *,
        category: str | None = None,
        outcome: str | None = None,
        actor: str | None = None,
        q: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PagedResult:
        with Session(self._engine) as db:
            stmt = select(AuditEvent)
            if category:
                stmt = stmt.where(AuditEvent.category == category)
            if outcome:
                stmt = stmt.where(AuditEvent.outcome == outcome)
            if actor:
                stmt = stmt.where(AuditEvent.actor == actor)
            if q and q.strip():
                pat = f"%{_escape_like(q.strip())}%"
                stmt = stmt.where(
                    AuditEvent.action.ilike(pat, escape="\\")
                    | AuditEvent.resource_ref.ilike(pat, escape="\\")
                    | AuditEvent.actor.ilike(pat, escape="\\")
                )
            total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = db.scalars(
                stmt.order_by(AuditEvent.seq.desc()).offset(offset).limit(limit)
            ).all()
            return PagedResult(items=[_to_audit(r) for r in rows], total=int(total))

    def build_timeline_inputs(
        self, case_id: int
    ) -> tuple[list[TimelineEvidenceInput], list[NoteInput]]:
        evidence = self.list_evidence(case_id)
        notes = self.list_notes(case_id)
        ev_in = [
            TimelineEvidenceInput(
                id=e.id,
                evidence_ref=e.evidence_ref,
                artifact_kind=e.artifact_kind,
                title=e.title,
                epistemic_basis=e.epistemic_basis,
                acquired_at=e.acquired_at,
                observed_start=e.observed_start,
                observed_end=e.observed_end,
                snapshot=e.snapshot,
            )
            for e in evidence
        ]
        note_in = [
            NoteInput(
                id=n.id,
                note_ref=n.note_ref,
                note_kind=n.note_kind,
                title=n.title,
                body=n.body,
                created_at=n.created_at,
                actor=n.actor,
                cited_evidence_ids=n.cited_evidence_ids,
            )
            for n in notes
        ]
        return ev_in, note_in
