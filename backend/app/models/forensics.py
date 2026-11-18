"""Forensic investigations, evidence, custody, and audit models (Phase 6, revision 0008)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_status_updated", "status", text("updated_at DESC")),
        Index("ix_investigations_created", text("created_at DESC")),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    case_uid: Mapped[str] = mapped_column(String(36), unique=True)
    case_ref: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(160))
    summary: Mapped[str] = mapped_column(String(2000))
    classification: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), default="open")
    lead_actor: Mapped[str] = mapped_column(String(64), default="local-operator")
    scope_authorized: Mapped[bool] = mapped_column(Boolean, default=True)
    scope_note: Mapped[str] = mapped_column(String(500))
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_count: Mapped[int] = mapped_column(default=0)
    custody_head_seq: Mapped[int] = mapped_column(default=0)
    custody_head_sha256: Mapped[str] = mapped_column(String(64), default="0" * 64)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime)
    sealed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    closed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    closure_reason: Mapped[str | None] = mapped_column(String(500), default=None)


class InvestigationEvidence(Base):
    __tablename__ = "investigation_evidence"
    __table_args__ = (
        UniqueConstraint("investigation_id", "evidence_ref", name="uq_evidence_case_ref"),
        Index("ix_evidence_case_acquired", "investigation_id", text("acquired_at DESC")),
        Index("ix_evidence_case_kind", "investigation_id", "artifact_kind"),
        Index("ix_evidence_sha256", "investigation_id", "content_sha256"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    evidence_ref: Mapped[str] = mapped_column(String(24))
    artifact_kind: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(200))
    epistemic_basis: Mapped[str] = mapped_column(String(24))
    storage_mode: Mapped[str] = mapped_column(String(20))
    canonical_version: Mapped[int] = mapped_column(SmallInteger, default=1)
    hash_algorithm: Mapped[str] = mapped_column(String(12), default="sha256")
    content_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_json: Mapped[str] = mapped_column(Text)
    vault_relpath: Mapped[str | None] = mapped_column(String(260), default=None)
    external_path_recorded: Mapped[str | None] = mapped_column(String(512), default=None)
    file_size_bytes: Mapped[int | None] = mapped_column(BigInteger, default=None)
    provenance_json: Mapped[str] = mapped_column(Text)
    source_table: Mapped[str | None] = mapped_column(String(32), default=None)
    source_record_id: Mapped[str | None] = mapped_column(String(64), default=None)
    observed_start: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    observed_end: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    integrity_status: Mapped[str] = mapped_column(String(24), default="verified")
    last_verified_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    acquired_by: Mapped[str] = mapped_column(String(64))
    acquired_at: Mapped[datetime] = mapped_column(UtcDateTime)


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    __table_args__ = (
        UniqueConstraint("investigation_id", "note_ref", name="uq_notes_case_ref"),
        Index("ix_notes_case_created", "investigation_id", "created_at"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    note_ref: Mapped[str] = mapped_column(String(24))
    supersedes_note_id: Mapped[int | None] = mapped_column(
        ForeignKey("investigation_notes.id", ondelete="RESTRICT"), default=None
    )
    note_kind: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(160))
    body: Mapped[str] = mapped_column(Text)
    cited_evidence_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    content_sha256: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class InvestigationCorrelation(Base):
    __tablename__ = "investigation_correlations"
    __table_args__ = (Index("ix_corr_case_run", "investigation_id", text("run_seq DESC"), "id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    run_seq: Mapped[int]
    rule_id: Mapped[str] = mapped_column(String(24))
    indicator_kind: Mapped[str] = mapped_column(String(24))
    indicator_value: Mapped[str] = mapped_column(String(255))
    epistemic_basis: Mapped[str] = mapped_column(String(16), default="inferred")
    confidence: Mapped[str] = mapped_column(String(8))
    summary: Mapped[str] = mapped_column(String(500))
    rationale: Mapped[str] = mapped_column(Text)
    limitations_json: Mapped[str] = mapped_column(Text)
    evidence_ids_json: Mapped[str] = mapped_column(Text)
    window_start: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    window_end: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class InvestigationCustodyEvent(Base):
    __tablename__ = "investigation_custody_events"
    __table_args__ = (
        UniqueConstraint("investigation_id", "seq", name="uq_custody_case_seq"),
        Index("ix_custody_case_time", "investigation_id", "occurred_at"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    seq: Mapped[int]
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime)
    actor: Mapped[str] = mapped_column(String(64))
    client_surface: Mapped[str] = mapped_column(String(24))
    action: Mapped[str] = mapped_column(String(40))
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("investigation_evidence.id", ondelete="RESTRICT"), default=None
    )
    note_id: Mapped[int | None] = mapped_column(
        ForeignKey("investigation_notes.id", ondelete="RESTRICT"), default=None
    )
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    prev_event_sha256: Mapped[str] = mapped_column(String(64))
    event_sha256: Mapped[str] = mapped_column(String(64))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_time_cat", text("occurred_at DESC"), "category"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(unique=True)
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime)
    actor: Mapped[str] = mapped_column(String(64))
    client_surface: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(24))
    action: Mapped[str] = mapped_column(String(48))
    outcome: Mapped[str] = mapped_column(String(16))
    investigation_id: Mapped[int | None] = mapped_column(default=None)
    resource_ref: Mapped[str | None] = mapped_column(String(64), default=None)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    prev_audit_sha256: Mapped[str] = mapped_column(String(64))
    audit_sha256: Mapped[str] = mapped_column(String(64))


class ReportExport(Base):
    __tablename__ = "report_exports"
    __table_args__ = (
        UniqueConstraint("investigation_id", "export_ref", name="uq_exports_case_ref"),
        Index("ix_exports_case_created", "investigation_id", text("created_at DESC")),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    export_ref: Mapped[str] = mapped_column(String(24))
    format: Mapped[str] = mapped_column(String(16))
    include_vault_files: Mapped[bool] = mapped_column(Boolean, default=False)
    bundle_sha256: Mapped[str] = mapped_column(String(64))
    byte_size: Mapped[int] = mapped_column(BigInteger)
    custody_head_seq: Mapped[int]
    custody_head_sha256: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
