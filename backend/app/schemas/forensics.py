"""Pydantic v2 request and response schemas for Investigations & Forensics (Phase 6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

CaseClassification = Literal[
    "triage", "incident", "audit", "anomaly_review", "web_assessment", "other"
]
CaseSeverity = Literal["info", "low", "medium", "high", "critical"]
CaseStatus = Literal["open", "active", "sealed", "closed"]
CaseTransitionStatus = Literal["active", "sealed", "closed"]
ArtifactKind = Literal["alert", "flow_session", "flow", "device", "web_inspection", "pcapng_file"]
DbArtifactKind = Literal["alert", "flow_session", "flow", "device", "web_inspection"]
NoteKind = Literal["observation", "hypothesis", "correlation_review", "conclusion", "limitation"]
ConfidenceLevel = Literal["low", "medium", "high"]
ExportFormat = Literal["markdown", "json_dossier", "zip_bundle"]
TimeSource = Literal["packet_capture", "local_wall_clock", "remote_tls_cert"]


class CreateCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(default="", max_length=2000)
    classification: CaseClassification = "incident"
    severity: CaseSeverity = "medium"
    actor: str | None = Field(default=None, max_length=64)
    scope_note: str = Field(default="Authorized local investigation", max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=16)
    confirm_authorized: StrictBool = False


class PurgeDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str | None = Field(default=None, max_length=64)
    confirm_action: StrictBool = False


class CaseStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_status: CaseTransitionStatus
    reason: str = Field(min_length=1, max_length=500)
    actor: str | None = Field(default=None, max_length=64)
    confirm_action: StrictBool = False


class AttachEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: ArtifactKind
    source_id: int | None = Field(default=None, ge=1)
    source_path: str | None = Field(default=None, max_length=260)
    vault_copy: StrictBool = True
    title: str | None = Field(default=None, max_length=200)
    actor: str | None = Field(default=None, max_length=64)
    confirm_action: StrictBool = False


class AddNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note_kind: NoteKind = "observation"
    confidence: ConfidenceLevel = "medium"
    title: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=16384)
    cited_evidence_ids: list[int] = Field(default_factory=list, max_length=100)
    supersedes_note_id: int | None = Field(default=None, ge=1)
    actor: str | None = Field(default=None, max_length=64)


class ActorActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str | None = Field(default=None, max_length=64)


class ExportCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: ExportFormat = "markdown"
    include_vault_files: StrictBool = False
    actor: str | None = Field(default=None, max_length=64)


class VerifyLocalBundleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=260)
    confirm_action: StrictBool = False


class CaseSummary(BaseModel):
    id: int
    case_uid: str
    case_ref: str
    title: str
    summary: str
    classification: str
    severity: str
    status: CaseStatus
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


class CaseList(BaseModel):
    items: list[CaseSummary]
    total: int
    limit: int
    offset: int


class EvidenceSummary(BaseModel):
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
    vault_relpath: str | None
    external_path_recorded: str | None
    file_size_bytes: int | None
    source_table: str | None
    source_record_id: str | None
    observed_start: datetime | None
    observed_end: datetime | None
    integrity_status: str
    last_verified_at: datetime | None
    acquired_by: str
    acquired_at: datetime


class EvidenceDetail(EvidenceSummary):
    snapshot: dict[str, Any]
    provenance: dict[str, Any]


class EvidenceList(BaseModel):
    items: list[EvidenceSummary]


class NoteSummary(BaseModel):
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


class NoteList(BaseModel):
    items: list[NoteSummary]


class CorrelationSummary(BaseModel):
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


class CorrelationList(BaseModel):
    items: list[CorrelationSummary]


class TimelineEventItem(BaseModel):
    timestamp_utc: datetime
    time_source: TimeSource
    epistemic_basis: str
    event_kind: str
    ref: str
    evidence_id: int | None
    note_id: int | None
    title: str
    summary: str
    indicators: list[str]


class TimelineList(BaseModel):
    items: list[TimelineEventItem]


class CustodyEventItem(BaseModel):
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


class CustodyList(BaseModel):
    items: list[CustodyEventItem]


class EvidenceIntegrityItem(BaseModel):
    evidence_id: int
    evidence_ref: str
    storage_mode: str
    expected_sha256: str
    computed_sha256: str | None
    integrity_status: str


class CaseIntegrityVerdict(BaseModel):
    investigation_id: int
    case_ref: str
    chain_valid: bool
    chain_checked_links: int
    chain_first_invalid_seq: int | None
    chain_error: str | None
    evidence_results: list[EvidenceIntegrityItem]
    all_verified: bool


class ExportSummary(BaseModel):
    id: int
    investigation_id: int
    export_ref: str
    format: ExportFormat
    include_vault_files: bool
    bundle_sha256: str
    byte_size: int
    custody_head_seq: int
    custody_head_sha256: str
    actor: str
    created_at: datetime


class ExportList(BaseModel):
    items: list[ExportSummary]
    total: int


class BundleVerificationResponse(BaseModel):
    valid: bool
    error: str | None
    case_ref: str | None
    dossier_sha256_valid: bool
    custody_chain_valid: bool
    verified_files: list[str]
    failed_files: list[str]
    checked_entries: int


class DeleteCaseResult(BaseModel):
    deleted_id: int


class ReportsOverviewResponse(BaseModel):
    total_cases: int
    open_or_active_cases: int
    sealed_cases: int
    closed_cases: int
    vault_used_bytes: int
    vault_max_total_bytes: int
    vault_max_file_bytes: int
    recent_exports: list[ExportSummary]


class VerifyAllResponse(BaseModel):
    items: list[CaseIntegrityVerdict]


class AuditEventItem(BaseModel):
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


class AuditEventList(BaseModel):
    items: list[AuditEventItem]
    total: int
    limit: int
    offset: int
