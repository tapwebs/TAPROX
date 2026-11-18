"""Investigations & Forensics REST endpoints (/api/v1/investigations/*)."""

from __future__ import annotations

from pathlib import Path as FsPath
from typing import Annotated, Any, cast

from fastapi import APIRouter, Body, Path, Query, Request, Response

from app.core.errors import ApiProblem
from app.schemas import forensics as api
from app.schemas.errors import ErrorResponse
from app.services.forensics.export import (
    MAX_UPLOAD_BUNDLE_BYTES,
    BundleVerificationResult,
    export_case_bundle,
    resolve_export_artifact,
    verify_bundle_bytes,
    verify_local_bundle,
)
from app.services.forensics.service import CaseIntegrityReport, ForensicsError, ForensicsService
from app.services.forensics.store import (
    CaseRecord,
    CorrelationRecord,
    EvidenceRecord,
    ExportRecord,
    NoteRecord,
)

router = APIRouter(prefix="/investigations", tags=["investigations"])

CaseId = Annotated[int, Path(ge=1, le=2**62)]
EvidenceId = Annotated[int, Path(ge=1, le=2**62)]
ExportId = Annotated[int, Path(ge=1, le=2**62)]

_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "Investigation or item not found"}
}
_DEFAULT_ACTOR_BODY = Body(default_factory=api.ActorActionRequest)


def _svc(request: Request) -> ForensicsService:
    svc: ForensicsService = request.app.state.forensics
    return svc


def _refuse(exc: ForensicsError) -> ApiProblem:
    return ApiProblem(exc.status, exc.code, str(exc))


def _to_case(c: CaseRecord) -> api.CaseSummary:
    return api.CaseSummary(
        id=c.id,
        case_uid=c.case_uid,
        case_ref=c.case_ref,
        title=c.title,
        summary=c.summary,
        classification=c.classification,
        severity=c.severity,
        status=cast(api.CaseStatus, c.status),
        lead_actor=c.lead_actor,
        scope_authorized=c.scope_authorized,
        scope_note=c.scope_note,
        tags=c.tags,
        evidence_count=c.evidence_count,
        custody_head_seq=c.custody_head_seq,
        custody_head_sha256=c.custody_head_sha256,
        created_at=c.created_at,
        updated_at=c.updated_at,
        sealed_at=c.sealed_at,
        closed_at=c.closed_at,
        closure_reason=c.closure_reason,
    )


def _to_evidence_summary(e: EvidenceRecord) -> api.EvidenceSummary:
    return api.EvidenceSummary(
        id=e.id,
        investigation_id=e.investigation_id,
        evidence_ref=e.evidence_ref,
        artifact_kind=e.artifact_kind,
        title=e.title,
        epistemic_basis=e.epistemic_basis,
        storage_mode=e.storage_mode,
        canonical_version=e.canonical_version,
        hash_algorithm=e.hash_algorithm,
        content_sha256=e.content_sha256,
        vault_relpath=e.vault_relpath,
        external_path_recorded=e.external_path_recorded,
        file_size_bytes=e.file_size_bytes,
        source_table=e.source_table,
        source_record_id=e.source_record_id,
        observed_start=e.observed_start,
        observed_end=e.observed_end,
        integrity_status=e.integrity_status,
        last_verified_at=e.last_verified_at,
        acquired_by=e.acquired_by,
        acquired_at=e.acquired_at,
    )


def _to_evidence_detail(e: EvidenceRecord) -> api.EvidenceDetail:
    return api.EvidenceDetail(
        **_to_evidence_summary(e).model_dump(),
        snapshot=e.snapshot,
        provenance=e.provenance,
    )


def _to_note(n: NoteRecord) -> api.NoteSummary:
    return api.NoteSummary(
        id=n.id,
        investigation_id=n.investigation_id,
        note_ref=n.note_ref,
        supersedes_note_id=n.supersedes_note_id,
        note_kind=n.note_kind,
        confidence=n.confidence,
        title=n.title,
        body=n.body,
        cited_evidence_ids=n.cited_evidence_ids,
        content_sha256=n.content_sha256,
        actor=n.actor,
        created_at=n.created_at,
    )


def _to_corr(c: CorrelationRecord) -> api.CorrelationSummary:
    return api.CorrelationSummary(
        id=c.id,
        investigation_id=c.investigation_id,
        run_seq=c.run_seq,
        rule_id=c.rule_id,
        indicator_kind=c.indicator_kind,
        indicator_value=c.indicator_value,
        epistemic_basis=c.epistemic_basis,
        confidence=c.confidence,
        summary=c.summary,
        rationale=c.rationale,
        limitations=c.limitations,
        evidence_ids=c.evidence_ids,
        window_start=c.window_start,
        window_end=c.window_end,
        created_at=c.created_at,
    )


def _to_export(x: ExportRecord) -> api.ExportSummary:
    return api.ExportSummary(
        id=x.id,
        investigation_id=x.investigation_id,
        export_ref=x.export_ref,
        format=cast(api.ExportFormat, x.format),
        include_vault_files=x.include_vault_files,
        bundle_sha256=x.bundle_sha256,
        byte_size=x.byte_size,
        custody_head_seq=x.custody_head_seq,
        custody_head_sha256=x.custody_head_sha256,
        actor=x.actor,
        created_at=x.created_at,
    )


def to_verdict_schema(r: CaseIntegrityReport) -> api.CaseIntegrityVerdict:
    return api.CaseIntegrityVerdict(
        investigation_id=r.investigation_id,
        case_ref=r.case_ref,
        chain_valid=r.chain_valid,
        chain_checked_links=r.chain_checked_links,
        chain_first_invalid_seq=r.chain_first_invalid_seq,
        chain_error=r.chain_error,
        evidence_results=[
            api.EvidenceIntegrityItem(
                evidence_id=it.evidence_id,
                evidence_ref=it.evidence_ref,
                storage_mode=it.storage_mode,
                expected_sha256=it.expected_sha256,
                computed_sha256=it.computed_sha256,
                integrity_status=it.integrity_status,
            )
            for it in r.evidence_results
        ],
        all_verified=r.all_verified,
    )


def _to_bundle_res(res: BundleVerificationResult) -> api.BundleVerificationResponse:
    return api.BundleVerificationResponse(
        valid=res.valid,
        error=res.error,
        case_ref=res.case_ref,
        dossier_sha256_valid=res.dossier_sha256_valid,
        custody_chain_valid=res.custody_chain_valid,
        verified_files=res.verified_files,
        failed_files=res.failed_files,
        checked_entries=res.checked_entries,
    )


@router.get("", summary="List investigation cases", response_model=api.CaseList)
def list_cases(
    request: Request,
    status: api.CaseStatus | None = None,
    severity: api.CaseSeverity | None = None,
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> api.CaseList:
    page = _svc(request).list_cases(
        status=status, severity=severity, q=q, limit=limit, offset=offset
    )
    return api.CaseList(
        items=[_to_case(c) for c in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "",
    summary="Open a new forensic investigation case",
    status_code=201,
    response_model=api.CaseSummary,
)
def create_case(request: Request, body: api.CreateCaseRequest) -> api.CaseSummary:
    try:
        case = _svc(request).create_case(
            title=body.title,
            summary=body.summary,
            classification=body.classification,
            severity=body.severity,
            scope_note=body.scope_note,
            tags=body.tags,
            actor=body.actor,
            confirm_authorized=body.confirm_authorized,
        )
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return _to_case(case)


@router.post(
    "/verify-bundle",
    summary="Verify a forensic ZIP evidence bundle (max 64 MiB upload)",
    response_model=api.BundleVerificationResponse,
)
async def verify_uploaded_bundle(request: Request) -> api.BundleVerificationResponse:
    cl_raw = request.headers.get("content-length")
    if cl_raw is not None:
        try:
            if int(cl_raw) > MAX_UPLOAD_BUNDLE_BYTES:
                raise ApiProblem(
                    413,
                    "bundle_upload_limit_exceeded",
                    f"Uploaded bundle exceeds {MAX_UPLOAD_BUNDLE_BYTES} byte limit.",
                )
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_UPLOAD_BUNDLE_BYTES:
            raise ApiProblem(
                413,
                "bundle_upload_limit_exceeded",
                f"Uploaded bundle exceeds {MAX_UPLOAD_BUNDLE_BYTES} byte limit.",
            )
        chunks.append(chunk)
    res = verify_bundle_bytes(b"".join(chunks))
    return _to_bundle_res(res)


@router.post(
    "/verify-local-bundle",
    summary="Verify a local forensic ZIP evidence bundle on disk (max 1 GiB)",
    response_model=api.BundleVerificationResponse,
)
def verify_local_archive(
    request: Request, body: api.VerifyLocalBundleRequest
) -> api.BundleVerificationResponse:
    if body.confirm_action is not True:
        raise ApiProblem(400, "confirmation_required", "Explicit confirmation is required.")
    raw = body.path.strip()
    if (
        raw.startswith(("\\\\", "//"))
        or ".." in FsPath(raw).parts
        or not raw.lower().endswith(".zip")
    ):
        raise ApiProblem(422, "invalid_bundle_path", "Enter an absolute local .zip bundle path.")
    candidate = FsPath(raw)
    if not candidate.is_absolute():
        raise ApiProblem(422, "invalid_bundle_path", "Path must be absolute.")
    res = verify_local_bundle(candidate.resolve())
    return _to_bundle_res(res)


@router.get(
    "/{case_id}",
    summary="Get one investigation case",
    response_model=api.CaseSummary,
    responses=_NOT_FOUND,
)
def get_case(request: Request, case_id: CaseId) -> api.CaseSummary:
    try:
        return _to_case(_svc(request).get_case(case_id))
    except ForensicsError as exc:
        raise _refuse(exc) from exc


@router.patch(
    "/{case_id}/status",
    summary="Seal, close, or reopen an investigation with a recorded custody reason",
    response_model=api.CaseSummary,
    responses=_NOT_FOUND,
)
def update_case_status(
    request: Request, case_id: CaseId, body: api.CaseStatusRequest
) -> api.CaseSummary:
    try:
        case = _svc(request).change_case_status(
            case_id,
            target_status=body.target_status,
            reason=body.reason,
            actor=body.actor,
            confirm_action=body.confirm_action,
        )
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return _to_case(case)


@router.delete(
    "/{case_id}",
    summary="Purge an empty draft case with zero evidence and zero custody records",
    response_model=api.DeleteCaseResult,
    responses=_NOT_FOUND,
)
def purge_draft_case(
    request: Request,
    case_id: CaseId,
    confirm_action: bool = Query(default=False),
    actor: str | None = Query(default=None, max_length=64),
) -> api.DeleteCaseResult:
    try:
        _svc(request).purge_draft_case(case_id, actor=actor, confirm_action=confirm_action)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.DeleteCaseResult(deleted_id=case_id)


@router.get(
    "/{case_id}/evidence",
    summary="List evidence items in an investigation",
    response_model=api.EvidenceList,
    responses=_NOT_FOUND,
)
def list_evidence(request: Request, case_id: CaseId) -> api.EvidenceList:
    try:
        items = _svc(request).list_evidence(case_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.EvidenceList(items=[_to_evidence_summary(e) for e in items])


@router.post(
    "/{case_id}/evidence",
    summary="Attach an immutable snapshot or vaulted PCAPNG artifact to a case",
    status_code=201,
    response_model=api.EvidenceDetail,
    responses=_NOT_FOUND,
)
def attach_evidence(
    request: Request, case_id: CaseId, body: api.AttachEvidenceRequest
) -> api.EvidenceDetail:
    svc = _svc(request)
    try:
        if body.kind == "pcapng_file":
            if not body.source_path:
                raise ApiProblem(
                    422, "missing_source_path", "source_path is required for pcapng_file."
                )
            ev = svc.attach_pcapng_evidence(
                case_id,
                source_path=body.source_path,
                vault_copy=body.vault_copy,
                title=body.title,
                actor=body.actor,
                confirm_action=body.confirm_action,
            )
        else:
            if body.source_id is None:
                raise ApiProblem(
                    422, "missing_source_id", "source_id is required for database evidence."
                )
            ev = svc.attach_db_evidence(
                case_id, kind=body.kind, source_id=body.source_id, actor=body.actor
            )
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return _to_evidence_detail(ev)


@router.get(
    "/{case_id}/evidence/{evidence_id}",
    summary="Get one case-isolated evidence snapshot and provenance",
    response_model=api.EvidenceDetail,
    responses=_NOT_FOUND,
)
def get_evidence_detail(
    request: Request, case_id: CaseId, evidence_id: EvidenceId
) -> api.EvidenceDetail:
    try:
        ev = _svc(request).get_evidence(case_id, evidence_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return _to_evidence_detail(ev)


@router.get(
    "/{case_id}/custody",
    summary="List append-only hash-chained custody records for a case",
    response_model=api.CustodyList,
    responses=_NOT_FOUND,
)
def list_custody(request: Request, case_id: CaseId) -> api.CustodyList:
    try:
        events = _svc(request).list_custody_events(case_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.CustodyList(
        items=[
            api.CustodyEventItem(
                id=c.id,
                investigation_id=c.investigation_id,
                seq=c.seq,
                occurred_at=c.occurred_at,
                actor=c.actor,
                client_surface=c.client_surface,
                action=c.action,
                evidence_id=c.evidence_id,
                note_id=c.note_id,
                artifact_sha256=c.artifact_sha256,
                details=c.details,
                prev_event_sha256=c.prev_event_sha256,
                event_sha256=c.event_sha256,
            )
            for c in events
        ]
    )


@router.post(
    "/{case_id}/verify",
    summary="Verify SHA-256 digests of all case evidence and its custody hash chain",
    response_model=api.CaseIntegrityVerdict,
    responses=_NOT_FOUND,
)
def verify_case(
    request: Request,
    case_id: CaseId,
    body: api.ActorActionRequest = _DEFAULT_ACTOR_BODY,
) -> api.CaseIntegrityVerdict:
    try:
        res = _svc(request).verify_case_integrity(case_id, actor=body.actor)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return to_verdict_schema(res)


@router.get(
    "/{case_id}/timeline",
    summary="Reconstruct chronological timeline across case evidence and notes",
    response_model=api.TimelineList,
    responses=_NOT_FOUND,
)
def get_timeline(request: Request, case_id: CaseId) -> api.TimelineList:
    try:
        events = _svc(request).get_timeline(case_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.TimelineList(
        items=[
            api.TimelineEventItem(
                timestamp_utc=ev.timestamp_utc,
                time_source=cast(api.TimeSource, ev.time_source),
                epistemic_basis=ev.epistemic_basis,
                event_kind=ev.event_kind,
                ref=ev.ref,
                evidence_id=ev.evidence_id,
                note_id=ev.note_id,
                title=ev.title,
                summary=ev.summary,
                indicators=ev.indicators,
            )
            for ev in events
        ]
    )


@router.post(
    "/{case_id}/correlate",
    summary="Run deterministic cross-evidence indicator correlation within a case",
    response_model=api.CorrelationList,
    responses=_NOT_FOUND,
)
def run_correlations(
    request: Request,
    case_id: CaseId,
    body: api.ActorActionRequest = _DEFAULT_ACTOR_BODY,
) -> api.CorrelationList:
    try:
        rows = _svc(request).run_correlations(case_id, actor=body.actor)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.CorrelationList(items=[_to_corr(r) for r in rows])


@router.get(
    "/{case_id}/correlations",
    summary="List latest deterministic correlations for a case",
    response_model=api.CorrelationList,
    responses=_NOT_FOUND,
)
def list_correlations(request: Request, case_id: CaseId) -> api.CorrelationList:
    try:
        rows = _svc(request).list_correlations(case_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.CorrelationList(items=[_to_corr(r) for r in rows])


@router.get(
    "/{case_id}/notes",
    summary="List append-only forensic note revisions for a case",
    response_model=api.NoteList,
    responses=_NOT_FOUND,
)
def list_notes(request: Request, case_id: CaseId) -> api.NoteList:
    try:
        notes = _svc(request).list_notes(case_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.NoteList(items=[_to_note(n) for n in notes])


@router.post(
    "/{case_id}/notes",
    summary="Append a new forensic note or revision linking to case evidence",
    status_code=201,
    response_model=api.NoteSummary,
    responses=_NOT_FOUND,
)
def add_note(request: Request, case_id: CaseId, body: api.AddNoteRequest) -> api.NoteSummary:
    try:
        note = _svc(request).add_note(
            case_id,
            note_kind=body.note_kind,
            confidence=body.confidence,
            title=body.title,
            body=body.body,
            cited_evidence_ids=body.cited_evidence_ids,
            supersedes_note_id=body.supersedes_note_id,
            actor=body.actor,
        )
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return _to_note(note)


@router.get(
    "/{case_id}/exports",
    summary="List report & bundle exports recorded for a case",
    response_model=api.ExportList,
    responses=_NOT_FOUND,
)
def list_case_exports(request: Request, case_id: CaseId) -> api.ExportList:
    try:
        page = _svc(request).list_exports(case_id=case_id, limit=100, offset=0)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return api.ExportList(items=[_to_export(x) for x in page.items], total=page.total)


@router.post(
    "/{case_id}/export",
    summary="Generate an exportable report (Markdown, JSON dossier, or ZIP bundle)",
    status_code=201,
    response_model=api.ExportSummary,
    responses=_NOT_FOUND,
)
def export_case(
    request: Request, case_id: CaseId, body: api.ExportCaseRequest
) -> api.ExportSummary:
    try:
        res = export_case_bundle(
            _svc(request),
            case_id,
            export_format=body.format,
            include_vault_files=body.include_vault_files,
            actor=body.actor,
        )
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    return _to_export(res.export)


@router.get(
    "/{case_id}/exports/{export_id}/download",
    summary="Download a generated report or ZIP bundle",
    responses=_NOT_FOUND,
)
def download_export(request: Request, case_id: CaseId, export_id: ExportId) -> Response:
    try:
        _, path, media_type = resolve_export_artifact(_svc(request), case_id, export_id)
    except ForensicsError as exc:
        raise _refuse(exc) from exc
    data = path.read_bytes()
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{path.name}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
