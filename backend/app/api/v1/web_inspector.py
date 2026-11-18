"""Web Inspector REST endpoints (/api/v1/web-inspector/*)."""

from typing import Annotated, Any, cast

from fastapi import APIRouter, Path, Query, Request, Response

from app.core.errors import ApiProblem
from app.schemas import web_inspector as api
from app.schemas.errors import ErrorResponse
from app.services.web_inspector.export import (
    export_inspection_json,
    export_inspection_markdown,
)
from app.services.web_inspector.service import InspectionRefused, WebInspectorService
from app.services.web_inspector.store import InspectionDetail, InspectionSummary

router = APIRouter(prefix="/web-inspector", tags=["web-inspector"])

InspectionId = Annotated[int, Path(ge=1, le=2**62)]
_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "No such inspection"}
}
_START_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Authorization confirmation required"},
    409: {"model": ErrorResponse, "description": "Another inspection is running"},
    422: {"model": ErrorResponse, "description": "Invalid or forbidden target URL"},
}


def _service(request: Request) -> WebInspectorService:
    svc: WebInspectorService = request.app.state.web_inspector
    return svc


def _not_found(inspection_id: int) -> ApiProblem:
    return ApiProblem(404, "inspection_not_found", f"No inspection with id {inspection_id}.")


def _to_summary(s: InspectionSummary) -> api.WebInspectionSummary:
    return api.WebInspectionSummary(
        id=s.id,
        target_url_sanitized=s.target_url_sanitized,
        scheme=s.scheme,
        host=s.host,
        port=s.port,
        method=cast(api.InspectionMethod, s.method),
        allow_private=s.allow_private,
        allow_insecure_tls=s.allow_insecure_tls,
        follow_redirects=s.follow_redirects,
        max_redirects=s.max_redirects,
        status=cast(api.InspectionStatus, s.status),
        final_url_sanitized=s.final_url_sanitized,
        final_ip=s.final_ip,
        redirect_count=s.redirect_count,
        http_status=s.http_status,
        fallback_performed=s.fallback_performed,
        fallback_method=s.fallback_method,
        fallback_status=s.fallback_status,
        assessment_response_method=s.assessment_response_method,
        assessment_response_status=s.assessment_response_status,
        assessment_classification=cast(api.AssessmentClassification, s.assessment_classification),
        inconclusive_reason=s.inconclusive_reason,
        tls_version=s.tls_version,
        tls_cipher=s.tls_cipher,
        cert_verified=s.cert_verified,
        cert_expires_at=s.cert_expires_at,
        findings_high=s.findings_high,
        findings_medium=s.findings_medium,
        findings_low=s.findings_low,
        findings_info=s.findings_info,
        warnings=s.warnings,
        error_code=s.error_code,
        error_message=s.error_message,
        source_session_id=s.source_session_id,
        source_device_id=s.source_device_id,
        source_alert_id=s.source_alert_id,
        started_at=s.started_at,
        ended_at=s.ended_at,
        duration_ms=s.duration_ms,
        request_profile=getattr(s, "request_profile", "standard"),
    )


def _to_detail(d: InspectionDetail) -> api.WebInspectionDetail:
    summary = _to_summary(d)
    return api.WebInspectionDetail(
        **summary.model_dump(),
        hops=[
            api.WebHopSchema(
                hop_index=h.hop_index,
                method=h.method,
                url_sanitized=h.url_sanitized,
                scheme=h.scheme,
                host=h.host,
                port=h.port,
                resolved_ip=h.resolved_ip,
                status_code=h.status_code,
                protocol_version=h.protocol_version,
                latency_ms=h.latency_ms,
                content_type=h.content_type,
                body_bytes_read=h.body_bytes_read,
                body_sha256=h.body_sha256,
                headers=[api.WebHeaderEntry(name=k, value=v) for k, v in h.headers],
                tls=api.WebTlsSummary(**h.tls) if h.tls is not None else None,
                redirect_location_sanitized=h.redirect_location_sanitized,
                blocked_reason=h.blocked_reason,
            )
            for h in d.hops
        ],
        certificates=[
            api.WebCertificateSchema(
                hop_index=c.hop_index,
                subject=c.subject,
                issuer=c.issuer,
                serial_hex=c.serial_hex,
                sha256_fingerprint=c.sha256_fingerprint,
                not_before=c.not_before,
                not_after=c.not_after,
                sans=c.sans,
                key_algorithm=c.key_algorithm,
                key_bits=c.key_bits,
                sig_algorithm=c.sig_algorithm,
                is_self_signed=c.is_self_signed,
                is_ca=c.is_ca,
                hostname_matched=c.hostname_matched,
                trust_verified=c.trust_verified,
                trust_error=c.trust_error,
            )
            for c in d.certificates
        ],
        cookies=[
            api.WebCookieSchema(
                hop_index=ck.hop_index,
                name=ck.name,
                domain=ck.domain,
                path=ck.path,
                secure=ck.secure,
                http_only=ck.http_only,
                same_site=ck.same_site,
                max_age_s=ck.max_age_s,
                expires_at=ck.expires_at,
                has_host_prefix=ck.has_host_prefix,
                has_secure_prefix=ck.has_secure_prefix,
                value_length=ck.value_length,
            )
            for ck in d.cookies
        ],
        findings=[
            api.WebFindingSchema(
                rule_id=f.rule_id,
                category=cast(api.WebCategory, f.category),
                severity=cast(api.WebSeverity, f.severity),
                confidence=cast(api.WebConfidence, f.confidence),
                title=f.title,
                summary=f.summary,
                why=f.why,
                remediation=f.remediation,
                benign_explanations=f.benign_explanations,
                blind_spots=f.blind_spots,
                evidence=f.evidence,
            )
            for f in d.findings
        ],
        header_matrix=[
            api.HeaderMatrixEntry(
                header=r.header,
                status=r.status,
                observed_value=r.observed_value,
                note=r.note,
            )
            for r in d.header_matrix
        ],
    )


@router.post(
    "/inspections",
    summary="Start an authorized passive web inspection",
    status_code=202,
    response_model=api.WebInspectionSummary,
    responses=_START_RESPONSES,
)
def start_inspection(request: Request, body: api.WebInspectionRequest) -> api.WebInspectionSummary:
    try:
        summary = _service(request).start(
            url=body.url,
            method=body.method,
            follow_redirects=body.follow_redirects,
            max_redirects=body.max_redirects,
            allow_private=body.allow_private_network,
            allow_insecure_tls=body.allow_insecure_tls,
            confirm_authorized=body.confirm_authorized,
            source_session_id=body.source_session_id,
            source_device_id=body.source_device_id,
            source_alert_id=body.source_alert_id,
            request_profile=body.request_profile,
            custom_user_agent=body.custom_user_agent,
        )
        return _to_summary(summary)
    except InspectionRefused as exc:
        raise ApiProblem(exc.status, exc.code, str(exc)) from exc


@router.get(
    "/inspections",
    summary="List Web Inspector history (newest first)",
    response_model=api.WebInspectionList,
)
def list_inspections(
    request: Request,
    status: api.InspectionStatus | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> api.WebInspectionList:
    items, total = _service(request).list(status=status, search=search, limit=limit, offset=offset)
    return api.WebInspectionList(
        inspections=[_to_summary(i) for i in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/inspections/{inspection_id}",
    summary="One inspection with hops, certificates, cookie flags, and findings",
    response_model=api.WebInspectionDetail,
    responses=_NOT_FOUND,
)
def get_inspection(request: Request, inspection_id: InspectionId) -> api.WebInspectionDetail:
    detail = _service(request).get(inspection_id)
    if detail is None:
        raise _not_found(inspection_id)
    return _to_detail(detail)


@router.post(
    "/inspections/{inspection_id}/cancel",
    summary="Cancel an active inspection",
    response_model=api.WebInspectionSummary,
    responses=_NOT_FOUND,
)
def cancel_inspection(request: Request, inspection_id: InspectionId) -> api.WebInspectionSummary:
    summary = _service(request).cancel(inspection_id)
    if summary is None:
        raise _not_found(inspection_id)
    return _to_summary(summary)


@router.delete(
    "/inspections/{inspection_id}",
    summary="Delete one finished inspection",
    response_model=api.DeleteWebInspectionResult,
    responses=_NOT_FOUND,
)
def delete_inspection(
    request: Request, inspection_id: InspectionId
) -> api.DeleteWebInspectionResult:
    try:
        deleted = _service(request).delete_one(inspection_id)
    except InspectionRefused as exc:
        raise ApiProblem(exc.status, exc.code, str(exc)) from exc
    if not deleted:
        raise _not_found(inspection_id)
    return api.DeleteWebInspectionResult(deleted=True)


@router.delete(
    "/history",
    summary="Delete all finished Web Inspector history",
    response_model=api.DeleteWebHistoryResult,
)
def delete_history(
    request: Request, body: api.DeleteWebHistoryRequest
) -> api.DeleteWebHistoryResult:
    if not body.confirm:
        raise ApiProblem(
            422,
            "confirmation_required",
            "Clearing Web Inspector history requires confirm=true.",
        )
    try:
        removed = _service(request).delete_history()
    except InspectionRefused as exc:
        raise ApiProblem(exc.status, exc.code, str(exc)) from exc
    return api.DeleteWebHistoryResult(deleted_inspections=removed)


@router.get(
    "/inspections/{inspection_id}/export",
    summary="Export an inspection report as redacted JSON or Markdown",
    responses={
        **_NOT_FOUND,
        200: {
            "description": "Sanitized inspection report",
            "content": {
                "application/json": {},
                "text/markdown": {},
            },
        },
    },
)
def export_inspection(
    request: Request,
    inspection_id: InspectionId,
    format: api.ExportFormat = "json",
) -> Response:
    detail = _service(request).get(inspection_id)
    if detail is None:
        raise _not_found(inspection_id)
    if format == "markdown":
        content = export_inspection_markdown(detail)
        media = "text/markdown; charset=utf-8"
        ext = "md"
    else:
        content = export_inspection_json(detail)
        media = "application/json; charset=utf-8"
        ext = "json"
    filename = f"taprox-web-inspection-{inspection_id}.{ext}"
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
