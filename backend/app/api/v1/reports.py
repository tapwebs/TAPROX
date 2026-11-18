"""Reports, Vault Integrity & Audit endpoints (/api/v1/reports/*, /api/v1/audit/*)."""

from __future__ import annotations

from fastapi import APIRouter, Body, Query, Request

from app.api.v1.investigations import _to_export, to_verdict_schema
from app.schemas import forensics as api
from app.services.forensics.service import ForensicsService

router = APIRouter(tags=["reports"])
_DEFAULT_ACTOR_BODY = Body(default_factory=api.ActorActionRequest)


def _svc(request: Request) -> ForensicsService:
    svc: ForensicsService = request.app.state.forensics
    return svc


@router.get(
    "/reports/overview",
    summary="Cross-case vault usage, case status counts, and recent exports",
    response_model=api.ReportsOverviewResponse,
)
def reports_overview(request: Request) -> api.ReportsOverviewResponse:
    svc = _svc(request)
    cases = svc.list_cases(limit=100, offset=0).items
    exports = svc.list_exports(limit=25, offset=0).items
    usage = svc.vault_usage()
    return api.ReportsOverviewResponse(
        total_cases=len(cases),
        open_or_active_cases=sum(1 for c in cases if c.status in {"open", "active"}),
        sealed_cases=sum(1 for c in cases if c.status == "sealed"),
        closed_cases=sum(1 for c in cases if c.status == "closed"),
        vault_used_bytes=int(usage["vault_used_bytes"]),
        vault_max_total_bytes=int(usage["vault_max_total_bytes"]),
        vault_max_file_bytes=int(usage["vault_max_file_bytes"]),
        recent_exports=[_to_export(x) for x in exports],
    )


@router.post(
    "/reports/verify-all",
    summary="Verify cryptographic hashes and custody chains across all investigations",
    response_model=api.VerifyAllResponse,
)
def verify_all_investigations(
    request: Request,
    body: api.ActorActionRequest = _DEFAULT_ACTOR_BODY,
) -> api.VerifyAllResponse:
    reports = _svc(request).verify_all_cases(actor=body.actor)
    return api.VerifyAllResponse(items=[to_verdict_schema(r) for r in reports])


@router.get(
    "/audit/events",
    summary="Query the installation-level append-only forensic audit log",
    response_model=api.AuditEventList,
)
def list_audit_events(
    request: Request,
    category: str | None = Query(default=None, max_length=24),
    outcome: str | None = Query(default=None, max_length=16),
    actor: str | None = Query(default=None, max_length=64),
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> api.AuditEventList:
    page = _svc(request).list_audit_events(
        category=category, outcome=outcome, actor=actor, q=q, limit=limit, offset=offset
    )
    return api.AuditEventList(
        items=[
            api.AuditEventItem(
                id=a.id,
                seq=a.seq,
                occurred_at=a.occurred_at,
                actor=a.actor,
                client_surface=a.client_surface,
                category=a.category,
                action=a.action,
                outcome=a.outcome,
                investigation_id=a.investigation_id,
                resource_ref=a.resource_ref,
                details=a.details,
                prev_audit_sha256=a.prev_audit_sha256,
                audit_sha256=a.audit_sha256,
            )
            for a in page.items
        ],
        total=page.total,
        limit=limit,
        offset=offset,
    )
