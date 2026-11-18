from ipaddress import ip_address
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Request

from app.core.errors import ApiProblem
from app.schemas import flows as api
from app.schemas.errors import ErrorResponse
from app.services.flows.aggregate import FlowFilter
from app.services.flows.service import FlowRefused, FlowService

router = APIRouter(prefix="/flows", tags=["flows"])

Session = Annotated[
    str,
    Query(
        pattern=r"^(current|[0-9]{1,9})$",
        description="'current' (what the Packet Explorer shows) or a saved session id.",
    ),
]
_REFUSED: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "No such flow or flow session"},
    422: {"model": ErrorResponse, "description": "Invalid parameter"},
}

# Plain `def` handlers run on worker threads: reading saved flows touches SQLite.


def _service(request: Request) -> FlowService:
    service: FlowService = request.app.state.flows
    return service


def _refuse(exc: FlowRefused) -> ApiProblem:
    return ApiProblem(exc.status, exc.code, str(exc))


@router.get(
    "/summary",
    summary="Totals, top talkers, protocols, destinations and applications",
    response_model=api.FlowSummary,
)
def flow_summary(request: Request, session: Session = "current") -> api.FlowSummary:
    try:
        return _service(request).summary(session)
    except FlowRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "/sessions", summary="Capture sessions whose flows are kept", response_model=api.FlowSessionList
)
def flow_sessions(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
    offset: Annotated[int, Query(ge=0, le=1000)] = 0,
) -> api.FlowSessionList:
    return _service(request).sessions(limit, offset)


@router.get(
    "/protocols",
    summary="Traffic by protocol",
    response_model=api.ProtocolStats,
    responses=_REFUSED,
)
def flow_protocols(request: Request, session: Session = "current") -> api.ProtocolStats:
    try:
        return _service(request).protocols(session)
    except FlowRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "/applications",
    summary="Identified applications and services, with the evidence for each",
    response_model=api.ApplicationStats,
    responses=_REFUSED,
)
def flow_applications(request: Request, session: Session = "current") -> api.ApplicationStats:
    try:
        return _service(request).applications(session)
    except FlowRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "/conversations",
    summary="Which pairs of addresses talk the most",
    response_model=api.ConversationList,
    responses=_REFUSED,
)
def flow_conversations(
    request: Request,
    session: Session = "current",
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> api.ConversationList:
    try:
        return _service(request).conversations(session, limit)
    except FlowRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "/timeline", summary="Traffic over time", response_model=api.Timeline, responses=_REFUSED
)
def flow_timeline(request: Request, session: Session = "current") -> api.Timeline:
    try:
        return _service(request).timeline(session)
    except FlowRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "",
    summary="Search, filter and sort flows (active and finished)",
    response_model=api.FlowPage,
    responses=_REFUSED,
)
def list_flows(
    request: Request,
    session: Session = "current",
    state: api.FlowState | None = None,
    transport: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9-]{1,24}$")] = None,
    protocol: Annotated[str | None, Query(max_length=40)] = None,
    application: Annotated[str | None, Query(max_length=64)] = None,
    confidence: api.Confidence | None = None,
    port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    ip: Annotated[str | None, Query(max_length=45)] = None,
    device_id: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    search: Annotated[str | None, Query(max_length=100)] = None,
    sort: api.FlowSort = "last_seen",
    order: Annotated[str, Query(pattern=r"^(asc|desc)$")] = "desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> api.FlowPage:
    ips: frozenset[str] | None = None
    if ip is not None:
        try:
            ips = frozenset({str(ip_address(ip))})
        except ValueError:
            raise ApiProblem(
                422, "validation_error", "ip must be an IPv4 or IPv6 address"
            ) from None
    flt = FlowFilter(
        state=state,
        transport=transport,
        protocol=protocol,
        application=application,
        confidence=confidence,
        port=port,
        ips=ips,
        search=search,
    )
    try:
        return _service(request).list_flows(session, flt, sort, order, limit, offset, device_id)
    except FlowRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "/{flow_id}",
    summary="One flow: counters, protocol details, evidence and limitations",
    response_model=api.FlowDetail,
    responses=_REFUSED,
)
def flow_detail(
    request: Request, flow_id: Annotated[str, Path(pattern=r"^[0-9]{1,9}-[0-9]{1,9}$")]
) -> api.FlowDetail:
    try:
        return _service(request).detail(flow_id)
    except FlowRefused as exc:
        raise _refuse(exc) from exc
