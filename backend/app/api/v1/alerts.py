"""Stored alerts: list, detail, status changes, audit trail and counts.

Read-only except for an alert's status and note.
"""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Request
from sqlalchemy.exc import OperationalError

from app.core.errors import ApiProblem
from app.schemas import alerts as api
from app.schemas.errors import ErrorResponse
from app.services.detection.lifecycle import TransitionRefused
from app.services.detection.service import DetectionService
from app.services.detection.store import AlertFilter, AlertNotFound, AlertStore

router = APIRouter(prefix="/alerts", tags=["alerts"])

AlertId = Annotated[int, Path(ge=1, le=2**62)]
_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "No such alert"},
    422: {"model": ErrorResponse, "description": "Invalid parameter"},
    503: {"model": ErrorResponse, "description": "The alert database is not available right now"},
}

# Plain `def` handlers run on worker threads: reading alerts touches SQLite.


def _store(request: Request) -> AlertStore:
    service: DetectionService = request.app.state.detection
    if service.store is None:
        raise ApiProblem(503, "detection_unavailable", "Alert storage is not available.")
    return service.store


def _unavailable() -> ApiProblem:
    return ApiProblem(503, "database_unavailable", "The alert database is not available right now.")


def _aware(name: str, value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ApiProblem(
            422, "validation_error", f"{name} needs a time zone, for example 2026-11-05T10:00:00Z."
        )
    return value.astimezone(UTC)


def _filter(
    status: api.AlertStatus | None,
    severity: api.AlertSeverity | None,
    category: api.AlertCategory | None,
    rule_id: str | None,
    device_id: int | None,
    ip: str | None,
    min_risk: int | None,
    since: datetime | None,
    until: datetime | None,
    search: str | None,
) -> AlertFilter:
    clean_ip: str | None = None
    if ip is not None:
        try:
            clean_ip = str(ip_address(ip))
        except ValueError:
            raise ApiProblem(
                422, "validation_error", "ip must be an IPv4 or IPv6 address."
            ) from None
    start, end = _aware("since", since), _aware("until", until)
    if start is not None and end is not None and start > end:
        raise ApiProblem(422, "validation_error", "since must not be later than until.")
    return AlertFilter(
        status=status,
        severity=severity,
        category=category,
        rule_id=rule_id,
        device_id=device_id,
        ip=clean_ip,
        min_risk=min_risk,
        since=start,
        until=end,
        search=(search or "").strip() or None,
    )


Status = Annotated[api.AlertStatus | None, Query(description="Only alerts in this state.")]
Severity = Annotated[api.AlertSeverity | None, Query()]
Category = Annotated[api.AlertCategory | None, Query()]
RuleId = Annotated[
    str | None, Query(pattern=r"^TT-[A-Z]{3}-[0-9]{3}$", description="For example TT-REC-001.")
]
DeviceId = Annotated[int | None, Query(ge=1, le=2**62)]
Address = Annotated[
    str | None, Query(max_length=45, description="Matches the alert's source or its target.")
]
MinRisk = Annotated[int | None, Query(ge=0, le=100)]
Since = Annotated[
    datetime | None, Query(description="Last update at or after this time (needs a time zone).")
]
Until = Annotated[
    datetime | None, Query(description="Last update at or before this time (needs a time zone).")
]
Search = Annotated[str | None, Query(max_length=100, description="Plain text, never a pattern.")]


@router.get(
    "",
    summary="List alerts, newest first by default",
    response_model=api.AlertPage,
    responses=_RESPONSES,
)
def list_alerts(
    request: Request,
    status: Status = None,
    severity: Severity = None,
    category: Category = None,
    rule_id: RuleId = None,
    device_id: DeviceId = None,
    ip: Address = None,
    min_risk: MinRisk = None,
    since: Since = None,
    until: Until = None,
    search: Search = None,
    sort: api.AlertSort = "updated",
    order: api.SortOrder = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> api.AlertPage:
    flt = _filter(
        status, severity, category, rule_id, device_id, ip, min_risk, since, until, search
    )
    try:
        return _store(request).list_alerts(flt, sort, order, limit, offset)
    except OperationalError:
        raise _unavailable() from None


@router.get(
    "/summary",
    summary="Counts by severity, status, category and rule, and alerts created per hour",
    response_model=api.AlertSummary,
    responses=_RESPONSES,
)
def alert_summary(
    request: Request,
    status: Status = None,
    severity: Severity = None,
    category: Category = None,
    rule_id: RuleId = None,
    device_id: DeviceId = None,
    ip: Address = None,
    min_risk: MinRisk = None,
    since: Since = None,
    until: Until = None,
    search: Search = None,
    range: Annotated[
        str,
        Query(
            pattern=r"^(24h|7d|30d|all)$",
            description="Timeline range: 24h hourly, 7d and 30d daily, all by day or week.",
        ),
    ] = "24h",
) -> api.AlertSummary:
    flt = _filter(
        status, severity, category, rule_id, device_id, ip, min_risk, since, until, search
    )
    try:
        return _store(request).summary(flt, range)
    except OperationalError:
        raise _unavailable() from None


@router.get(
    "/{alert_id}",
    summary="One alert: evidence, risk breakdown, benign explanations and blind spots",
    response_model=api.AlertDetail,
    responses=_RESPONSES,
)
def alert_detail(request: Request, alert_id: AlertId) -> api.AlertDetail:
    try:
        detail = _store(request).get_alert(alert_id)
    except OperationalError:
        raise _unavailable() from None
    if detail is None:
        raise ApiProblem(404, "alert_not_found", "There is no alert with that id.")
    return detail


@router.patch(
    "/{alert_id}",
    summary="Change an alert's status (acknowledge, resolve, suppress...) or add a note",
    response_model=api.AlertDetail,
    responses={
        **_RESPONSES,
        409: {"model": ErrorResponse, "description": "That status change is not allowed"},
    },
)
def change_alert(request: Request, alert_id: AlertId, body: api.AlertPatch) -> api.AlertDetail:
    if body.status is None and body.note is None:
        raise ApiProblem(422, "validation_error", "Provide a status, a note, or both.")
    try:
        return _store(request).change_status(alert_id, body.status, body.note)
    except AlertNotFound:
        raise ApiProblem(404, "alert_not_found", "There is no alert with that id.") from None
    except TransitionRefused as exc:
        raise ApiProblem(409, "invalid_status_transition", str(exc)) from None
    except OperationalError:
        raise _unavailable() from None


@router.get(
    "/{alert_id}/events",
    summary="The audit trail of one alert, oldest first",
    response_model=api.AlertEventPage,
    responses=_RESPONSES,
)
def alert_events(
    request: Request,
    alert_id: AlertId,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> api.AlertEventPage:
    try:
        page = _store(request).events(alert_id, limit, offset)
    except OperationalError:
        raise _unavailable() from None
    if page is None:
        raise ApiProblem(404, "alert_not_found", "There is no alert with that id.")
    return page
