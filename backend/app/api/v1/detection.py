from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from sqlalchemy.exc import OperationalError

from app.core.errors import ApiProblem
from app.schemas.alerts import DeleteHistoryRequest, DeleteHistoryResult, StoredRunPage
from app.schemas.detection import DetectionRun, DetectionStatus
from app.schemas.errors import ErrorResponse
from app.services.detection.persist import WriterBusy
from app.services.detection.service import DetectionService, DetectionUnavailable
from app.services.detection.store import AlertStore

router = APIRouter(prefix="/detection", tags=["detection"])


def _service(request: Request) -> DetectionService:
    service: DetectionService = request.app.state.detection
    return service


def _store(request: Request) -> AlertStore:
    store = _service(request).store
    if store is None:
        raise ApiProblem(503, "detection_unavailable", "Alert storage is not available.")
    return store


def _run(raw: Any) -> DetectionRun:
    e = raw["engine"]
    return DetectionRun(
        run_id=raw["run_id"],
        stored_run_id=raw["stored_run_id"],
        warnings=raw["warnings"],
        session_id=raw["session_id"],
        source=raw["source"],
        status=raw["status"],
        error=raw["error"],
        started_at=raw["started_at"],
        ended_at=raw["ended_at"],
        queue=raw["queue"],
        events_processed=e["processed"],
        events_by_kind=e["events"],
        malformed_events=e["malformed"],
        findings=e["findings"],
        alerts_created=e["alerts_created"],
        alerts_updated=e["alerts_updated"],
        alerts_unchanged=e["alerts_unchanged"],
        alerts_evicted=e["alerts_evicted"],
        alerts_in_memory=e["alerts_in_memory"],
        alerts_by_severity=e["alerts_by_severity"],
        self_activity_excluded=e["self_activity_excluded"],
        rule_errors=e["rule_errors"],
        rule_states={rule_id: state for rule_id, (state, _reason) in e["rule_states"].items()},
        finished=e["finished"],
    )


@router.get(
    "/status",
    summary="Threat-detection counters and diagnostics (no alert content)",
    response_model=DetectionStatus,
)
def detection_status(request: Request) -> DetectionStatus:
    raw = _service(request).status()
    return DetectionStatus(
        enabled=raw["enabled"],
        queue_size=raw["queue_size"],
        runs_kept=raw["runs_kept"],
        max_alerts_per_run=raw["max_alerts_per_run"],
        alerts_are_kept_in_memory_only=not raw["persistence"]["enabled"],
        persistence=raw["persistence"],
        rules=raw["rules"],
        runs=[_run(r) for r in raw["runs"]],
    )


_STORAGE: dict[int | str, dict[str, Any]] = {
    503: {"model": ErrorResponse, "description": "The alert database is not available right now"},
}


@router.get(
    "/runs",
    summary="Stored detection runs: one per analysed session, with counts and warnings",
    response_model=StoredRunPage,
    responses=_STORAGE,
)
def detection_runs(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> StoredRunPage:
    store = _store(request)
    try:
        return store.list_runs(limit, offset)
    except OperationalError:
        raise ApiProblem(
            503, "database_unavailable", "The alert database is not available right now."
        ) from None


@router.delete(
    "/history",
    summary="Delete all stored alerts and finished detection runs (cannot be undone)",
    response_model=DeleteHistoryResult,
    responses={
        **_STORAGE,
        422: {
            "model": ErrorResponse,
            "description": "The request body is missing or confirm is not true",
        },
    },
)
def delete_detection_history(request: Request, body: DeleteHistoryRequest) -> DeleteHistoryResult:
    """Removes alerts with their evidence and events, and runs that have finished.

    Inventory, flows, captures, rule settings and everything else are left alone. The body must be
    `{"confirm": true}`.
    """
    if not body.confirm:
        raise ApiProblem(
            422, "confirmation_required", "Deleting security history needs confirm to be true."
        )
    try:
        return _service(request).delete_history()
    except DetectionUnavailable:
        raise ApiProblem(503, "detection_unavailable", "Alert storage is not available.") from None
    except WriterBusy:
        raise ApiProblem(
            503, "database_unavailable", "Alert storage is busy; try again in a moment."
        ) from None
    except OperationalError:
        raise ApiProblem(
            503, "database_unavailable", "The alert database is not available right now."
        ) from None
