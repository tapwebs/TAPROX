import logging
import time
from datetime import datetime

from fastapi import APIRouter, Request, Response
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.database import current_schema_version
from app.models.app_meta import AppMeta
from app.schemas.health import DatabaseHealth, HealthResponse

router = APIRouter(tags=["health"])
log = logging.getLogger(__name__)


def _probe_database(engine: Engine) -> DatabaseHealth:
    try:
        with Session(engine) as session:
            stamp = session.get(AppMeta, "initialized_at")
        return DatabaseHealth(
            status="ok",
            schema_version=current_schema_version(engine),
            initialized_at=datetime.fromisoformat(stamp.value) if stamp else None,
        )
    except SQLAlchemyError:
        # Details go to the log only; API callers must not learn filesystem paths.
        log.warning("Database health probe failed", exc_info=True)
        return DatabaseHealth(status="error", schema_version=None, initialized_at=None)


@router.get(
    "/health",
    summary="Backend and database health",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse, "description": "Database unavailable"}},
)
def get_health(request: Request, response: Response) -> HealthResponse:
    database = _probe_database(request.app.state.engine)
    healthy = database.status == "ok"
    if not healthy:
        response.status_code = 503
    return HealthResponse(
        status="ok" if healthy else "unhealthy",
        service="tapnettrack-backend",
        version=__version__,
        api_version="v1",
        started_at=request.app.state.started_at,
        uptime_seconds=round(time.monotonic() - request.app.state.started_monotonic, 3),
        database=database,
    )
