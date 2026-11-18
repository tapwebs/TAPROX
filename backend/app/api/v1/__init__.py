"""Version 1 of the REST API. Every route registered here requires the bearer token."""

from fastapi import APIRouter, Depends

from app.api.v1 import (
    alerts,
    behaviour,
    capture,
    detection,
    devices,
    discovery,
    flows,
    health,
    interfaces,
    investigations,
    reports,
    system,
    topology,
    web_inspector,
)
from app.core.security import require_token
from app.schemas.errors import ErrorResponse

router = APIRouter(
    dependencies=[Depends(require_token)],
    responses={
        401: {"model": ErrorResponse, "description": "Missing or invalid API token"},
        403: {"model": ErrorResponse, "description": "Host or Origin not permitted"},
        422: {"model": ErrorResponse, "description": "Request validation failed"},
    },
)
router.include_router(health.router)
router.include_router(system.router)
router.include_router(interfaces.router)
router.include_router(devices.router)
router.include_router(discovery.router)
router.include_router(capture.router)
router.include_router(flows.router)
router.include_router(detection.router)
router.include_router(alerts.router)
router.include_router(behaviour.router)
router.include_router(topology.router)
router.include_router(web_inspector.router)
router.include_router(investigations.router)
router.include_router(reports.router)
