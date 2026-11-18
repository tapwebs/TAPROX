from fastapi import APIRouter

from app.schemas.system import CapturePrerequisitesResponse
from app.services.capture.prerequisites import detect_capture_prerequisites

router = APIRouter(prefix="/system", tags=["system"])


@router.get(
    "/capture-prerequisites",
    summary="Detect native packet-capture prerequisites on this machine",
    response_model=CapturePrerequisitesResponse,
)
def get_capture_prerequisites() -> CapturePrerequisitesResponse:
    # A plain `def`: FastAPI runs it on a worker thread, so the subprocess calls do not block
    # the event loop.
    return detect_capture_prerequisites()
