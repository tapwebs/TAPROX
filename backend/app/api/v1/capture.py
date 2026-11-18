from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query, Request

from app.core.errors import ApiProblem
from app.schemas.capture import (
    CaptureInterfaceList,
    CaptureStatus,
    FilterCheck,
    FilterCheckRequest,
    OpenCaptureRequest,
    PacketDetail,
    PacketPage,
    PacketSort,
    SaveCaptureRequest,
    SavedCapture,
    StartCaptureRequest,
)
from app.schemas.errors import ErrorResponse
from app.services.capture.service import CaptureRefused, CaptureService

router = APIRouter(prefix="/capture", tags=["capture"])

_REFUSED: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "The request was refused (path, filter or value)"},
    404: {"model": ErrorResponse, "description": "No such interface, file or packet"},
    409: {"model": ErrorResponse, "description": "Not possible in the current capture state"},
    503: {"model": ErrorResponse, "description": "Capture tools are missing or failed"},
}

# Plain `def` handlers run on worker threads: they may wait on a tool subprocess.


def _service(request: Request) -> CaptureService:
    service: CaptureService = request.app.state.capture
    return service


def _refuse(exc: CaptureRefused) -> ApiProblem:
    return ApiProblem(exc.status, exc.code, str(exc))


@router.get("/status", summary="The current capture session", response_model=CaptureStatus)
def capture_status(request: Request) -> CaptureStatus:
    return _service(request).status()


@router.get(
    "/interfaces",
    summary="Interfaces that can be captured on",
    response_model=CaptureInterfaceList,
    responses=_REFUSED,
)
def capture_interfaces(request: Request) -> CaptureInterfaceList:
    try:
        return _service(request).capture_interfaces()
    except CaptureRefused as exc:
        raise _refuse(exc) from exc


@router.post(
    "/start",
    summary="Start a passive capture on one interface",
    status_code=202,
    response_model=CaptureStatus,
    responses=_REFUSED,
)
def start_capture(request: Request, body: StartCaptureRequest) -> CaptureStatus:
    try:
        return _service(request).start(body)
    except CaptureRefused as exc:
        raise _refuse(exc) from exc


@router.post("/stop", summary="Ask the running capture to stop", response_model=CaptureStatus)
def stop_capture(request: Request) -> CaptureStatus:
    return _service(request).stop()


@router.get(
    "/packets",
    summary="One page of packets (server-side sort, filter and search)",
    response_model=PacketPage,
    responses=_REFUSED,
)
def list_packets(
    request: Request,
    offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    sort: PacketSort = "number",
    order: Literal["asc", "desc"] = "asc",
    display_filter: Annotated[str | None, Query(max_length=1000)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> PacketPage:
    try:
        return _service(request).packets(offset, limit, sort, order, display_filter, search)
    except CaptureRefused as exc:
        raise _refuse(exc) from exc


@router.get(
    "/packets/{number}",
    summary="Decoded detail and bytes of one packet",
    response_model=PacketDetail,
    responses=_REFUSED,
)
def packet_detail(request: Request, number: Annotated[int, Path(ge=1, le=2**31)]) -> PacketDetail:
    try:
        detail = _service(request).packet_detail(number)
    except CaptureRefused as exc:
        raise _refuse(exc) from exc
    if detail is None:
        raise ApiProblem(404, "packet_not_found", f"There is no packet {number} in this capture.")
    return detail


@router.post(
    "/filter/validate",
    summary="Check a display filter with tshark",
    response_model=FilterCheck,
    responses=_REFUSED,
)
def validate_filter(request: Request, body: FilterCheckRequest) -> FilterCheck:
    try:
        return _service(request).check_filter(body.display_filter)
    except CaptureRefused as exc:
        raise _refuse(exc) from exc


@router.post(
    "/save",
    summary="Save the capture as a new PCAPNG file (never overwrites)",
    response_model=SavedCapture,
    responses=_REFUSED,
)
def save_capture(request: Request, body: SaveCaptureRequest) -> SavedCapture:
    try:
        return _service(request).save(body.path)
    except CaptureRefused as exc:
        raise _refuse(exc) from exc


@router.post(
    "/open",
    summary="Open a PCAPNG file for inspection",
    response_model=CaptureStatus,
    responses=_REFUSED,
)
def open_capture(request: Request, body: OpenCaptureRequest) -> CaptureStatus:
    try:
        return _service(request).open_file(body.path)
    except CaptureRefused as exc:
        raise _refuse(exc) from exc
