from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Request

from app.core.errors import ApiProblem
from app.schemas.discovery import CurrentScan, Scan, ScanList, ScanRequest
from app.schemas.errors import ErrorResponse
from app.services.discovery.service import DiscoveryService, ScanRefused

router = APIRouter(prefix="/discovery", tags=["discovery"])

ScanId = Annotated[str, Path(pattern=r"^[A-Za-z0-9-]{1,36}$", description="Scan id.")]
_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "No such scan"}
}
_REFUSED: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Active scan not authorised by the user"},
    404: {"model": ErrorResponse, "description": "No such interface"},
    409: {"model": ErrorResponse, "description": "A scan is running, or the interface is unusable"},
    503: {"model": ErrorResponse, "description": "The operating system cannot do discovery now"},
}

# Plain `def` handlers run on worker threads. Starting a scan only validates and spawns the scan
# thread; the scan itself never runs inside a request.


def _service(request: Request) -> DiscoveryService:
    service: DiscoveryService = request.app.state.discovery
    return service


def _not_found(scan_id: str) -> ApiProblem:
    return ApiProblem(404, "scan_not_found", f"No scan with id {scan_id}.")


@router.post(
    "/scans",
    summary="Start a discovery scan",
    status_code=202,
    response_model=Scan,
    responses=_REFUSED,
)
def start_scan(request: Request, body: ScanRequest) -> Scan:
    try:
        return _service(request).start(body)
    except ScanRefused as exc:
        raise ApiProblem(exc.status, exc.code, str(exc)) from exc


@router.get("/scans", summary="Scan history (newest first)", response_model=ScanList)
def list_scans(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ScanList:
    scans, total = _service(request).list(limit=limit, offset=offset)
    return ScanList(scans=scans, total=total, limit=limit, offset=offset)


@router.get("/scans/current", summary="The scan running now, if any", response_model=CurrentScan)
def current_scan(request: Request) -> CurrentScan:
    return CurrentScan(scan=_service(request).current())


@router.get("/scans/{scan_id}", summary="One scan", response_model=Scan, responses=_NOT_FOUND)
def get_scan(request: Request, scan_id: ScanId) -> Scan:
    scan = _service(request).get(scan_id)
    if scan is None:
        raise _not_found(scan_id)
    return scan


@router.post(
    "/scans/{scan_id}/cancel",
    summary="Ask a running scan to stop",
    response_model=Scan,
    responses=_NOT_FOUND,
)
def cancel_scan(request: Request, scan_id: ScanId) -> Scan:
    scan = _service(request).cancel(scan_id)
    if scan is None:
        raise _not_found(scan_id)
    return scan
