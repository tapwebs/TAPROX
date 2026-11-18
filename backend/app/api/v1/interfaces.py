from typing import Annotated

from fastapi import APIRouter, Path, Query, Request

from app.core.errors import ApiProblem
from app.schemas.interfaces import InterfaceEventList, InterfaceList, NetworkInterface
from app.services.interface_manager.manager import InterfaceManager, InterfaceNotFoundError
from app.services.interface_manager.raw import InterfaceProviderError

router = APIRouter(prefix="/interfaces", tags=["interfaces"])

InterfaceId = Annotated[
    str, Path(pattern=r"^[A-Za-z0-9._:@-]{1,64}$", description="Interface id from the listing.")
]


def _manager(request: Request) -> InterfaceManager:
    manager: InterfaceManager = request.app.state.interfaces
    return manager


def _unavailable(exc: InterfaceProviderError) -> ApiProblem:
    return ApiProblem(503, f"interfaces_{exc.code}", str(exc))


# Plain `def` handlers run on FastAPI's worker threads, so the operating-system calls never block
# the event loop.


@router.get("", summary="List network interfaces", response_model=InterfaceList)
def list_interfaces(request: Request, refresh: bool = False) -> InterfaceList:
    try:
        return _manager(request).snapshot(force=refresh)
    except InterfaceProviderError as exc:
        raise _unavailable(exc) from exc


@router.post(
    "/refresh",
    summary="Re-read the interfaces now and report what changed",
    response_model=InterfaceList,
)
def refresh_interfaces(request: Request) -> InterfaceList:
    try:
        return _manager(request).snapshot(force=True)
    except InterfaceProviderError as exc:
        raise _unavailable(exc) from exc


@router.get(
    "/events", summary="Recent interface changes (newest first)", response_model=InterfaceEventList
)
def list_events(
    request: Request, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> InterfaceEventList:
    return InterfaceEventList(events=_manager(request).events(limit))


@router.get("/{interface_id}", summary="One interface", response_model=NetworkInterface)
def get_interface(request: Request, interface_id: InterfaceId) -> NetworkInterface:
    try:
        return _manager(request).get(interface_id)
    except InterfaceNotFoundError as exc:
        raise ApiProblem(
            404,
            "interface_not_found",
            f"No interface '{interface_id}' has been seen in this session.",
        ) from exc
    except InterfaceProviderError as exc:
        raise _unavailable(exc) from exc
