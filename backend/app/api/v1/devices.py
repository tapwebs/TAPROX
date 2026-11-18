from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.core.errors import ApiProblem
from app.models import device as orm
from app.repositories import devices as repo
from app.schemas import devices as schemas
from app.services.interface_manager.raw import InterfaceProviderError

router = APIRouter(prefix="/devices", tags=["devices"])

DeviceId = Annotated[int, Path(ge=1, le=2**62, description="Device id from the listing.")]
IdPattern = r"^[A-Za-z0-9._:@-]{1,64}$"  # same alphabet as the interfaces API


def _local_macs(request: Request) -> set[str]:
    """MACs of this computer's own interfaces, from the cached interface snapshot."""
    try:
        return {n.mac for n in request.app.state.interfaces.snapshot().interfaces if n.mac}
    except InterfaceProviderError:
        return set()  # the inventory stays usable when the interface provider is not


def _present(device: orm.Device, now: datetime, local: set[str]) -> schemas.Device:
    return schemas.Device(
        id=device.id,
        mac=device.mac,
        is_local=device.mac in local,
        observed=schemas.ObservedFacts(
            ip=device.last_ip,
            interface_id=device.last_interface_id,
            hostname=device.hostname,
            hostname_source=device.hostname_source,
            first_seen=device.first_seen,
            last_seen=device.last_seen,
            source=device.last_source,
            confidence=device.confidence,  # type: ignore[arg-type]
        ),
        inferred=schemas.InferredFacts(
            vendor=device.vendor,
            vendor_basis="oui" if device.vendor else None,
            mac_randomized=device.mac_randomized,
            state=repo.device_state(device.last_seen, now, device.confidence),
        ),
    )


def _device_or_404(session: Session, device_id: int) -> orm.Device:
    device = repo.get_device(session, device_id)
    if device is None:
        raise ApiProblem(404, "device_not_found", f"No device with id {device_id}.")
    return device


@router.get("", summary="List the device inventory", response_model=schemas.DeviceList)
def list_devices(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    search: Annotated[
        str | None,
        Query(max_length=100, description="Matches IP (including past IPs), MAC, name or vendor."),
    ] = None,
    state: repo.DeviceState | None = None,
    interface_id: Annotated[str | None, Query(pattern=IdPattern)] = None,
    ip: Annotated[str | None, Query(max_length=45)] = None,
    scan_id: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9-]{1,36}$")] = None,
    sort: repo.SortField = "last_seen",
    order: repo.SortOrder = "desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> schemas.DeviceList:
    if ip is not None:
        try:
            ip = str(ip_address(ip))  # canonical text, so "::1" and "0:0::1" find the same rows
        except ValueError:
            raise ApiProblem(
                422, "validation_error", "ip must be an IPv4 or IPv6 address"
            ) from None
    now = datetime.now(UTC)
    query = repo.DeviceQuery(
        search=search,
        state=state,
        interface_id=interface_id,
        ip=ip,
        scan_id=scan_id,
        sort=sort,
        order=order,
        limit=limit,
        offset=offset,
    )
    rows, total = repo.list_devices(session, query, now=now)
    local = _local_macs(request)
    return schemas.DeviceList(
        devices=[_present(d, now, local) for d in rows],
        total=total,
        limit=limit,
        offset=offset,
        generated_at=now,
    )


@router.get(
    "/{device_id}",
    summary="One device with its address history",
    response_model=schemas.DeviceDetail,
)
def get_device(
    request: Request, session: Annotated[Session, Depends(get_session)], device_id: DeviceId
) -> schemas.DeviceDetail:
    device = _device_or_404(session, device_id)
    summary = _present(device, datetime.now(UTC), _local_macs(request))
    return schemas.DeviceDetail(
        **summary.model_dump(),
        addresses=[
            schemas.DeviceAddress(
                ip=a.ip,
                family=6 if a.family == 6 else 4,
                interface_id=a.interface_id,
                first_seen=a.first_seen,
                last_seen=a.last_seen,
            )
            for a in repo.list_addresses(session, device.id)
        ],
    )


@router.get(
    "/{device_id}/observations",
    summary="Observation history of one device (newest first)",
    response_model=schemas.DeviceObservationList,
)
def list_observations(
    session: Annotated[Session, Depends(get_session)],
    device_id: DeviceId,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> schemas.DeviceObservationList:
    _device_or_404(session, device_id)
    rows, total = repo.list_observations(session, device_id, limit=limit, offset=offset)
    return schemas.DeviceObservationList(
        observations=[
            schemas.DeviceObservation(
                id=o.id,
                observed_at=o.observed_at,
                source=o.source,
                ip=o.ip,
                interface_id=o.interface_id,
                confidence=o.confidence,  # type: ignore[arg-type]
                neighbor_state=o.neighbor_state,
                hostname=o.hostname,
                scan_id=o.scan_id,
            )
            for o in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )
