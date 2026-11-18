"""Finds the devices a finished discovery scan added (input of rule TT-DEV-001).

A device counts as new when its first sighting falls inside the scan, the inventory already held at least
`min_inventory_size` devices from before the scan, an earlier completed scan of the same interface is at least
`network_age_h` hours older than this one, and the user has not marked the device known. The first scans on a network
therefore raise nothing.
"""

from collections.abc import Mapping
from datetime import timedelta

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.models.detection import DeviceAnnotation
from app.models.device import Device
from app.models.discovery_scan import DiscoveryScan
from app.services.detection.events import InventoryDevicesNew, NewDevice

MAX_DEVICES = 100


def new_devices(
    engine: Engine, scan_id: str, params: Mapping[str, int | float]
) -> InventoryDevicesNew | None:
    """The event for a completed scan, or None when nothing qualifies."""
    with Session(engine) as db:
        scan = db.get(DiscoveryScan, scan_id)
        if scan is None or scan.status != "completed" or scan.finished_at is None:
            return None
        older = scan.started_at - timedelta(hours=float(params["network_age_h"]))
        earlier = db.scalar(
            select(func.count())
            .select_from(DiscoveryScan)
            .where(
                DiscoveryScan.interface_id == scan.interface_id,
                DiscoveryScan.status == "completed",
                DiscoveryScan.started_at <= older,
                DiscoveryScan.id != scan.id,
            )
        )
        before = (
            db.scalar(
                select(func.count()).select_from(Device).where(Device.first_seen < scan.started_at)
            )
            or 0
        )
        if not earlier or before < int(params["min_inventory_size"]):
            return None
        known = select(DeviceAnnotation.device_id).where(DeviceAnnotation.trust == "known")
        rows = db.scalars(
            select(Device)
            .where(
                Device.first_seen >= scan.started_at,
                Device.first_seen <= scan.finished_at,
                Device.id.not_in(known),
            )
            .order_by(Device.first_seen, Device.id)
            .limit(MAX_DEVICES)
        ).all()
        if not rows:
            return None
        devices = tuple(
            NewDevice(d.mac, d.last_ip, d.vendor, d.mac_randomized, d.first_seen.timestamp())
            for d in rows
        )
        return InventoryDevicesNew(
            scan.finished_at.timestamp(), scan_id, before + len(rows), devices
        )
