"""The device inventory. A device is identified by its MAC address.

* Same MAC, new IP (DHCP)  -> the same device with another address-history row.
* Same IP, different MAC   -> a different device; the IP history shows both.
* A MAC with the locally-administered bit set may be a privacy-randomised address. The same
  physical device can then appear under several MACs. Nothing is merged by guesswork.

No packet data is stored here; that belongs to the future capture architecture.
"""

from datetime import datetime

from sqlalchemy import ForeignKey, Index, SmallInteger, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String(17), unique=True)
    vendor: Mapped[str | None] = mapped_column(String(160), default=None)
    mac_randomized: Mapped[bool] = mapped_column(default=False)
    hostname: Mapped[str | None] = mapped_column(String(255), default=None)
    hostname_source: Mapped[str | None] = mapped_column(String(32), default=None)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, index=True)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, index=True)
    last_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    last_ip_sort: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    last_interface_id: Mapped[str | None] = mapped_column(String(64), default=None)
    confidence: Mapped[str] = mapped_column(String(16))
    last_source: Mapped[str] = mapped_column(String(32))


class DeviceAddress(Base):
    """Every IP address a device has been observed with, per interface (the DHCP history)."""

    __tablename__ = "device_addresses"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "ip", "interface_id", name="uq_device_addresses_device_ip_if"
        ),
        Index("ix_device_addresses_ip", "ip"),
        Index("ix_device_addresses_device", "device_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(45))
    ip_sort: Mapped[str] = mapped_column(String(40))
    family: Mapped[int] = mapped_column(SmallInteger)
    interface_id: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime)


class DeviceObservation(Base):
    """Append-only evidence: who saw this device, how, and how sure that was. Bounded per device."""

    __tablename__ = "device_observations"
    __table_args__ = (
        Index("ix_device_observations_device_time", "device_id", "observed_at"),
        Index("ix_device_observations_scan", "scan_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    observed_at: Mapped[datetime] = mapped_column(UtcDateTime)
    source: Mapped[str] = mapped_column(String(32))
    ip: Mapped[str | None] = mapped_column(String(45), default=None)
    interface_id: Mapped[str | None] = mapped_column(String(64), default=None)
    confidence: Mapped[str] = mapped_column(String(16))
    neighbor_state: Mapped[str | None] = mapped_column(String(16), default=None)
    hostname: Mapped[str | None] = mapped_column(String(255), default=None)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("discovery_scans.id", ondelete="SET NULL"), default=None
    )
