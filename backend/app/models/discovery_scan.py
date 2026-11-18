from datetime import datetime

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class DiscoveryScan(Base):
    """One discovery run: what was asked, how far it got, and how it ended."""

    __tablename__ = "discovery_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    interface_id: Mapped[str] = mapped_column(String(64))
    interface_name: Mapped[str] = mapped_column(String(255))
    mode: Mapped[str] = mapped_column(String(16))
    network: Mapped[str | None] = mapped_column(String(43), default=None)
    status: Mapped[str] = mapped_column(String(16))
    phase: Mapped[str | None] = mapped_column(String(24), default=None)
    targets_total: Mapped[int] = mapped_column(default=0)
    targets_done: Mapped[int] = mapped_column(default=0)
    devices_found: Mapped[int] = mapped_column(default=0)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    error_code: Mapped[str | None] = mapped_column(String(48), default=None)
    error_message: Mapped[str | None] = mapped_column(String(500), default=None)
    resolve_names: Mapped[bool] = mapped_column(default=True)
    warnings_json: Mapped[str | None] = mapped_column(Text, default=None)  # JSON list of strings
