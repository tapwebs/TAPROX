"""Stored alerts (Phase 4, revision 0004).

An alert copies its evidence by value, so it never depends on flow rows that Phase 3 later
prunes. Foreign keys to flow sessions, runs and devices are ON DELETE SET NULL for the same
reason.
"""

from datetime import datetime

from sqlalchemy import (
    Float,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class AlertRow(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("uq_alerts_dedup_key", "dedup_key", unique=True),
        Index("ix_alerts_status_updated", "status", "updated_at"),
        Index("ix_alerts_risk_updated", text("risk_score DESC"), text("updated_at DESC")),
        Index("ix_alerts_rule", "rule_id", "updated_at"),
        Index("ix_alerts_entity", "entity_kind", "entity_key"),
        Index("ix_alerts_device", "entity_device_id", "status"),
        Index("ix_alerts_corr", "correlation_group_id"),
        Index("ix_alerts_created", "created_at"),
        {"sqlite_autoincrement": True},  # an alert id is never handed out again after a delete
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16))
    rule_version: Mapped[int] = mapped_column(SmallInteger)
    category: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(160))
    summary: Mapped[str] = mapped_column(String(500))
    why: Mapped[str] = mapped_column(Text)
    benign_json: Mapped[str] = mapped_column(Text)
    blind_spots_json: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(8))
    confidence: Mapped[str] = mapped_column(String(8))
    risk_score: Mapped[int] = mapped_column(SmallInteger)
    risk_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="open")
    status_changed_at: Mapped[datetime] = mapped_column(UtcDateTime)
    status_note: Mapped[str | None] = mapped_column(String(500), default=None)
    entity_kind: Mapped[str] = mapped_column(String(10))
    entity_key: Mapped[str] = mapped_column(String(80))
    entity_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), default=None
    )
    secondary_key: Mapped[str] = mapped_column(String(120))
    dedup_key: Mapped[str] = mapped_column(String(300))
    correlation_group_id: Mapped[str | None] = mapped_column(String(36), default=None)
    observed_start: Mapped[datetime] = mapped_column(UtcDateTime)  # packet time as UTC
    observed_end: Mapped[datetime] = mapped_column(UtcDateTime)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)  # wall clock
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime)
    source: Mapped[str] = mapped_column(String(8))  # live | file
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_runs.id", ondelete="SET NULL"), default=None
    )
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("flow_sessions.id", ondelete="SET NULL"), default=None
    )
    occurrence_count: Mapped[int] = mapped_column(default=1)
    recurrence_count: Mapped[int] = mapped_column(default=0)
    evidence_dropped: Mapped[int] = mapped_column(default=0)
    params_json: Mapped[str] = mapped_column(Text)
    observed_json: Mapped[str] = mapped_column(Text)


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    __table_args__ = (UniqueConstraint("alert_id", "seq", name="uq_alert_evidence_alert_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    seq: Mapped[int]
    kind: Mapped[str] = mapped_column(String(16))
    basis: Mapped[str] = mapped_column(String(10))  # observed | inferred | inventory
    observed_at: Mapped[float | None] = mapped_column(Float, default=None)  # packet time
    text: Mapped[str] = mapped_column(String(300))
    data_json: Mapped[str] = mapped_column(Text)


class AlertEvent(Base):
    """The audit trail of one alert."""

    __tablename__ = "alert_events"
    __table_args__ = (Index("ix_alert_events_alert_at", "alert_id", "at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    at: Mapped[datetime] = mapped_column(UtcDateTime)
    kind: Mapped[str] = mapped_column(String(16))
    from_status: Mapped[str | None] = mapped_column(String(16), default=None)
    to_status: Mapped[str | None] = mapped_column(String(16), default=None)
    note: Mapped[str | None] = mapped_column(String(500), default=None)
    data_json: Mapped[str | None] = mapped_column(Text, default=None)
