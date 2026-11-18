"""Detection runs, rule settings and suppressions (Phase 4, revision 0004).

A run is one analysed session. Rule settings hold only what the user changed (absence means
"default"), so a new rule needs no data migration.
"""

from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    __table_args__ = (
        Index("ix_detection_runs_started", "started_at"),
        Index("ix_detection_runs_session", "session_id"),
        {"sqlite_autoincrement": True},  # a deleted run's id is never handed out again
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("flow_sessions.id", ondelete="SET NULL"), default=None
    )
    source: Mapped[str] = mapped_column(String(8))  # live | file
    started_at: Mapped[datetime] = mapped_column(UtcDateTime)
    ended_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    status: Mapped[str] = mapped_column(String(12))  # running | completed | failed | aborted
    events_processed: Mapped[int] = mapped_column(default=0)
    events_dropped: Mapped[int] = mapped_column(default=0)
    alerts_created: Mapped[int] = mapped_column(default=0)
    alerts_updated: Mapped[int] = mapped_column(default=0)
    findings_suppressed: Mapped[int] = mapped_column(default=0)
    baseline_updated: Mapped[bool] = mapped_column(default=False)
    rules_json: Mapped[str] = mapped_column(Text)
    vantage_json: Mapped[str] = mapped_column(Text)
    warnings_json: Mapped[str] = mapped_column(Text)


class DetectionRuleSetting(Base):
    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    enabled: Mapped[bool | None] = mapped_column(default=None)  # None = the rule's default
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime)


class DetectionRuleChange(Base):
    __tablename__ = "detection_rule_changes"
    __table_args__ = (Index("ix_detection_rule_changes_rule_at", "rule_id", "at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16))
    at: Mapped[datetime] = mapped_column(UtcDateTime)
    kind: Mapped[str] = mapped_column(String(16))  # enable | disable | params | reset
    old_json: Mapped[str | None] = mapped_column(Text, default=None)
    new_json: Mapped[str | None] = mapped_column(Text, default=None)


class Suppression(Base):
    __tablename__ = "suppressions"
    __table_args__ = (
        UniqueConstraint(
            "rule_id", "entity_kind", "entity_key", name="uq_suppressions_rule_entity"
        ),
        Index("ix_suppressions_expires", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16))
    entity_kind: Mapped[str] = mapped_column(String(10))
    entity_key: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)


class DeviceAnnotation(Base):
    """What the user says about a device (revision 0005). A statement by the user, not a discovered fact."""

    __tablename__ = "device_annotations"
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(16), default="unspecified")
    trust: Mapped[str] = mapped_column(
        String(10), default="unreviewed"
    )  # unreviewed | known | ignored
    note: Mapped[str | None] = mapped_column(String(300), default=None)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime)


class NetworkProfile(Base):
    """One row per observed network (interface network plus gateway): gateway MAC memory and baseline readiness."""

    __tablename__ = "network_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    network_key: Mapped[str] = mapped_column(String(64), unique=True)
    cidr: Mapped[str] = mapped_column(String(43))
    gateway_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    gateway_mac: Mapped[str | None] = mapped_column(String(17), default=None)
    gateway_mac_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    live_seconds: Mapped[int] = mapped_column(default=0)
    sessions: Mapped[int] = mapped_column(default=0)
    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime)
    baseline_ready_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)


class DeviceBaseline(Base):
    """Learned behaviour of one device on one network: bounded sets and per-minute windows, rewritten once per run end."""

    __tablename__ = "device_baselines"
    __table_args__ = (
        UniqueConstraint("network_id", "device_key", name="uq_device_baselines_net_dev"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("network_profiles.id", ondelete="CASCADE"))
    device_key: Mapped[str] = mapped_column(String(40))
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), default=None
    )
    protocols_json: Mapped[str] = mapped_column(Text, default="[]")
    apps_json: Mapped[str] = mapped_column(Text, default="[]")
    lan_peers_json: Mapped[str] = mapped_column(Text, default="[]")
    listen_ports_json: Mapped[str] = mapped_column(Text, default="[]")
    ext_peers_json: Mapped[str] = mapped_column(Text, default="[]")
    windows_json: Mapped[str] = mapped_column(Text, default="[]")
    windows_count: Mapped[int] = mapped_column(default=0)
    median_out: Mapped[float] = mapped_column(Float, default=0.0)
    mad_out: Mapped[float] = mapped_column(Float, default=0.0)
    median_flows: Mapped[float] = mapped_column(Float, default=0.0)
    mad_flows: Mapped[float] = mapped_column(Float, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime)
