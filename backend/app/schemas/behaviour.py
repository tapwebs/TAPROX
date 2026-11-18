"""Schemas for rule configuration, suppressions, device annotations, baselines and device risk (Phase 4 M5, M6, M9)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.detection import DetectionParam

Role = Literal["gateway", "dns_server", "server", "printer", "iot", "workstation", "unspecified"]
Trust = Literal["unreviewed", "known", "ignored"]
EntityKind = Literal["ip", "mac", "device", "domain", "network"]


class RuleChange(BaseModel):
    at: datetime
    kind: str
    old: dict[str, object]
    new: dict[str, object]


class RuleConfig(BaseModel):
    id: str
    name: str
    category: str
    version: int
    severity: str
    description: str
    benign_explanations: list[str]
    blind_spots: list[str]
    default_enabled: bool
    enabled: bool
    requires_baseline: bool
    requires_direction: bool
    state: Literal["evaluating", "disabled", "not_evaluated"]
    reason: str
    customised: bool = Field(
        description="True when the user changed the switch or a value from its default."
    )
    params: list[DetectionParam]
    changes: list[RuleChange] = Field(
        default_factory=list, description="Recent changes, newest first (detail only)."
    )


class RuleConfigList(BaseModel):
    items: list[RuleConfig]


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    params: dict[str, float] | None = Field(
        default=None, description="Values by name; each is checked against its bounds."
    )


class SuppressionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(max_length=16)
    entity_kind: EntityKind
    entity_key: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=1, max_length=300)
    expires_at: datetime | None = None


class Suppression(BaseModel):
    id: int
    rule_id: str
    entity_kind: str
    entity_key: str
    reason: str
    created_at: datetime
    expires_at: datetime | None


class SuppressionList(BaseModel):
    items: list[Suppression]


class AnnotationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role = "unspecified"
    trust: Trust = "unreviewed"
    note: str | None = Field(default=None, max_length=300)


class Annotation(BaseModel):
    device_id: int
    role: Role
    trust: Trust
    note: str | None
    updated_at: datetime


class Network(BaseModel):
    id: int
    network_key: str
    cidr: str
    gateway_ip: str | None
    gateway_mac: str | None
    live_seconds: int
    sessions: int
    first_seen_at: datetime
    last_seen_at: datetime
    baseline_ready: bool
    baseline_ready_at: datetime | None
    baseline_devices: int
    hours_needed: float
    sessions_needed: int


class NetworkList(BaseModel):
    items: list[Network]


class BaselineReset(BaseModel):
    network_id: int
    devices_removed: int


class DetectionSettings(BaseModel):
    retention_alert_days: int = Field(ge=7, le=3650)
    retention_alert_max: int = Field(ge=100, le=100_000)
    baseline_hours_min: float = Field(ge=0, le=720)
    baseline_sessions_min: int = Field(ge=1, le=100)
    risk_half_life_days: int = Field(ge=1, le=90)


class DetectionSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retention_alert_days: int | None = Field(default=None, ge=7, le=3650)
    retention_alert_max: int | None = Field(default=None, ge=100, le=100_000)
    baseline_hours_min: float | None = Field(default=None, ge=0, le=720)
    baseline_sessions_min: int | None = Field(default=None, ge=1, le=100)
    risk_half_life_days: int | None = Field(default=None, ge=1, le=90)


class RiskContribution(BaseModel):
    alert_id: int
    rule_id: str
    title: str
    status: str
    risk: int
    decay: float


class DeviceRisk(BaseModel):
    device_id: int
    ip: str | None
    mac: str
    hostname: str | None
    role: Role
    trust: Trust
    score: int = Field(ge=0, le=100)
    half_life_days: float
    alerts_counted: int
    contributing: list[RiskContribution]


class DeviceRiskList(BaseModel):
    items: list[DeviceRisk]
