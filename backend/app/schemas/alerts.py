"""Stored alerts and detection runs (Phase 4).

Alert text comes from fixed templates; user notes are plain text.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

AlertStatus = Literal[
    "open", "acknowledged", "investigating", "resolved", "false_positive", "suppressed"
]
AlertSeverity = Literal["info", "low", "medium", "high", "critical"]
AlertConfidence = Literal["low", "medium", "high"]
AlertCategory = Literal["recon", "traffic", "dns", "device", "app"]
AlertSort = Literal["updated", "risk", "severity"]
SortOrder = Literal["asc", "desc"]


class AlertListItem(BaseModel):
    id: int
    rule_id: str = Field(description="For example TT-REC-001.")
    rule_version: int
    category: str
    title: str
    summary: str
    severity: AlertSeverity
    confidence: AlertConfidence
    risk_score: int = Field(ge=0, le=100, description="Orders alerts. It is not a probability.")
    status: AlertStatus
    status_changed_at: datetime
    entity_kind: str
    entity_key: str
    secondary_key: str
    entity_device_id: int | None
    observed_start: datetime = Field(
        description="Packet time as UTC. Old for a replayed capture file."
    )
    observed_end: datetime
    created_at: datetime = Field(description="Wall clock when the alert was first stored.")
    updated_at: datetime
    source: Literal["live", "file"]
    run_id: int | None = Field(description="The stored detection run; null once that run is gone.")
    session_id: int | None = Field(
        description="The flow session analysed; null once Phase 3 pruned it."
    )
    occurrence_count: int
    recurrence_count: int
    correlation_group_id: str | None


class RiskFactorOut(BaseModel):
    name: str
    pct: int = Field(description="Hundredths added to the context multiplier (+10 is +0.10).")
    reason: str


class RiskBreakdown(BaseModel):
    value: int
    severity_pct: int
    confidence_pct: int
    multiplier_pct: int
    factors: list[RiskFactorOut]
    explanation: str


class EvidenceOut(BaseModel):
    seq: int
    kind: str
    basis: Literal["observed", "inferred", "inventory"]
    observed_at: float | None = Field(description="Packet time in seconds since 1970.")
    text: str
    data: dict[str, Any]


class AlertDetail(AlertListItem):
    why: str
    benign_explanations: list[str]
    blind_spots: list[str]
    risk: RiskBreakdown
    params: dict[str, Any] = Field(description="The rule settings in force when it fired.")
    observed: dict[str, Any] = Field(description="The key measured numbers.")
    evidence: list[EvidenceOut]
    evidence_dropped: int = Field(description="Evidence items beyond the cap: counted, not kept.")
    status_note: str | None
    related: list[AlertListItem] = Field(description="Other alerts in the same correlation group.")


class AlertPage(BaseModel):
    items: list[AlertListItem]
    total: int
    limit: int
    offset: int


class AlertEventOut(BaseModel):
    id: int
    at: datetime
    kind: str
    from_status: str | None
    to_status: str | None
    note: str | None
    data: dict[str, Any] | None


class AlertEventPage(BaseModel):
    items: list[AlertEventOut]
    total: int
    limit: int
    offset: int


class AlertPatch(BaseModel):
    """Change the status, add a note, or both. Nothing else about an alert can be edited."""

    model_config = ConfigDict(extra="forbid")

    status: AlertStatus | None = None
    note: str | None = Field(default=None, max_length=500)

    @field_validator("note")
    @classmethod
    def _plain_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if any(ord(c) < 32 and c not in "\n\t" for c in value):
            raise ValueError("The note may not contain control characters.")
        return value or None


class RuleCount(BaseModel):
    rule_id: str
    count: int


class HourBucket(BaseModel):
    start: datetime
    count: int


class AlertSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_category: dict[str, int]
    top_rules: list[RuleCount]
    created_last_24h: list[HourBucket] = Field(description="24 hourly buckets, oldest first.")
    timeline_step: Literal["hour", "day", "week"] = Field(
        description="Bucket width: hour, day or week."
    )
    timeline: list[HourBucket] = Field(
        description="Alerts created per bucket for the range, oldest first; empty without alerts."
    )


class StoredRun(BaseModel):
    id: int
    session_id: int | None
    source: Literal["live", "file"]
    started_at: datetime
    ended_at: datetime | None
    status: Literal["running", "completed", "failed", "aborted"]
    events_processed: int
    events_dropped: int
    alerts_created: int
    alerts_updated: int
    findings_suppressed: int
    baseline_updated: bool
    warnings: list[str]
    rules: list[dict[str, Any]]
    vantage: dict[str, Any]


class StoredRunPage(BaseModel):
    items: list[StoredRun]
    total: int
    limit: int
    offset: int


class DeleteHistoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool = Field(
        description="Must be the JSON value true, not a string or a number. Cannot be undone."
    )


class DeleteHistoryResult(BaseModel):
    alerts_deleted: int
    runs_deleted: int
