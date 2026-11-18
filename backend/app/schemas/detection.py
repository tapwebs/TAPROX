"""GET /api/v1/detection/status: counters and diagnostics, with no alert content.

Stored alerts are in schemas/alerts.py.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class DetectionParam(BaseModel):
    name: str
    value: float
    default: float
    minimum: float
    maximum: float
    unit: str


class DetectionRule(BaseModel):
    id: str = Field(description="Stable rule id, for example TT-REC-001.")
    name: str
    category: str
    version: int
    severity: str = Field(description="The rule's base severity.")
    enabled: bool
    default_enabled: bool
    requires_baseline: bool
    state: Literal["evaluating", "disabled", "not_evaluated"]
    reason: str = Field(
        description="Why a rule is disabled or not evaluated; empty while it is evaluating."
    )
    params: list[DetectionParam]


class DetectionQueue(BaseModel):
    maxsize: int
    depth: int
    high_water: int
    offered: int
    accepted: int
    dropped: int = Field(description="Telemetry events the queue refused because it was full.")
    dropped_after_close: int
    closed: bool


class DetectionPersistence(BaseModel):
    """Whether alerts reach the database. What did not is counted here, never reported as stored."""

    enabled: bool = Field(
        description="False when this service has no database (alerts then stay in memory)."
    )
    healthy: bool | None = Field(
        default=None,
        description="False while the last write failed; the alerts wait and are retried.",
    )
    running: bool | None = None
    pending_alerts: int | None = Field(default=None, description="Waiting to be written.")
    max_pending: int | None = None
    alerts_inserted: int | None = Field(
        default=None, description="New alerts committed since start."
    )
    alerts_updated: int | None = Field(
        default=None, description="Existing alerts updated since start."
    )
    flushes: int | None = None
    failed_flushes: int | None = None
    consecutive_failures: int | None = None
    dropped_alerts: int | None = Field(
        default=None, description="Refused because the waiting set was full."
    )
    rejected_alerts: int | None = Field(default=None, description="Refused by the database itself.")
    lost_at_shutdown: int | None = Field(
        default=None, description="Still waiting when the application closed."
    )
    alerts_not_stored: int | None = Field(
        default=None, description="dropped + rejected + lost at shutdown."
    )
    last_error: str | None = None
    last_error_at: datetime | None = None
    last_flush_at: datetime | None = None
    longest_write_ms: float | None = None
    pruned_alerts: int | None = Field(
        default=None, description="Removed by the retention limits since start."
    )
    pruned_open_alerts: int | None = Field(
        default=None, description="Of those, open or investigating ones."
    )
    pruned_runs: int | None = None
    prune_failures: int | None = None
    retention_days: int | None = None
    retention_rows: int | None = None
    retention_problems: list[str] | None = None


class DetectionRun(BaseModel):
    run_id: int
    stored_run_id: int | None = Field(
        description="The run's id in the database (alerts use it too); null without storage."
    )
    warnings: list[str] = Field(
        description="What a reader should know about the quality of this run's analysis."
    )
    session_id: int = Field(
        description="The flow session analysed; 0 when flows are not being stored."
    )
    source: Literal["live", "file"]
    status: Literal["running", "completed", "failed"]
    error: str | None = Field(
        description="The kind of error that stopped the worker, if it failed."
    )
    started_at: datetime
    ended_at: datetime | None
    queue: DetectionQueue
    events_processed: int
    events_by_kind: dict[str, int]
    malformed_events: dict[str, int] = Field(
        description="Events discarded as malformed, by reason."
    )
    findings: int
    alerts_created: int
    alerts_updated: int
    alerts_unchanged: int
    alerts_evicted: int
    alerts_in_memory: int
    alerts_by_severity: dict[str, int]
    self_activity_excluded: int
    rule_errors: dict[str, int]
    rule_states: dict[str, str] = Field(
        description="Per rule: evaluating, disabled or not_evaluated."
    )
    finished: bool


class DetectionStatus(BaseModel):
    enabled: bool
    queue_size: int
    runs_kept: int
    max_alerts_per_run: int
    alerts_are_kept_in_memory_only: bool = Field(
        description="True only when this service has no database: alerts are lost at exit."
    )
    persistence: DetectionPersistence
    rules: list[DetectionRule]
    runs: list[DetectionRun] = Field(description="Newest first.")
