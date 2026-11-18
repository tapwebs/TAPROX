"""Alerts, evidence, events, detection runs, rule settings and suppressions (Phase 4).

Revision ID: 0004
Revises: 0003

Additive only: new tables, no existing row or column is touched. Forward only, like the revisions before it.
`alerts` and `detection_runs` use AUTOINCREMENT so an id is never reused after a delete (the UI holds alert ids).
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("session_id", sa.Integer, sa.ForeignKey("flow_sessions.id", ondelete="SET NULL")),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("ended_at", sa.DateTime),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("events_processed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("events_dropped", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alerts_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alerts_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_suppressed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("baseline_updated", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("rules_json", sa.Text, nullable=False),
        sa.Column("vantage_json", sa.Text, nullable=False),
        sa.Column("warnings_json", sa.Text, nullable=False),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_detection_runs_started", "detection_runs", ["started_at"])
    op.create_index("ix_detection_runs_session", "detection_runs", ["session_id"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("rule_id", sa.String(16), nullable=False),
        sa.Column("rule_version", sa.SmallInteger, nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("why", sa.Text, nullable=False),
        sa.Column("benign_json", sa.Text, nullable=False),
        sa.Column("blind_spots_json", sa.Text, nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("risk_score", sa.SmallInteger, nullable=False),
        sa.Column("risk_json", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("status_changed_at", sa.DateTime, nullable=False),
        sa.Column("status_note", sa.String(500)),
        sa.Column("entity_kind", sa.String(10), nullable=False),
        sa.Column("entity_key", sa.String(80), nullable=False),
        sa.Column("entity_device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("secondary_key", sa.String(120), nullable=False),
        sa.Column("dedup_key", sa.String(300), nullable=False),
        sa.Column("correlation_group_id", sa.String(36)),
        sa.Column("observed_start", sa.DateTime, nullable=False),
        sa.Column("observed_end", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("run_id", sa.Integer, sa.ForeignKey("detection_runs.id", ondelete="SET NULL")),
        sa.Column("session_id", sa.Integer, sa.ForeignKey("flow_sessions.id", ondelete="SET NULL")),
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("recurrence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("evidence_dropped", sa.Integer, nullable=False, server_default="0"),
        sa.Column("params_json", sa.Text, nullable=False),
        sa.Column("observed_json", sa.Text, nullable=False),
        sqlite_autoincrement=True,
    )
    op.create_index("uq_alerts_dedup_key", "alerts", ["dedup_key"], unique=True)
    op.create_index("ix_alerts_status_updated", "alerts", ["status", "updated_at"])
    op.create_index(
        "ix_alerts_risk_updated",
        "alerts",
        [sa.text("risk_score DESC"), sa.text("updated_at DESC")],
    )
    op.create_index("ix_alerts_rule", "alerts", ["rule_id", "updated_at"])
    op.create_index("ix_alerts_entity", "alerts", ["entity_kind", "entity_key"])
    op.create_index("ix_alerts_device", "alerts", ["entity_device_id", "status"])
    op.create_index("ix_alerts_corr", "alerts", ["correlation_group_id"])
    op.create_index("ix_alerts_created", "alerts", ["created_at"])

    op.create_table(
        "alert_evidence",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "alert_id", sa.Integer, sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("basis", sa.String(10), nullable=False),
        sa.Column("observed_at", sa.Float),
        sa.Column("text", sa.String(300), nullable=False),
        sa.Column("data_json", sa.Text, nullable=False),
        sa.UniqueConstraint("alert_id", "seq", name="uq_alert_evidence_alert_seq"),
    )

    op.create_table(
        "alert_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "alert_id", sa.Integer, sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("at", sa.DateTime, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("from_status", sa.String(16)),
        sa.Column("to_status", sa.String(16)),
        sa.Column("note", sa.String(500)),
        sa.Column("data_json", sa.Text),
    )
    op.create_index("ix_alert_events_alert_at", "alert_events", ["alert_id", "at"])

    op.create_table(
        "detection_rules",
        sa.Column("rule_id", sa.String(16), primary_key=True),
        sa.Column("enabled", sa.Boolean),
        sa.Column("params_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "detection_rule_changes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("rule_id", sa.String(16), nullable=False),
        sa.Column("at", sa.DateTime, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("old_json", sa.Text),
        sa.Column("new_json", sa.Text),
    )
    op.create_index(
        "ix_detection_rule_changes_rule_at", "detection_rule_changes", ["rule_id", "at"]
    )

    op.create_table(
        "suppressions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("rule_id", sa.String(16), nullable=False),
        sa.Column("entity_kind", sa.String(10), nullable=False),
        sa.Column("entity_key", sa.String(80), nullable=False),
        sa.Column("reason", sa.String(300), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("expires_at", sa.DateTime),
        sa.UniqueConstraint("rule_id", "entity_kind", "entity_key", name="uq_suppressions_rule_entity"),
    )
    op.create_index("ix_suppressions_expires", "suppressions", ["expires_at"])


def downgrade() -> None:  # pragma: no cover - this project only migrates forward
    for table in (
        "suppressions",
        "detection_rule_changes",
        "detection_rules",
        "alert_events",
        "alert_evidence",
        "alerts",
        "detection_runs",
    ):
        op.drop_table(table)
