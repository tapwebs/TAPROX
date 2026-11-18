"""Web Inspector tables (Phase 5, revision 0007).

Revision ID: 0007
Revises: 0006

Additive only: five new tables for authorized web inspection history, hops, certificates,
cookie attributes (no values), and findings.
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_inspections",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_url_sanitized", sa.String(2048), nullable=False),
        sa.Column("scheme", sa.String(5), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("method", sa.String(4), nullable=False),
        sa.Column("allow_private", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("allow_insecure_tls", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("follow_redirects", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("max_redirects", sa.SmallInteger, nullable=False, server_default="5"),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("final_url_sanitized", sa.String(2048)),
        sa.Column("final_ip", sa.String(45)),
        sa.Column("redirect_count", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("http_status", sa.SmallInteger),
        sa.Column("tls_version", sa.String(16)),
        sa.Column("tls_cipher", sa.String(96)),
        sa.Column("cert_verified", sa.Boolean),
        sa.Column("cert_expires_at", sa.DateTime),
        sa.Column("findings_high", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_medium", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_low", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_info", sa.Integer, nullable=False, server_default="0"),
        sa.Column("warnings_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("error_code", sa.String(48)),
        sa.Column("error_message", sa.String(500)),
        sa.Column(
            "source_session_id", sa.Integer, sa.ForeignKey("flow_sessions.id", ondelete="SET NULL")
        ),
        sa.Column("source_device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("source_alert_id", sa.Integer, sa.ForeignKey("alerts.id", ondelete="SET NULL")),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("ended_at", sa.DateTime),
        sa.Column("duration_ms", sa.Integer),
    )
    op.create_index("ix_web_inspections_started", "web_inspections", [sa.text("started_at DESC")])
    op.create_index(
        "ix_web_inspections_host", "web_inspections", ["host", sa.text("started_at DESC")]
    )
    op.create_index(
        "ix_web_inspections_status", "web_inspections", ["status", sa.text("started_at DESC")]
    )

    op.create_table(
        "web_hops",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "inspection_id",
            sa.Integer,
            sa.ForeignKey("web_inspections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hop_index", sa.SmallInteger, nullable=False),
        sa.Column("url_sanitized", sa.String(2048), nullable=False),
        sa.Column("scheme", sa.String(5), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("resolved_ip", sa.String(45)),
        sa.Column("status_code", sa.SmallInteger),
        sa.Column("protocol_version", sa.String(16)),
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column("content_type", sa.String(128)),
        sa.Column("body_bytes_read", sa.Integer, nullable=False, server_default="0"),
        sa.Column("body_sha256", sa.String(64)),
        sa.Column("headers_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("tls_json", sa.Text),
        sa.Column("redirect_location_sanitized", sa.String(2048)),
        sa.Column("blocked_reason", sa.String(64)),
        sa.UniqueConstraint("inspection_id", "hop_index", name="uq_web_hops_inspection_hop"),
    )

    op.create_table(
        "web_certificates",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "inspection_id",
            sa.Integer,
            sa.ForeignKey("web_inspections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hop_index", sa.SmallInteger, nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("serial_hex", sa.String(128), nullable=False),
        sa.Column("sha256_fingerprint", sa.String(64), nullable=False),
        sa.Column("not_before", sa.DateTime, nullable=False),
        sa.Column("not_after", sa.DateTime, nullable=False),
        sa.Column("san_json", sa.Text, nullable=False),
        sa.Column("key_algorithm", sa.String(32), nullable=False),
        sa.Column("key_bits", sa.Integer),
        sa.Column("sig_algorithm", sa.String(64), nullable=False),
        sa.Column("is_self_signed", sa.Boolean, nullable=False),
        sa.Column("is_ca", sa.Boolean, nullable=False),
        sa.Column("hostname_matched", sa.Boolean, nullable=False),
        sa.Column("trust_verified", sa.Boolean, nullable=False),
        sa.Column("trust_error", sa.String(200)),
        sa.UniqueConstraint("inspection_id", "hop_index", name="uq_web_certs_inspection_hop"),
    )

    op.create_table(
        "web_cookies",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "inspection_id",
            sa.Integer,
            sa.ForeignKey("web_inspections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hop_index", sa.SmallInteger, nullable=False),
        sa.Column("seq", sa.SmallInteger, nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("domain", sa.String(255)),
        sa.Column("path", sa.String(512)),
        sa.Column("secure", sa.Boolean, nullable=False),
        sa.Column("http_only", sa.Boolean, nullable=False),
        sa.Column("same_site", sa.String(12), nullable=False),
        sa.Column("max_age_s", sa.Integer),
        sa.Column("expires_at", sa.DateTime),
        sa.Column("has_host_prefix", sa.Boolean, nullable=False),
        sa.Column("has_secure_prefix", sa.Boolean, nullable=False),
        sa.Column("value_length", sa.Integer, nullable=False),
    )
    op.create_index(
        "ix_web_cookies_inspection", "web_cookies", ["inspection_id", "hop_index", "seq"]
    )

    op.create_table(
        "web_findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "inspection_id",
            sa.Integer,
            sa.ForeignKey("web_inspections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("seq", sa.SmallInteger, nullable=False),
        sa.Column("rule_id", sa.String(24), nullable=False),
        sa.Column("category", sa.String(12), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("why", sa.Text, nullable=False),
        sa.Column("remediation", sa.Text, nullable=False),
        sa.Column("benign_json", sa.Text, nullable=False),
        sa.Column("blind_spots_json", sa.Text, nullable=False),
        sa.Column("evidence_json", sa.Text, nullable=False),
    )
    op.create_index("ix_web_findings_inspection", "web_findings", ["inspection_id", "seq"])


def downgrade() -> None:  # pragma: no cover - forward-only migrations
    op.drop_table("web_findings")
    op.drop_table("web_cookies")
    op.drop_table("web_certificates")
    op.drop_table("web_hops")
    op.drop_table("web_inspections")
