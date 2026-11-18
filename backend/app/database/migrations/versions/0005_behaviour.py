"""Device annotations, network profiles and device baselines (Phase 4 / M5).

Revision ID: 0005
Revises: 0004

Additive only: three new tables, no existing row or column is touched. Forward only, like the revisions before it.
The baselines table is created here, empty, so the baseline milestone needs no new revision.
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_annotations",
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role", sa.String(16), nullable=False, server_default="unspecified"),
        sa.Column("trust", sa.String(10), nullable=False, server_default="unreviewed"),
        sa.Column("note", sa.String(300)),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )
    op.create_table(
        "network_profiles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("network_key", sa.String(64), nullable=False, unique=True),
        sa.Column("cidr", sa.String(43), nullable=False),
        sa.Column("gateway_ip", sa.String(45)),
        sa.Column("gateway_mac", sa.String(17)),
        sa.Column("gateway_mac_at", sa.DateTime),
        sa.Column("live_seconds", sa.Integer, nullable=False, server_default="0"),
        sa.Column("sessions", sa.Integer, nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime, nullable=False),
        sa.Column("last_seen_at", sa.DateTime, nullable=False),
        sa.Column("baseline_ready_at", sa.DateTime),
    )
    op.create_table(
        "device_baselines",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("network_id", sa.Integer, sa.ForeignKey("network_profiles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_key", sa.String(40), nullable=False),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("protocols_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("apps_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("lan_peers_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("listen_ports_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("ext_peers_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("windows_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("windows_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("median_out", sa.Float, nullable=False, server_default="0"),
        sa.Column("mad_out", sa.Float, nullable=False, server_default="0"),
        sa.Column("median_flows", sa.Float, nullable=False, server_default="0"),
        sa.Column("mad_flows", sa.Float, nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("network_id", "device_key", name="uq_device_baselines_net_dev"),
    )


def downgrade() -> None:  # pragma: no cover - this project only migrates forward
    for table in ("device_baselines", "network_profiles", "device_annotations"):
        op.drop_table(table)
