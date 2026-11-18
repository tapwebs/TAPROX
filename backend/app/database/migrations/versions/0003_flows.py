"""Flow sessions and flow records (Phase 3).

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_sessions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("interface_id", sa.String(64)),
        sa.Column("interface_name", sa.String(255)),
        sa.Column("file_name", sa.String(255)),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("ended_at", sa.DateTime),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("packets", sa.Integer, nullable=False, server_default="0"),
        sa.Column("bytes", sa.Integer, nullable=False, server_default="0"),
        sa.Column("totals_json", sa.Text),
        sa.Column("timeline_json", sa.Text),
        sa.Column("timeline_width", sa.Integer, nullable=False, server_default="1"),
        sa.Column("local_addresses_json", sa.Text),
        sa.Column("local_networks_json", sa.Text),
        sa.Column("warnings_json", sa.Text),
    )
    op.create_index("ix_flow_sessions_started_at", "flow_sessions", ["started_at"])
    op.create_table(
        "flows",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "session_id",
            sa.Integer,
            sa.ForeignKey("flow_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("transport", sa.String(24), nullable=False),
        sa.Column("ip_version", sa.SmallInteger, nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer),
        sa.Column("dst_port", sa.Integer),
        sa.Column("initiator_basis", sa.String(12), nullable=False),
        sa.Column("first_seen", sa.Float, nullable=False),
        sa.Column("last_seen", sa.Float, nullable=False),
        sa.Column("first_packet", sa.Integer, nullable=False),
        sa.Column("last_packet", sa.Integer, nullable=False),
        sa.Column("packets_fwd", sa.Integer, nullable=False),
        sa.Column("packets_rev", sa.Integer, nullable=False),
        sa.Column("bytes_fwd", sa.Integer, nullable=False),
        sa.Column("bytes_rev", sa.Integer, nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("tcp_bits", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("mac_src", sa.String(17)),
        sa.Column("mac_dst", sa.String(17)),
        sa.Column("mac_dst_hint", sa.String(17)),
        sa.Column("protocol", sa.String(40), nullable=False),
        sa.Column("application", sa.String(64)),
        sa.Column("category", sa.String(48), nullable=False),
        sa.Column("method", sa.String(24), nullable=False),
        sa.Column("confidence", sa.String(12), nullable=False),
        sa.Column("evidence_json", sa.Text),
        sa.Column("meta_json", sa.Text),
        sa.UniqueConstraint("session_id", "seq", name="uq_flows_session_seq"),
    )
    op.create_index("ix_flows_session_id", "flows", ["session_id"])


def downgrade() -> None:  # pragma: no cover - this project only migrates forward
    op.drop_table("flows")
    op.drop_table("flow_sessions")
