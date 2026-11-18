"""Topology history and the session vantage (Phase 4 / M7).

Revision ID: 0006
Revises: 0005

Additive only: two new tables and five nullable columns on flow_sessions. No existing row is rewritten; sessions saved
before this revision keep NULL and are shown as "vantage not recorded".
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "topology_edges",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("edge_key", sa.String(200), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("a_key", sa.String(64), nullable=False),
        sa.Column("b_key", sa.String(64), nullable=False),
        sa.Column("a_label", sa.String(80), nullable=False),
        sa.Column("b_label", sa.String(80), nullable=False),
        sa.Column("basis", sa.String(10), nullable=False),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("first_seen_at", sa.DateTime, nullable=False),
        sa.Column("last_seen_at", sa.DateTime, nullable=False),
        sa.Column("flows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("bytes", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("protocols_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("applications_json", sa.Text, nullable=False, server_default="[]"),
    )
    op.create_index("ix_topology_edges_last_seen", "topology_edges", ["last_seen_at"])
    op.create_index("ix_topology_edges_a", "topology_edges", ["a_key"])
    op.create_index("ix_topology_edges_b", "topology_edges", ["b_key"])
    op.create_table(
        "topology_edge_days",
        sa.Column("edge_id", sa.Integer, sa.ForeignKey("topology_edges.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("day", sa.String(10), primary_key=True),
        sa.Column("flows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("bytes", sa.BigInteger, nullable=False, server_default="0"),
    )
    op.add_column("flow_sessions", sa.Column("gateways_json", sa.Text))
    op.add_column("flow_sessions", sa.Column("dns_servers_json", sa.Text))
    op.add_column("flow_sessions", sa.Column("interface_mac", sa.String(17)))
    op.add_column("flow_sessions", sa.Column("promiscuous", sa.Boolean))
    op.add_column("flow_sessions", sa.Column("network_key", sa.String(64)))


def downgrade() -> None:  # pragma: no cover - this project only migrates forward
    op.drop_table("topology_edge_days")
    op.drop_table("topology_edges")
