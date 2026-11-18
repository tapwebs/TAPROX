"""Device inventory and discovery scans.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "discovery_scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("interface_id", sa.String(64), nullable=False),
        sa.Column("interface_name", sa.String(255), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("network", sa.String(43)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("phase", sa.String(24)),
        sa.Column("targets_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("targets_done", sa.Integer, nullable=False, server_default="0"),
        sa.Column("devices_found", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("finished_at", sa.DateTime),
        sa.Column("error_code", sa.String(48)),
        sa.Column("error_message", sa.String(500)),
        sa.Column("resolve_names", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("warnings_json", sa.Text),
    )
    op.create_index("ix_discovery_scans_started_at", "discovery_scans", ["started_at"])

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("mac", sa.String(17), nullable=False, unique=True),
        sa.Column("vendor", sa.String(160)),
        sa.Column("mac_randomized", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("hostname", sa.String(255)),
        sa.Column("hostname_source", sa.String(32)),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.Column("last_ip", sa.String(45)),
        sa.Column("last_ip_sort", sa.String(40)),
        sa.Column("last_interface_id", sa.String(64)),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("last_source", sa.String(32), nullable=False),
    )
    op.create_index("ix_devices_first_seen", "devices", ["first_seen"])
    op.create_index("ix_devices_last_seen", "devices", ["last_seen"])
    op.create_index("ix_devices_last_ip_sort", "devices", ["last_ip_sort"])

    op.create_table(
        "device_addresses",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("ip_sort", sa.String(40), nullable=False),
        sa.Column("family", sa.SmallInteger, nullable=False),
        sa.Column("interface_id", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.UniqueConstraint("device_id", "ip", "interface_id", name="uq_device_addresses_device_ip_if"),
    )
    op.create_index("ix_device_addresses_ip", "device_addresses", ["ip"])
    op.create_index("ix_device_addresses_device", "device_addresses", ["device_id"])

    op.create_table(
        "device_observations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observed_at", sa.DateTime, nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("ip", sa.String(45)),
        sa.Column("interface_id", sa.String(64)),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("neighbor_state", sa.String(16)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("discovery_scans.id", ondelete="SET NULL")),
    )
    op.create_index("ix_device_observations_device_time", "device_observations", ["device_id", "observed_at"])
    op.create_index("ix_device_observations_scan", "device_observations", ["scan_id"])
