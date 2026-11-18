"""Create app_meta and record when this installation's database was initialised.

Revision ID: 0001
Revises:
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_meta = op.create_table(
        "app_meta",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", sa.String(length=512), nullable=False),
    )
    op.bulk_insert(app_meta, [{"key": "initialized_at", "value": datetime.now(UTC).isoformat()}])
