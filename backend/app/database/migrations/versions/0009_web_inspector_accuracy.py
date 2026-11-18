"""Web Inspector response assessment accuracy columns (Phase 5 hardening, revision 0009).

Revision ID: 0009
Revises: 0008

Additive only: add fallback tracking and response assessment classification to web_inspections,
and HTTP method tracking to web_hops.
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # web_inspections additive columns
    op.add_column(
        "web_inspections",
        sa.Column("fallback_performed", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "web_inspections",
        sa.Column("fallback_method", sa.String(8), nullable=True),
    )
    op.add_column(
        "web_inspections",
        sa.Column("fallback_status", sa.SmallInteger, nullable=True),
    )
    op.add_column(
        "web_inspections",
        sa.Column("assessment_response_method", sa.String(8), nullable=True),
    )
    op.add_column(
        "web_inspections",
        sa.Column("assessment_response_status", sa.SmallInteger, nullable=True),
    )
    op.add_column(
        "web_inspections",
        sa.Column(
            "assessment_classification",
            sa.String(32),
            nullable=False,
            server_default="verified",
        ),
    )
    op.add_column(
        "web_inspections",
        sa.Column("inconclusive_reason", sa.String(255), nullable=True),
    )

    # web_hops additive column
    op.add_column(
        "web_hops",
        sa.Column("method", sa.String(8), nullable=False, server_default="HEAD"),
    )


def downgrade() -> None:  # pragma: no cover - forward-only migrations
    # SQLite does not support easy ALTER TABLE DROP COLUMN on older engines,
    # and migrations in this project are forward-only.
    pass

