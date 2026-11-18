"""Investigations & Forensics tables and append-only triggers (Phase 6, revision 0008).

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


_TRIGGER_STATEMENTS = (
    """
    CREATE TRIGGER tr_custody_no_update
    BEFORE UPDATE ON investigation_custody_events
    BEGIN
        SELECT RAISE(ABORT, 'custody ledger is append-only');
    END;
    """,
    """
    CREATE TRIGGER tr_custody_no_delete
    BEFORE DELETE ON investigation_custody_events
    BEGIN
        SELECT RAISE(ABORT, 'custody ledger is append-only');
    END;
    """,
    """
    CREATE TRIGGER tr_audit_no_update
    BEFORE UPDATE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit log is append-only');
    END;
    """,
    """
    CREATE TRIGGER tr_audit_no_delete
    BEFORE DELETE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit log is append-only');
    END;
    """,
    """
    CREATE TRIGGER tr_notes_no_update
    BEFORE UPDATE ON investigation_notes
    BEGIN
        SELECT RAISE(ABORT, 'forensic notes are append-only revisions');
    END;
    """,
    """
    CREATE TRIGGER tr_notes_no_delete
    BEFORE DELETE ON investigation_notes
    BEGIN
        SELECT RAISE(ABORT, 'forensic notes cannot be deleted');
    END;
    """,
    """
    CREATE TRIGGER tr_evidence_no_delete
    BEFORE DELETE ON investigation_evidence
    BEGIN
        SELECT RAISE(ABORT, 'original case evidence cannot be deleted');
    END;
    """,
    """
    CREATE TRIGGER tr_evidence_no_mutate
    BEFORE UPDATE ON investigation_evidence
    WHEN
        NEW.id != OLD.id OR
        NEW.investigation_id != OLD.investigation_id OR
        NEW.evidence_ref != OLD.evidence_ref OR
        NEW.artifact_kind != OLD.artifact_kind OR
        NEW.title != OLD.title OR
        NEW.epistemic_basis != OLD.epistemic_basis OR
        NEW.storage_mode != OLD.storage_mode OR
        NEW.canonical_version != OLD.canonical_version OR
        NEW.hash_algorithm != OLD.hash_algorithm OR
        NEW.content_sha256 != OLD.content_sha256 OR
        NEW.snapshot_json != OLD.snapshot_json OR
        NEW.vault_relpath IS NOT OLD.vault_relpath OR
        NEW.external_path_recorded IS NOT OLD.external_path_recorded OR
        NEW.file_size_bytes IS NOT OLD.file_size_bytes OR
        NEW.provenance_json != OLD.provenance_json OR
        NEW.source_table IS NOT OLD.source_table OR
        NEW.source_record_id IS NOT OLD.source_record_id OR
        NEW.observed_start IS NOT OLD.observed_start OR
        NEW.observed_end IS NOT OLD.observed_end OR
        NEW.acquired_by != OLD.acquired_by OR
        NEW.acquired_at != OLD.acquired_at
    BEGIN
        SELECT RAISE(ABORT, 'evidence snapshot and provenance are immutable');
    END;
    """,
)


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_uid", sa.String(36), nullable=False, unique=True),
        sa.Column("case_ref", sa.String(32), nullable=False, unique=True),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("summary", sa.String(2000), nullable=False),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("lead_actor", sa.String(64), nullable=False, server_default="local-operator"),
        sa.Column("scope_authorized", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("scope_note", sa.String(500), nullable=False),
        sa.Column("tags_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("evidence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("custody_head_seq", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "custody_head_sha256",
            sa.String(64),
            nullable=False,
            server_default="0" * 64,
        ),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("sealed_at", sa.DateTime),
        sa.Column("closed_at", sa.DateTime),
        sa.Column("closure_reason", sa.String(500)),
    )
    op.create_index(
        "ix_investigations_status_updated",
        "investigations",
        ["status", sa.text("updated_at DESC")],
    )
    op.create_index("ix_investigations_created", "investigations", [sa.text("created_at DESC")])

    op.create_table(
        "investigation_evidence",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "investigation_id",
            sa.Integer,
            sa.ForeignKey("investigations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("evidence_ref", sa.String(24), nullable=False),
        sa.Column("artifact_kind", sa.String(24), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("epistemic_basis", sa.String(24), nullable=False),
        sa.Column("storage_mode", sa.String(20), nullable=False),
        sa.Column("canonical_version", sa.SmallInteger, nullable=False, server_default="1"),
        sa.Column("hash_algorithm", sa.String(12), nullable=False, server_default="sha256"),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_json", sa.Text, nullable=False),
        sa.Column("vault_relpath", sa.String(260)),
        sa.Column("external_path_recorded", sa.String(512)),
        sa.Column("file_size_bytes", sa.BigInteger),
        sa.Column("provenance_json", sa.Text, nullable=False),
        sa.Column("source_table", sa.String(32)),
        sa.Column("source_record_id", sa.String(64)),
        sa.Column("observed_start", sa.DateTime),
        sa.Column("observed_end", sa.DateTime),
        sa.Column("integrity_status", sa.String(24), nullable=False, server_default="verified"),
        sa.Column("last_verified_at", sa.DateTime),
        sa.Column("acquired_by", sa.String(64), nullable=False),
        sa.Column("acquired_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("investigation_id", "evidence_ref", name="uq_evidence_case_ref"),
    )
    op.create_index(
        "ix_evidence_case_acquired",
        "investigation_evidence",
        ["investigation_id", sa.text("acquired_at DESC")],
    )
    op.create_index(
        "ix_evidence_case_kind", "investigation_evidence", ["investigation_id", "artifact_kind"]
    )
    op.create_index(
        "ix_evidence_sha256", "investigation_evidence", ["investigation_id", "content_sha256"]
    )

    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "investigation_id",
            sa.Integer,
            sa.ForeignKey("investigations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("note_ref", sa.String(24), nullable=False),
        sa.Column(
            "supersedes_note_id",
            sa.Integer,
            sa.ForeignKey("investigation_notes.id", ondelete="RESTRICT"),
        ),
        sa.Column("note_kind", sa.String(24), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("cited_evidence_ids_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("investigation_id", "note_ref", name="uq_notes_case_ref"),
    )
    op.create_index(
        "ix_notes_case_created", "investigation_notes", ["investigation_id", "created_at"]
    )

    op.create_table(
        "investigation_correlations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "investigation_id",
            sa.Integer,
            sa.ForeignKey("investigations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("run_seq", sa.Integer, nullable=False),
        sa.Column("rule_id", sa.String(24), nullable=False),
        sa.Column("indicator_kind", sa.String(24), nullable=False),
        sa.Column("indicator_value", sa.String(255), nullable=False),
        sa.Column("epistemic_basis", sa.String(16), nullable=False, server_default="inferred"),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("limitations_json", sa.Text, nullable=False),
        sa.Column("evidence_ids_json", sa.Text, nullable=False),
        sa.Column("window_start", sa.DateTime),
        sa.Column("window_end", sa.DateTime),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index(
        "ix_corr_case_run",
        "investigation_correlations",
        ["investigation_id", sa.text("run_seq DESC"), "id"],
    )

    op.create_table(
        "investigation_custody_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "investigation_id",
            sa.Integer,
            sa.ForeignKey("investigations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("occurred_at", sa.DateTime, nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("client_surface", sa.String(24), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column(
            "evidence_id",
            sa.Integer,
            sa.ForeignKey("investigation_evidence.id", ondelete="RESTRICT"),
        ),
        sa.Column(
            "note_id",
            sa.Integer,
            sa.ForeignKey("investigation_notes.id", ondelete="RESTRICT"),
        ),
        sa.Column("artifact_sha256", sa.String(64)),
        sa.Column("details_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("prev_event_sha256", sa.String(64), nullable=False),
        sa.Column("event_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("investigation_id", "seq", name="uq_custody_case_seq"),
    )
    op.create_index(
        "ix_custody_case_time",
        "investigation_custody_events",
        ["investigation_id", "occurred_at"],
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("seq", sa.Integer, nullable=False, unique=True),
        sa.Column("occurred_at", sa.DateTime, nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("client_surface", sa.String(24), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("investigation_id", sa.Integer),
        sa.Column("resource_ref", sa.String(64)),
        sa.Column("details_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("prev_audit_sha256", sa.String(64), nullable=False),
        sa.Column("audit_sha256", sa.String(64), nullable=False),
    )
    op.create_index("ix_audit_time_cat", "audit_events", [sa.text("occurred_at DESC"), "category"])

    op.create_table(
        "report_exports",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "investigation_id",
            sa.Integer,
            sa.ForeignKey("investigations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("export_ref", sa.String(24), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("include_vault_files", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("bundle_sha256", sa.String(64), nullable=False),
        sa.Column("byte_size", sa.BigInteger, nullable=False),
        sa.Column("custody_head_seq", sa.Integer, nullable=False),
        sa.Column("custody_head_sha256", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("investigation_id", "export_ref", name="uq_exports_case_ref"),
    )
    op.create_index(
        "ix_exports_case_created",
        "report_exports",
        ["investigation_id", sa.text("created_at DESC")],
    )

    for stmt in _TRIGGER_STATEMENTS:
        op.execute(sa.text(stmt))
