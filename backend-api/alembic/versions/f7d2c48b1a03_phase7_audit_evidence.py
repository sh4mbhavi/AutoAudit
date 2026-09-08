"""Phase 7: audit-grade evidence, manual approval history and mapping pinning.

Adds the evidence artifact/audit tables, the manual-evidence approval lifecycle
with append-only revisions, and the scan-level SOC 2 mapping pin. Also extends
the Phase 3 scan-input freeze to cover the Phase 6 connection snapshot and the
new Phase 7 mapping columns, which the original ROW(...) comparison did not
include and therefore did not protect.

Forward-only, consistent with Phase 3/5/6.

Revision ID: f7d2c48b1a03
Revises: e6a13c95d842
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "f7d2c48b1a03"
down_revision = "e6a13c95d842"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Scan-level mapping pin (plan item 15.1.3).
    # ------------------------------------------------------------------
    op.add_column("scan", sa.Column("mapping_id", sa.String(80), nullable=True))
    op.add_column("scan", sa.Column("mapping_version", sa.String(30), nullable=True))
    op.add_column("scan", sa.Column("mapping_digest", sa.String(64), nullable=True))
    op.add_column("scan", sa.Column("mapping_snapshot", JSONB(), nullable=True))
    op.add_column(
        "scan", sa.Column("policy_corpus_digest", sa.String(64), nullable=True)
    )
    op.add_column("scan", sa.Column("evidence_version", sa.String(30), nullable=True))

    # ------------------------------------------------------------------
    # Evidence artifacts.
    # ------------------------------------------------------------------
    op.create_table(
        "evidence_artifact",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("object_id", sa.String(43), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.Column("scan_result_id", sa.Integer(), nullable=True),
        sa.Column("control_id", sa.String(50), nullable=True),
        sa.Column("display_filename", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("declared_media_type", sa.String(100), nullable=True),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("storage_backend", sa.String(30), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("failure_code", sa.String(60), nullable=True),
        sa.Column("retention_policy_version", sa.String(30), nullable=False),
        sa.Column("retention_expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "legal_hold", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("provenance", JSONB(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["scan_result_id"], ["scan_result.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "kind IN ('upload','report')", name="ck_evidence_artifact_kind"
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','available','failed','deleted')",
            name="ck_evidence_artifact_status",
        ),
        sa.CheckConstraint("byte_size >= 0", name="ck_evidence_artifact_byte_size"),
        # Content is only readable while the row says it is available.
        sa.CheckConstraint(
            "(status = 'deleted') = (deleted_at IS NOT NULL)",
            name="ck_evidence_artifact_deleted_at",
        ),
    )
    # Unique index rather than a separate UNIQUE constraint plus a plain index:
    # the model declares object_id unique and indexed, which renders as exactly
    # one unique index, and two objects enforcing the same thing is redundant.
    op.create_index(
        "ix_evidence_artifact_object_id",
        "evidence_artifact",
        ["object_id"],
        unique=True,
    )
    op.create_index("ix_evidence_artifact_user_id", "evidence_artifact", ["user_id"])
    op.create_index("ix_evidence_artifact_scan_id", "evidence_artifact", ["scan_id"])
    op.create_index(
        "ix_evidence_artifact_scan_result_id", "evidence_artifact", ["scan_result_id"]
    )
    op.create_index(
        "ix_evidence_artifact_user_kind", "evidence_artifact", ["user_id", "kind"]
    )
    op.create_index(
        "ix_evidence_artifact_retention_expires_at",
        "evidence_artifact",
        ["retention_expires_at"],
    )

    # ------------------------------------------------------------------
    # Append-only evidence audit trail.
    # ------------------------------------------------------------------
    op.create_table(
        "evidence_audit_event",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("artifact_object_id", sa.String(43), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("detail", JSONB(), nullable=True),
        sa.Column(
            "occurred_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"], ["evidence_artifact.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "outcome IN ('allowed','denied','error')",
            name="ck_evidence_audit_event_outcome",
        ),
    )
    op.create_index(
        "ix_evidence_audit_event_object_id",
        "evidence_audit_event",
        ["artifact_object_id"],
    )
    op.create_index(
        "ix_evidence_audit_event_occurred_at", "evidence_audit_event", ["occurred_at"]
    )

    # ------------------------------------------------------------------
    # Manual / inherited evidence with an approval lifecycle.
    # ------------------------------------------------------------------
    op.create_table(
        "manual_evidence_record",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_result_id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("control_id", sa.String(50), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("control_owner", sa.String(200), nullable=True),
        sa.Column("evidence_owner", sa.String(200), nullable=True),
        sa.Column("evidence_source", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("reviewer_user_id", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("collection_period_start", sa.DateTime(), nullable=True),
        sa.Column("collection_period_end", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("cadence", sa.String(30), nullable=True),
        sa.Column("retention_policy_version", sa.String(30), nullable=False),
        sa.Column(
            "current_revision_number",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"], ["scan_result.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewer_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_result_id", name="uq_manual_evidence_record_scan_result"
        ),
        sa.CheckConstraint(
            "status IN ('draft','submitted','approved','rejected','withdrawn','expired')",
            name="ck_manual_evidence_record_status",
        ),
        sa.CheckConstraint(
            "evidence_source IN ('manual','inherited')",
            name="ck_manual_evidence_record_source",
        ),
        sa.CheckConstraint(
            "collection_period_start IS NULL"
            " OR collection_period_end IS NULL"
            " OR collection_period_start <= collection_period_end",
            name="ck_manual_evidence_record_period",
        ),
        # An independent reviewer is structural, not conventional.
        sa.CheckConstraint(
            "reviewer_user_id IS NULL OR reviewer_user_id <> user_id",
            name="ck_manual_evidence_record_independent_reviewer",
        ),
        sa.CheckConstraint(
            "status NOT IN ('approved','rejected') OR reviewer_user_id IS NOT NULL",
            name="ck_manual_evidence_record_reviewed_by",
        ),
    )
    op.create_index(
        "ix_manual_evidence_record_user_id", "manual_evidence_record", ["user_id"]
    )
    op.create_index(
        "ix_manual_evidence_record_scan_id", "manual_evidence_record", ["scan_id"]
    )
    op.create_index(
        "ix_manual_evidence_record_expires_at", "manual_evidence_record", ["expires_at"]
    )

    op.create_table(
        "manual_evidence_revision",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("record_id", sa.Integer(), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("status_after", sa.String(30), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_role", sa.String(30), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("attachment_object_ids", JSONB(), nullable=True),
        sa.Column("external_references", JSONB(), nullable=True),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("provenance", JSONB(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["record_id"], ["manual_evidence_record.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "record_id", "revision_number", name="uq_manual_evidence_revision_number"
        ),
        sa.CheckConstraint(
            "action IN ('created','amended','submitted','approved','rejected',"
            "'withdrawn','expired')",
            name="ck_manual_evidence_revision_action",
        ),
        sa.CheckConstraint(
            "status_after IN ('draft','submitted','approved','rejected','withdrawn',"
            "'expired')",
            name="ck_manual_evidence_revision_status",
        ),
        sa.CheckConstraint(
            "(action = 'rejected') = (rejection_reason IS NOT NULL)",
            name="ck_manual_evidence_revision_rejection_reason",
        ),
        sa.CheckConstraint(
            "revision_number >= 1", name="ck_manual_evidence_revision_number_positive"
        ),
    )
    op.create_index(
        "ix_manual_evidence_revision_record_id",
        "manual_evidence_revision",
        ["record_id"],
    )

    # ------------------------------------------------------------------
    # Append-only enforcement for both history tables.
    # ------------------------------------------------------------------
    op.execute("""
        CREATE FUNCTION reject_phase7_history_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Phase 7 % history is append-only', TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER phase7_evidence_audit_append_only
        BEFORE UPDATE OR DELETE ON evidence_audit_event
        FOR EACH ROW EXECUTE FUNCTION reject_phase7_history_mutation();
    """)
    op.execute("""
        CREATE TRIGGER phase7_manual_revision_append_only
        BEFORE UPDATE OR DELETE ON manual_evidence_revision
        FOR EACH ROW EXECUTE FUNCTION reject_phase7_history_mutation();
    """)

    # ------------------------------------------------------------------
    # An approved artifact's identity and content digest are frozen. Retention
    # and lifecycle fields stay mutable so deletion under policy remains possible.
    # ------------------------------------------------------------------
    op.execute("""
        CREATE FUNCTION protect_phase7_artifact_identity() RETURNS trigger AS $$
        BEGIN
            IF ROW(NEW.id, NEW.object_id, NEW.user_id, NEW.kind, NEW.scan_id,
                   NEW.scan_result_id, NEW.control_id, NEW.content_sha256,
                   NEW.byte_size, NEW.storage_backend, NEW.storage_key,
                   NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.object_id, OLD.user_id, OLD.kind, OLD.scan_id,
                   OLD.scan_result_id, OLD.control_id, OLD.content_sha256,
                   OLD.byte_size, OLD.storage_backend, OLD.storage_key,
                   OLD.created_at)
            THEN
                RAISE EXCEPTION 'Phase 7 evidence artifact identity is immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER phase7_artifact_identity_immutable
        BEFORE UPDATE ON evidence_artifact
        FOR EACH ROW EXECUTE FUNCTION protect_phase7_artifact_identity();
    """)

    # ------------------------------------------------------------------
    # A record's control binding and submitter never change, and an approved or
    # rejected decision cannot be silently reopened by an in-place UPDATE.
    # ------------------------------------------------------------------
    op.execute("""
        CREATE FUNCTION protect_phase7_manual_record() RETURNS trigger AS $$
        BEGIN
            IF ROW(NEW.id, NEW.scan_result_id, NEW.scan_id, NEW.control_id,
                   NEW.user_id, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.scan_result_id, OLD.scan_id, OLD.control_id,
                   OLD.user_id, OLD.created_at)
            THEN
                RAISE EXCEPTION 'Phase 7 manual evidence identity is immutable'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.current_revision_number < OLD.current_revision_number THEN
                RAISE EXCEPTION 'Phase 7 manual evidence history cannot rewind'
                    USING ERRCODE = '23514';
            END IF;
            IF OLD.status IN ('approved', 'rejected')
               AND NEW.status IS DISTINCT FROM OLD.status
               AND NEW.current_revision_number = OLD.current_revision_number
            THEN
                RAISE EXCEPTION 'Phase 7 manual evidence decisions change only through a revision'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER phase7_manual_record_protected
        BEFORE UPDATE ON manual_evidence_record
        FOR EACH ROW EXECUTE FUNCTION protect_phase7_manual_record();
    """)

    # ------------------------------------------------------------------
    # Extend the Phase 3 scan-input freeze.
    #
    # The original ROW(...) list was written before connection_snapshot (Phase 6)
    # and the Phase 7 mapping pin existed, so those columns were mutable after
    # creation even though they are frozen evidence inputs. Replacing the function
    # body in place keeps the existing trigger and its Phase 3 error message.
    # ------------------------------------------------------------------
    op.execute("""
        CREATE OR REPLACE FUNCTION protect_phase3_scan_inputs() RETURNS trigger AS $$
        BEGIN
            IF OLD.semantics_version IS NOT NULL
               AND ROW(NEW.id, NEW.user_id, NEW.m365_connection_id,
                       NEW.azure_connection_id, NEW.gcp_connection_id, NEW.aws_connection_id,
                       NEW.framework, NEW.benchmark, NEW.version,
                       NEW.selected_count, NEW.total_controls, NEW.metadata_snapshot,
                       NEW.metadata_digest, NEW.correlation_id, NEW.semantics_version,
                       NEW.connection_snapshot, NEW.mapping_id, NEW.mapping_version,
                       NEW.mapping_digest, NEW.mapping_snapshot,
                       NEW.policy_corpus_digest, NEW.evidence_version)
                   IS DISTINCT FROM
                   ROW(OLD.id, OLD.user_id, OLD.m365_connection_id,
                       OLD.azure_connection_id, OLD.gcp_connection_id, OLD.aws_connection_id,
                       OLD.framework, OLD.benchmark, OLD.version,
                       OLD.selected_count, OLD.total_controls, OLD.metadata_snapshot,
                       OLD.metadata_digest, OLD.correlation_id, OLD.semantics_version,
                       OLD.connection_snapshot, OLD.mapping_id, OLD.mapping_version,
                       OLD.mapping_digest, OLD.mapping_snapshot,
                       OLD.policy_corpus_digest, OLD.evidence_version)
            THEN
                RAISE EXCEPTION 'Phase 3 scan inputs are immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Phase 7 audit evidence is forward-only; restore from a verified backup instead."
    )
