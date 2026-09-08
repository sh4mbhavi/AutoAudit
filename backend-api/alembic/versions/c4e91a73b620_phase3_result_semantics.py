"""Phase 3 selection, provenance and immutable terminal results.

Revision ID: c4e91a73b620
Revises: 2899a0e678b6

Legacy attribution stays NULL: previous skipped rows cannot establish selection.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c4e91a73b620"
down_revision = "2899a0e678b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan", sa.Column("selected_count", sa.Integer(), nullable=True))
    op.add_column("scan", sa.Column("coverage_score", sa.Numeric(5, 2), nullable=True))
    op.add_column(
        "scan",
        sa.Column(
            "indeterminate_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "scan",
        sa.Column(
            "not_assessable_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column("scan", sa.Column("semantics_version", sa.String(30), nullable=True))
    op.add_column(
        "scan", sa.Column("metadata_snapshot", postgresql.JSONB(), nullable=True)
    )
    op.add_column("scan", sa.Column("metadata_digest", sa.Text(), nullable=True))
    op.add_column("scan", sa.Column("correlation_id", sa.String(36), nullable=True))
    op.add_column("scan_result", sa.Column("selected", sa.Boolean(), nullable=True))
    op.add_column("scan_result", sa.Column("reason_code", sa.Text(), nullable=True))
    op.add_column(
        "scan_result", sa.Column("provenance", postgresql.JSONB(), nullable=True)
    )
    op.execute("""
        CREATE FUNCTION protect_phase3_terminal_result() RETURNS trigger AS $$
        BEGIN
            IF OLD.selected IS NOT NULL
               AND OLD.status IN ('passed', 'failed', 'indeterminate', 'error', 'skipped', 'not_assessable')
               AND ROW(NEW.id, NEW.status, NEW.message, NEW.evidence, NEW.provenance,
                       NEW.reason_code, NEW.control_id, NEW.scan_id, NEW.selected,
                       NEW.created_at, NEW.updated_at)
                   IS DISTINCT FROM
                   ROW(OLD.id, OLD.status, OLD.message, OLD.evidence, OLD.provenance,
                       OLD.reason_code, OLD.control_id, OLD.scan_id, OLD.selected,
                       OLD.created_at, OLD.updated_at)
            THEN
                RAISE EXCEPTION 'Phase 3 terminal result is immutable'
                    USING ERRCODE = '23514';
            END IF;
            -- Freeze selection and identity from creation, including pending rows.
            -- Otherwise clearing selected could opt out of terminal protection.
            IF OLD.selected IS NOT NULL
               AND ROW(NEW.id, NEW.scan_id, NEW.control_id, NEW.selected, NEW.created_at)
                   IS DISTINCT FROM
                   ROW(OLD.id, OLD.scan_id, OLD.control_id, OLD.selected, OLD.created_at)
            THEN
                RAISE EXCEPTION 'Phase 3 result identity and selection are immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER phase3_terminal_result_immutable
        BEFORE UPDATE ON scan_result
        FOR EACH ROW EXECUTE FUNCTION protect_phase3_terminal_result();
    """)

    op.execute("""
        CREATE FUNCTION protect_phase3_scan_inputs() RETURNS trigger AS $$
        BEGIN
            IF OLD.semantics_version IS NOT NULL
               AND ROW(NEW.id, NEW.user_id, NEW.m365_connection_id,
                       NEW.azure_connection_id, NEW.gcp_connection_id, NEW.aws_connection_id,
                       NEW.framework, NEW.benchmark, NEW.version,
                       NEW.selected_count, NEW.total_controls, NEW.metadata_snapshot,
                       NEW.metadata_digest, NEW.correlation_id, NEW.semantics_version)
                   IS DISTINCT FROM
                   ROW(OLD.id, OLD.user_id, OLD.m365_connection_id,
                       OLD.azure_connection_id, OLD.gcp_connection_id, OLD.aws_connection_id,
                       OLD.framework, OLD.benchmark, OLD.version,
                       OLD.selected_count, OLD.total_controls, OLD.metadata_snapshot,
                       OLD.metadata_digest, OLD.correlation_id, OLD.semantics_version)
            THEN
                RAISE EXCEPTION 'Phase 3 scan inputs are immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER phase3_scan_inputs_immutable
        BEFORE UPDATE ON scan
        FOR EACH ROW EXECUTE FUNCTION protect_phase3_scan_inputs();
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Phase 3 result provenance is forward-only; restore from a verified backup instead."
    )
