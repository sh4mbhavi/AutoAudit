"""Durable scan lifecycle and selected-connection SharePoint binding.

Revision ID: e6a13c95d842
Revises: d5f02b84c731
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "e6a13c95d842"
down_revision = "d5f02b84c731"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("scan", "correlation_id", type_=sa.String(128))
    op.add_column("scan", sa.Column("dispatch_id", sa.String(36), nullable=True))
    op.create_unique_constraint("uq_scan_dispatch_id", "scan", ["dispatch_id"])
    op.add_column(
        "scan",
        sa.Column("dispatch_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan",
        sa.Column(
            "last_progress_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.add_column("scan", sa.Column("deadline_at", sa.DateTime(), nullable=True))
    op.add_column("scan", sa.Column("lifecycle_version", sa.String(30), nullable=True))
    op.add_column("scan", sa.Column("connection_snapshot", JSONB(), nullable=True))
    for name, kind in (
        ("sharepoint_admin_url", sa.Text()),
        ("sharepoint_tenant_id", sa.String(255)),
        ("sharepoint_certificate_alias", sa.String(255)),
    ):
        op.add_column("m365_connection", sa.Column(name, kind, nullable=True))
    op.create_table(
        "scan_dispatch",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scan.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "result_id",
            sa.Integer(),
            sa.ForeignKey("scan_result.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("task_name", sa.String(100), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "available_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("dispatched_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(100), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_scan_dispatch_available", "scan_dispatch", ["available_at"])
    op.create_index(
        "ix_scan_lifecycle_reconcile", "scan", ["status", "last_progress_at"]
    )


def downgrade():
    raise RuntimeError(
        "Phase 6 lifecycle is forward-only; retain durable dispatch and audit state"
    )
