"""Revocable browser sessions and irreversible Google credential purge.

Revision ID: d5f02b84c731
Revises: c4e91a73b620
"""

from alembic import op
import sqlalchemy as sa

revision = "d5f02b84c731"
down_revision = "c4e91a73b620"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "auth_session",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_auth_session_token_hash", "auth_session", ["token_hash"], unique=True
    )
    op.create_index("ix_auth_session_user_id", "auth_session", ["user_id"])
    op.create_index("ix_auth_session_expires_at", "auth_session", ["expires_at"])
    op.execute(
        "UPDATE oauth_account SET access_token='', refresh_token=NULL, expires_at=NULL WHERE oauth_name='google'"
    )
    op.create_check_constraint(
        "ck_google_identity_only",
        "oauth_account",
        "oauth_name <> 'google' OR (access_token = '' AND refresh_token IS NULL AND expires_at IS NULL)",
    )


def downgrade():
    raise RuntimeError(
        "Phase 5 credential purge is forward-only; discarded credentials cannot be restored"
    )
