"""Merge manual verification and user profile migration heads.

Revision ID: 2899a0e678b6
Revises: ccf7645372fc, d87c3bb49953
"""

from collections.abc import Sequence

revision: str = "2899a0e678b6"
down_revision: str | Sequence[str] | None = ("ccf7645372fc", "d87c3bb49953")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Join the existing branches without changing their schema or data."""


def downgrade() -> None:
    """Restore both branch markers without reverting either branch."""
