"""GRC-D05 result semantics: coverage beside compliance, indeterminate counted

Adds the scan-level columns the two-number scoring contract needs:
``selected_count`` (the frozen coverage denominator), ``coverage_score``,
``indeterminate_count``, ``not_assessable_count`` and ``semantics_version``.
``scan_result.status`` is already ``String(20)`` and stores the ``indeterminate``
and ``not_assessable`` values without an enum change, so no ``scan_result`` column
is altered here.

This revision also merges the two migration heads main carries
(``k1l2m3n4o567`` and ``l1m2n3o4p567``) so the tree has a single head and
``alembic upgrade head`` is unambiguous.

Revision ID: c4e91a73b620
Revises: k1l2m3n4o567, l1m2n3o4p567
Create Date: 2026-09-08
"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4e91a73b620"
down_revision: Union[str, Sequence[str], None] = ("k1l2m3n4o567", "l1m2n3o4p567")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan", sa.Column("selected_count", sa.Integer(), nullable=True))
    op.add_column(
        "scan", sa.Column("coverage_score", sa.Numeric(5, 2), nullable=True)
    )
    op.add_column(
        "scan",
        sa.Column(
            "indeterminate_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "scan",
        sa.Column(
            "not_assessable_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "scan", sa.Column("semantics_version", sa.String(length=30), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scan", "semantics_version")
    op.drop_column("scan", "not_assessable_count")
    op.drop_column("scan", "indeterminate_count")
    op.drop_column("scan", "coverage_score")
    op.drop_column("scan", "selected_count")
