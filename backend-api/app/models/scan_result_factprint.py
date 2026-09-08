"""ScanResultFactprint: the declared scalar projection of one collector fact.

Phase 8 needs to know whether a tenant setting moved between two scans without
ever storing the tenant's own data. What is persisted here is therefore a
*declared* projection — a named boolean, integer, enum token or bounded enum set
that the collector's Phase 4 contract already pins — alongside a keyed digest of
its value. The raw collector payload never reaches this table.

Three properties are structural rather than conventional, and the CHECK
constraints below are their enforcement:

* ``observed_value`` can only ever hold a short JSON scalar, so an object or an
  array cannot be stored here even by a future bug;
* an ``enum_set`` field carries member digests and member tokens and no scalar,
  and both member lists are bounded;
* every row names the key that produced its digests, so a row written under a
  retired key is identifiable rather than merely stale.

The table mirrors migration a3f5c1d90b47 exactly, constraint names included, so
an autogenerate diff against it is empty.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# The only shapes a projection may declare. A field kind outside this tuple is
# rejected by ck_factprint_field_kind before it reaches a row.
FIELD_KINDS = ("bool", "int", "enum", "enum_set")

# Bound on an enum_set projection, matching ck_factprint_members_bounded. A set
# larger than this is not truncated into a row that would read as complete; the
# writer declines to record the field at all.
MAX_SET_MEMBERS = 25


class ScanResultFactprint(Base):
    """One projected, digested fact observed by one scan."""

    __tablename__ = "scan_result_factprint"
    __table_args__ = (
        CheckConstraint(
            "field_kind IN ('bool','int','enum','enum_set')",
            name="ck_factprint_field_kind",
        ),
        CheckConstraint(
            "field_name ~ '^[a-z][a-z0-9_]{0,39}$'",
            name="ck_factprint_field_name",
        ),
        CheckConstraint(
            "value_digest ~ '^[0-9a-f]{64}$'",
            name="ck_factprint_value_digest",
        ),
        # No object and no array, ever: this is where a raw tenant record would
        # otherwise leak into an evidence table.
        CheckConstraint(
            "observed_value IS NULL"
            " OR jsonb_typeof(observed_value) NOT IN ('object','array')",
            name="ck_factprint_scalar_value",
        ),
        CheckConstraint(
            "observed_value IS NULL OR length(observed_value::text) <= 40",
            name="ck_factprint_value_length",
        ),
        CheckConstraint(
            "(field_kind = 'enum_set') = (member_digests IS NOT NULL)",
            name="ck_factprint_set_members",
        ),
        CheckConstraint(
            "(field_kind = 'enum_set') = (member_tokens IS NOT NULL)",
            name="ck_factprint_set_tokens",
        ),
        CheckConstraint(
            "field_kind <> 'enum_set' OR observed_value IS NULL",
            name="ck_factprint_set_scalar",
        ),
        CheckConstraint(
            "member_digests IS NULL OR jsonb_typeof(member_digests) = 'array'",
            name="ck_factprint_members_array",
        ),
        CheckConstraint(
            "member_tokens IS NULL OR jsonb_typeof(member_tokens) = 'array'",
            name="ck_factprint_tokens_array",
        ),
        CheckConstraint(
            "member_digests IS NULL OR jsonb_array_length(member_digests) <= 25",
            name="ck_factprint_members_bounded",
        ),
        CheckConstraint(
            "member_tokens IS NULL OR jsonb_array_length(member_tokens) <= 25",
            name="ck_factprint_tokens_bounded",
        ),
        Index(
            "uq_factprint_scan_control_field",
            "scan_id",
            "control_id",
            "field_name",
            unique=True,
        ),
        Index("ix_factprint_scan_id", "scan_id"),
        Index("ix_factprint_control_id", "control_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # CASCADE: a factprint is an observation of one scan and has no meaning
    # without it. drift_baseline holds its scan by RESTRICT, so a scan a baseline
    # depends on cannot be deleted in the first place.
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan.id", ondelete="CASCADE"), nullable=False
    )

    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    collector_id: Mapped[str] = mapped_column(String(120), nullable=False)

    # Which declared projection produced the row. A collector normalisation
    # change moves this, which is how drift tells a code change apart from a
    # tenant change instead of reporting the first as the second.
    projection_id: Mapped[str] = mapped_column(String(120), nullable=False)

    field_name: Mapped[str] = mapped_column(String(40), nullable=False)
    field_kind: Mapped[str] = mapped_column(String(10), nullable=False)

    # Keyed digest (HMAC-SHA256), never a bare sha256: an unkeyed digest of a
    # boolean or a small enum is a lookup table, not a pseudonym.
    value_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    member_digests: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    member_tokens: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    # A short JSON scalar, or NULL when the value is not safe to record in the
    # clear. Constrained to a scalar and to 40 characters by the CHECKs above.
    observed_value: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)

    factprint_schema: Mapped[str] = mapped_column(String(40), nullable=False)

    # Identifies the key, never the key. A row written under a retired key can be
    # found without the key ever being recoverable from this table.
    key_id: Mapped[str] = mapped_column(String(16), nullable=False)

    retention_policy_version: Mapped[str] = mapped_column(String(40), nullable=False)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
