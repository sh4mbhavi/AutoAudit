"""Manual and inherited evidence with an approval lifecycle and immutable history.

Phase 7 replaces the single mutable free-text comment (``ManualScanResultDetail``,
retained unchanged for backward compatibility) with a record whose every decision
is an append-only revision. The record row carries the current lifecycle state and
its owners; the revision rows carry what happened, who did it and why.

Two rules are structural rather than conventional:

* revisions are insert-only, enforced by a database trigger, so an approval can
  never be edited away;
* a record can only reach ``approved``/``rejected`` through a revision written by
  a reviewer who is not the submitter, so review is independent.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.compliance import Scan
    from app.models.scan_result import ScanResult
    from app.models.user import User

# Lifecycle of a manual/inherited evidence record.
MANUAL_EVIDENCE_STATUSES = (
    "draft",
    "submitted",
    "approved",
    "rejected",
    "withdrawn",
    "expired",
)

# What a revision records. Every state change is one of these.
MANUAL_EVIDENCE_ACTIONS = (
    "created",
    "amended",
    "submitted",
    "approved",
    "rejected",
    "withdrawn",
    "expired",
)

# Recollection cadence for evidence that goes stale.
MANUAL_EVIDENCE_CADENCES = (
    "ad_hoc",
    "monthly",
    "quarterly",
    "semiannual",
    "annual",
)

# Where the assurance actually comes from. "inherited" is a provider or
# third-party control; it must never be counted as automated M365 coverage.
MANUAL_EVIDENCE_SOURCES = ("manual", "inherited")

# Maximum length of any reviewer-visible free text field.
MANUAL_EVIDENCE_TEXT_MAX = 4000


class ManualEvidenceRecord(Base):
    """Current state of one control's manual or inherited evidence."""

    __tablename__ = "manual_evidence_record"
    __table_args__ = (
        UniqueConstraint(
            "scan_result_id", name="uq_manual_evidence_record_scan_result"
        ),
        CheckConstraint(
            "status IN ('draft','submitted','approved','rejected','withdrawn','expired')",
            name="ck_manual_evidence_record_status",
        ),
        CheckConstraint(
            "evidence_source IN ('manual','inherited')",
            name="ck_manual_evidence_record_source",
        ),
        CheckConstraint(
            "collection_period_start IS NULL"
            " OR collection_period_end IS NULL"
            " OR collection_period_start <= collection_period_end",
            name="ck_manual_evidence_record_period",
        ),
        Index("ix_manual_evidence_record_user_id", "user_id"),
        Index("ix_manual_evidence_record_scan_id", "scan_id"),
        Index("ix_manual_evidence_record_expires_at", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    # RESTRICT, not CASCADE: approved evidence must not be silently destroyed by
    # deleting a scan. Deletion has to go through the audited path.
    scan_result_id: Mapped[int] = mapped_column(
        ForeignKey("scan_result.id", ondelete="RESTRICT"), nullable=False
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan.id", ondelete="RESTRICT"), nullable=False
    )

    # The control this evidence answers, frozen from the scan's pinned metadata.
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)

    # Submitting account. Distinct from the two accountable-party fields below,
    # which are organisational roles rather than application users.
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    control_owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    evidence_owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    evidence_source: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)

    # Reviewer that produced the current approved/rejected state.
    reviewer_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    collection_period_start: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    collection_period_end: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    cadence: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    retention_policy_version: Mapped[str] = mapped_column(String(30), nullable=False)

    current_revision_number: Mapped[int] = mapped_column(
        nullable=False, server_default="0"
    )

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship()
    scan_result: Mapped["ScanResult"] = relationship()
    user: Mapped["User"] = relationship(foreign_keys=[user_id])
    revisions: Mapped[list["ManualEvidenceRevision"]] = relationship(
        back_populates="record", order_by="ManualEvidenceRevision.revision_number"
    )


class ManualEvidenceRevision(Base):
    """One immutable decision in a record's history."""

    __tablename__ = "manual_evidence_revision"
    __table_args__ = (
        UniqueConstraint(
            "record_id", "revision_number", name="uq_manual_evidence_revision_number"
        ),
        CheckConstraint(
            "action IN ('created','amended','submitted','approved','rejected',"
            "'withdrawn','expired')",
            name="ck_manual_evidence_revision_action",
        ),
        CheckConstraint(
            "status_after IN ('draft','submitted','approved','rejected','withdrawn',"
            "'expired')",
            name="ck_manual_evidence_revision_status",
        ),
        # A rejection must say why. An approval must not smuggle in a rejection reason.
        CheckConstraint(
            "(action = 'rejected') = (rejection_reason IS NOT NULL)",
            name="ck_manual_evidence_revision_rejection_reason",
        ),
        Index("ix_manual_evidence_revision_record_id", "record_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    record_id: Mapped[int] = mapped_column(
        ForeignKey("manual_evidence_record.id", ondelete="RESTRICT"), nullable=False
    )
    revision_number: Mapped[int] = mapped_column(nullable=False)

    action: Mapped[str] = mapped_column(String(30), nullable=False)
    status_after: Mapped[str] = mapped_column(String(30), nullable=False)

    actor_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    # Preserved verbatim so history stays readable after an account is removed.
    actor_role: Mapped[str] = mapped_column(String(30), nullable=False)

    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Opaque EvidenceArtifact.object_id values, never filenames or paths.
    attachment_object_ids: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    # [{label, uri, note}] for evidence held outside AutoAudit.
    external_references: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    # Digest over this revision's evidence set, so a later reader can prove the
    # approved bundle is the bundle that was reviewed.
    evidence_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Benchmark/mapping identity and request correlation at decision time.
    provenance: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )

    record: Mapped["ManualEvidenceRecord"] = relationship(back_populates="revisions")
