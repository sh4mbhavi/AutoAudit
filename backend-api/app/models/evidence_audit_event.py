"""Append-only audit trail for evidence objects and generated reports.

Phase 7 anti-pattern guard: approved evidence must not be editable or deletable
without an audit event. Rows here are insert-only; a database trigger rejects
UPDATE and DELETE, so the trail survives even when the artifact content is
removed under retention. ``artifact_object_id`` is stored denormalised for
exactly that reason.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base

AUDIT_ACTIONS = (
    "created",
    "processing_started",
    "processed",
    "processing_failed",
    "downloaded",
    "rejected",
    "deleted",
    "retention_expired",
    "legal_hold_applied",
    "legal_hold_released",
)

AUDIT_OUTCOMES = ("allowed", "denied", "error")


class EvidenceAuditEvent(Base):
    """One immutable record of an access or lifecycle decision."""

    __tablename__ = "evidence_audit_event"
    __table_args__ = (
        Index("ix_evidence_audit_event_object_id", "artifact_object_id"),
        Index("ix_evidence_audit_event_occurred_at", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Kept even after the artifact row is gone, so deletion is itself auditable.
    artifact_object_id: Mapped[str] = mapped_column(String(43), nullable=False)
    artifact_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("evidence_artifact.id", ondelete="SET NULL"), nullable=True
    )

    # Null when the actor is the system (retention sweep) or the account is gone.
    actor_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    action: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)

    # Propagated from RequestLoggingMiddleware so an access decision can be tied
    # back to the originating request without storing the request itself.
    request_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Redacted structured context only: codes, sizes, identifiers. Never file
    # bytes, extracted text, credentials or tenant payloads.
    detail: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    occurred_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
