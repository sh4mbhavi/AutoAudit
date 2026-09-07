"""EvidenceArtifact: an uploaded evidence file or a generated report.

Phase 7 replaces filename-addressed evidence with a tenant-scoped random object
id. Nothing in the API may authorize an artifact by its display filename; the
opaque ``object_id`` is the only public handle, and every read resolves the
owning user through this row before returning bytes.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import BigInteger, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User

# Artifact kinds. An upload is caller-supplied evidence; a report is generated.
ARTIFACT_KINDS = ("upload", "report")

# Lifecycle. Bytes are only readable in "available"; "deleted" keeps the row as
# a tombstone so the audit trail and retention record survive content removal.
ARTIFACT_STATUSES = ("pending", "processing", "available", "failed", "deleted")


class EvidenceArtifact(Base):
    """A stored evidence object, addressed only by an opaque object id."""

    __tablename__ = "evidence_artifact"
    __table_args__ = (
        Index("ix_evidence_artifact_user_kind", "user_id", "kind"),
        Index("ix_evidence_artifact_scan_result_id", "scan_result_id"),
        Index("ix_evidence_artifact_retention_expires_at", "retention_expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    # Public handle. Unguessable, tenant-scoped, and never derived from user
    # input, the strategy name, the original filename or a timestamp.
    object_id: Mapped[str] = mapped_column(
        String(43), nullable=False, unique=True, index=True
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )

    kind: Mapped[str] = mapped_column(String(20), nullable=False)

    # Optional linkage to the control this evidence supports. Kept nullable so a
    # free-standing upload is still ownable and auditable.
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_result_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan_result.id", ondelete="SET NULL"), nullable=True
    )
    control_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Display only. Sanitized on write and never used to locate or authorize.
    display_filename: Mapped[str] = mapped_column(String(255), nullable=False)

    # Detected from content, not from the client-supplied extension.
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    declared_media_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )

    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Digest of the raw uploaded bytes, not of extracted text, so re-uploading
    # the same file is provably the same evidence.
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    storage_backend: Mapped[str] = mapped_column(String(30), nullable=False)
    storage_key: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(String(20), nullable=False)
    # Stable, redacted code. Never an exception string or a caller-supplied value.
    failure_code: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)

    retention_policy_version: Mapped[str] = mapped_column(String(30), nullable=False)
    retention_expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    legal_hold: Mapped[bool] = mapped_column(nullable=False, server_default="false")
    deleted_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Benchmark/mapping identity and request correlation. Never raw evidence.
    provenance: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship()
