"""Response schemas for the Phase 7 evidence object API.

Only the opaque ``object_id`` is public. ``storage_backend`` and ``storage_key``
are deliberately absent: exposing where bytes live would hand a caller the very
addressing scheme Phase 7 removed. ``provenance`` is also withheld because it is
an internal correlation record rather than a tenant-facing field.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceArtifactRead(BaseModel):
    """Metadata for one evidence object the caller owns."""

    object_id: str
    kind: str
    display_filename: str
    media_type: str
    declared_media_type: str | None = None
    byte_size: int
    content_sha256: str
    status: str
    failure_code: str | None = None
    scan_id: int | None = None
    scan_result_id: int | None = None
    control_id: str | None = None
    retention_policy_version: str
    retention_expires_at: datetime | None = None
    legal_hold: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceArtifactList(BaseModel):
    """One page of the caller's own artifacts."""

    items: list[EvidenceArtifactRead]
    limit: int
    offset: int
    returned: int


class EvidenceUploadAccepted(BaseModel):
    """What a completed upload proves about the stored bytes."""

    object_id: str
    status: str
    kind: str
    media_type: str
    byte_size: int
    content_sha256: str
    extracted_chars: int | None = None


class EvidenceReadiness(BaseModel):
    """Deliberately boolean.

    The legacy ``/health`` route returned absolute container paths and an OCR
    version probe to any caller (AUTH-02). Readiness is the only fact a client
    needs, so the filesystem layout is no longer part of the answer.
    """

    ready: bool


class EvidenceScanResponse(BaseModel):
    """The legacy scan response shape, kept so the existing UI still renders.

    ``reports`` now carries opaque object ids rather than guessable filenames,
    and every download resolves through ownership.
    """

    ok: bool
    findings: list[dict] = Field(default_factory=list)
    reports: list[str] = Field(default_factory=list)
    note: str = ""
    object_id: str | None = None
    validator: dict | None = None


class LegalHoldRequest(BaseModel):
    """Apply or release a legal hold.

    ``reason`` is recorded on the audit event and is required in both
    directions: a hold placed or lifted without a stated reason is exactly the
    unaccountable action a hold exists to prevent. It is bounded and redacted by
    the audit writer like every other detail field.
    """

    hold: bool
    # Stripped before validation, and control characters rejected outright.
    # Without this "   " passed min_length=3, and the audit writer's redaction
    # then dropped the empty result -- committing a hold whose recorded reason
    # was absent, which is precisely what this field exists to prevent.
    reason: str = Field(min_length=3, max_length=120)

    @field_validator("reason")
    @classmethod
    def _substantive(cls, value: str) -> str:
        cleaned = "".join(c for c in value if c.isprintable()).strip()
        if len(cleaned) < 3:
            raise ValueError("reason must contain at least 3 printable characters")
        return cleaned


class EvidenceAuditEventRead(BaseModel):
    """One entry of the evidence access log."""

    artifact_object_id: str
    action: str
    outcome: str
    actor_user_id: int | None = None
    request_id: str | None = None
    detail: dict | None = None
    occurred_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceAuditEventList(BaseModel):
    """One page of the access log for a single artifact."""

    items: list[EvidenceAuditEventRead]
    limit: int
    offset: int
    returned: int
