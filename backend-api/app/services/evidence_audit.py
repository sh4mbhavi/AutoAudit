"""Append-only audit trail writer for evidence access and lifecycle events.

Every decision the evidence API makes about an object is recorded here: the
allowed ones and, just as importantly, the denied ones. A download refused
because the caller does not own the object is exactly the event an auditor needs
to see, so AUTH-01 cannot recur silently.

The table rejects UPDATE and DELETE at the database level (Phase 7 trigger
``phase7_evidence_audit_append_only``). This module never attempts either, and
``artifact_object_id`` is written denormalised so the trail survives the
artifact row being detached under retention.

``detail`` is redacted structured context only. ``redact_detail`` keeps
JSON-scalar values under short keys and drops everything else, so a filename, a
credential, a stack trace or a slice of tenant content cannot be smuggled into
the audit record by a caller or by a careless call site.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence_artifact import EvidenceArtifact
from app.models.evidence_audit_event import (
    AUDIT_ACTIONS,
    AUDIT_OUTCOMES,
    EvidenceAuditEvent,
)

logger = logging.getLogger("api")

ACTION_CREATED = "created"
ACTION_PROCESSING_STARTED = "processing_started"
ACTION_PROCESSED = "processed"
ACTION_PROCESSING_FAILED = "processing_failed"
ACTION_DOWNLOADED = "downloaded"
ACTION_REJECTED = "rejected"
ACTION_DELETED = "deleted"

OUTCOME_ALLOWED = "allowed"
OUTCOME_DENIED = "denied"
OUTCOME_ERROR = "error"

_OBJECT_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_REQUEST_ID_PATTERN = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")
_DETAIL_KEY_PATTERN = re.compile(r"\A[a-z][a-z0-9_]{0,39}\Z")

_MAX_DETAIL_KEYS = 20
_MAX_DETAIL_STRING = 120
_MAX_DETAIL_ITEMS = 20
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def _scalar(value: Any) -> Any | None:
    """Keep only values that are safe to store verbatim in JSONB."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        cleaned = _CONTROL_CHARACTERS.sub(" ", value).strip()
        return cleaned[:_MAX_DETAIL_STRING] if cleaned else None
    return None


def redact_detail(detail: Any) -> dict[str, Any] | None:
    """Reduce arbitrary context to a small dictionary of redacted scalars."""
    if not isinstance(detail, Mapping):
        return None
    safe: dict[str, Any] = {}
    for key, value in detail.items():
        if len(safe) >= _MAX_DETAIL_KEYS:
            break
        if not isinstance(key, str) or not _DETAIL_KEY_PATTERN.match(key):
            continue
        if isinstance(value, (list, tuple)):
            items = [
                item
                for item in (_scalar(entry) for entry in value[:_MAX_DETAIL_ITEMS])
                if item is not None
            ]
            if items:
                safe[key] = items
            continue
        scalar = _scalar(value)
        if scalar is not None:
            safe[key] = scalar
    return safe or None


def _object_id_of(artifact: EvidenceArtifact | str) -> str:
    object_id = (
        artifact if isinstance(artifact, str) else getattr(artifact, "object_id", "")
    )
    if not _OBJECT_ID_PATTERN.match(object_id or ""):
        raise ValueError("an audit event requires a well formed artifact object id")
    return object_id


def _actor_id(actor: Any) -> int | None:
    identifier = getattr(actor, "id", None) if actor is not None else None
    if isinstance(identifier, bool) or not isinstance(identifier, int):
        return None
    return identifier


def build_event(
    *,
    artifact: EvidenceArtifact | str,
    actor: Any,
    action: str,
    outcome: str,
    request_id: str | None = None,
    detail: Mapping[str, Any] | None = None,
) -> EvidenceAuditEvent:
    """Construct one immutable event without touching the session."""
    if action not in AUDIT_ACTIONS:
        raise ValueError("unknown evidence audit action")
    if outcome not in AUDIT_OUTCOMES:
        raise ValueError("unknown evidence audit outcome")

    object_id = _object_id_of(artifact)
    artifact_id = None if isinstance(artifact, str) else getattr(artifact, "id", None)
    safe_request_id = (
        request_id
        if isinstance(request_id, str) and _REQUEST_ID_PATTERN.match(request_id)
        else None
    )
    return EvidenceAuditEvent(
        artifact_object_id=object_id,
        artifact_id=artifact_id if isinstance(artifact_id, int) else None,
        actor_user_id=_actor_id(actor),
        action=action,
        outcome=outcome,
        request_id=safe_request_id,
        detail=redact_detail(detail),
    )


async def record_event(
    db: AsyncSession,
    *,
    artifact: EvidenceArtifact | str,
    actor: Any,
    action: str,
    outcome: str,
    request_id: str | None = None,
    detail: Mapping[str, Any] | None = None,
) -> EvidenceAuditEvent:
    """Insert one audit event. The caller owns the surrounding transaction.

    The row is flushed so a later failure in the same request cannot leave the
    caller believing an access decision was recorded when it was not.
    """
    event = build_event(
        artifact=artifact,
        actor=actor,
        action=action,
        outcome=outcome,
        request_id=request_id,
        detail=detail,
    )
    db.add(event)
    await db.flush()
    return event
