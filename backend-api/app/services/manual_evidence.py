"""Manual and inherited evidence approval workflow (Phase 7, plan item 15.1.5).

This module is the only place that moves a ``ManualEvidenceRecord`` between
states. Every legal move writes one ``ManualEvidenceRevision`` and advances the
record's ``current_revision_number`` inside a single transaction that starts by
locking the record row, so two concurrent decisions cannot interleave. Illegal
moves raise a typed error instead of mutating anything.

Three properties are deliberately structural rather than conventional:

* history is append-only. Nothing here updates or deletes a revision, and the
  database refuses those statements anyway;
* review is independent. The approving or rejecting actor may never be the
  record's submitter, checked here for a clean error and by a CHECK constraint
  underneath;
* manual evidence is a *residual* assurance stream. Nothing in this module
  reads, writes or derives ``scan_result.status``, the scan's per-status counts,
  the compliance score or the coverage score. Approving a document is not a
  configuration assessment, and an approval must never make an automated control
  look assessed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.compliance import Scan
from app.models.evidence_artifact import EvidenceArtifact
from app.models.manual_evidence import (
    MANUAL_EVIDENCE_CADENCES,
    MANUAL_EVIDENCE_SOURCES,
    MANUAL_EVIDENCE_TEXT_MAX,
    ManualEvidenceRecord,
    ManualEvidenceRevision,
)

# Identifies the workflow semantics that produced a revision, the way Phase 3
# stamps semantics_version and Phase 6 stamps lifecycle_version.
WORKFLOW_VERSION = "phase7-manual-v1"

# Recorded on every revision so a reader of the history can never mistake an
# approved document for automated configuration coverage.
ASSURANCE_STREAM = "manual_residual"

# States that accept no further transition.
TERMINAL_STATUSES = frozenset({"withdrawn", "expired"})

# action -> (allowed source states, resulting state, revision action)
TRANSITIONS: dict[str, tuple[frozenset[str], str, str]] = {
    "submit": (frozenset({"draft"}), "submitted", "submitted"),
    "amend": (frozenset({"draft", "rejected", "approved"}), "draft", "amended"),
    "approve": (frozenset({"submitted"}), "approved", "approved"),
    "reject": (frozenset({"submitted"}), "rejected", "rejected"),
    "withdraw": (
        frozenset({"draft", "submitted", "approved", "rejected"}),
        "withdrawn",
        "withdrawn",
    ),
    "expire": (frozenset({"approved"}), "expired", "expired"),
}

# Transitions only an independent reviewer may perform.
REVIEWER_TRANSITIONS = frozenset({"approve", "reject"})

# Transitions only the submitting account may perform.
SUBMITTER_TRANSITIONS = frozenset({"submit", "amend", "withdraw"})

# Transitions that must re-prove the carried attachments are still available.
# Evidence must never be sent for review, or approved, once the artifacts behind
# it have failed or been deleted. Withdrawal and expiry deliberately stay
# possible so a record can always be closed out.
REVALIDATED_TRANSITIONS = frozenset({"submit", "approve"})

MAX_ATTACHMENTS = 50
MAX_EXTERNAL_REFERENCES = 25
MAX_URI_LENGTH = 2000
MAX_LABEL_LENGTH = 200

# Opaque, tenant-scoped artifact handles. Never a filename or a path.
_OBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,43}$")
# Matches the request id shape the API middleware accepts, so provenance can
# never carry an unvalidated caller-supplied string.
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CONTROL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$")
# PostgreSQL rejects NUL in text and JSONB. Stripping the C0 range here (keeping
# tab, newline and carriage return) means no free-text field can turn into an
# untyped database error, and no control byte can be smuggled into a log line.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_VERSION_PATTERN = re.compile(r"^v[0-9]+(?:\.[0-9]+){0,3}$")

# Artifacts whose bytes are gone (or never arrived) cannot back an approval.
ATTACHABLE_ARTIFACT_STATUSES = frozenset({"pending", "processing", "available"})

# Optional deployment override for the read-only auditor instruction templates.
TEMPLATE_DIR_ENV = "MANUAL_CONTROL_TEMPLATES_DIR"


# ----------------------------------------------------------------------------
# Typed errors. Each carries the HTTP status the API layer should return, so no
# database constraint ever surfaces to a caller as a 500.
# ----------------------------------------------------------------------------


class ManualEvidenceError(Exception):
    """Base class for workflow failures with a stable machine-readable code."""

    status_code = 409
    code = "manual_evidence_error"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def as_detail(self) -> dict[str, Any]:
        """Response body: a stable code and a message, never raw evidence."""
        return {"code": self.code, "message": self.message, **self.context}


class RecordNotFound(ManualEvidenceError):
    status_code = 404
    code = "manual_evidence_not_found"


class IllegalTransition(ManualEvidenceError):
    status_code = 409
    code = "illegal_transition"


class IndependentReviewRequired(ManualEvidenceError):
    status_code = 403
    code = "independent_review_required"


class RejectionReasonRequired(ManualEvidenceError):
    status_code = 422
    code = "rejection_reason_required"


class InvalidEvidenceSet(ManualEvidenceError):
    status_code = 422
    code = "invalid_evidence_set"


class UnknownAttachment(ManualEvidenceError):
    status_code = 422
    code = "unknown_attachment"


# ----------------------------------------------------------------------------
# Small helpers.
# ----------------------------------------------------------------------------


def utc_now() -> datetime:
    """Naive UTC, matching every other timestamp column in this schema."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalise an aware timestamp to the naive UTC the columns store."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _clean_text(value: Any, *, limit: int = MANUAL_EVIDENCE_TEXT_MAX) -> Optional[str]:
    """Trim to a bounded string, mapping blank input to NULL."""
    if value is None:
        return None
    text = _CONTROL_CHARACTERS.sub("", str(value)).strip()
    if not text:
        return None
    return text[:limit]


def safe_request_id(value: Any) -> Optional[str]:
    """Keep only a request id shaped like the one the middleware issues."""
    if not isinstance(value, str) or not _REQUEST_ID_PATTERN.fullmatch(value):
        return None
    return value


# ----------------------------------------------------------------------------
# Evidence set normalisation and digest.
# ----------------------------------------------------------------------------


def _canonical_reference(reference: Any) -> dict[str, Optional[str]]:
    """One external reference reduced to its three canonical fields."""
    if isinstance(reference, dict):
        raw = reference
    elif hasattr(reference, "model_dump"):
        raw = reference.model_dump()
    else:
        raise InvalidEvidenceSet("Each external reference must be an object.")

    label = _clean_text(raw.get("label"), limit=MAX_LABEL_LENGTH)
    uri = _clean_text(raw.get("uri"), limit=MAX_URI_LENGTH)
    note = _clean_text(raw.get("note"))
    if not label:
        raise InvalidEvidenceSet("Each external reference needs a label.")
    if uri is not None:
        scheme, separator, remainder = uri.partition("://")
        if not separator or scheme.lower() not in {"http", "https"}:
            raise InvalidEvidenceSet(
                "External reference URIs must be http or https, or be omitted."
            )
        authority = remainder.split("/", 1)[0]
        if "@" in authority:
            # Credentials in a URI would be persisted in the revision history.
            raise InvalidEvidenceSet(
                "External reference URIs must not embed credentials."
            )
    return {"label": label, "uri": uri, "note": note}


def normalise_evidence_set(
    attachment_object_ids: Optional[Iterable[Any]],
    external_references: Optional[Iterable[Any]],
) -> tuple[list[str], list[dict[str, Optional[str]]]]:
    """Validate and canonically order one revision's evidence set."""
    object_ids: list[str] = []
    for candidate in attachment_object_ids or []:
        if not isinstance(candidate, str) or not _OBJECT_ID_PATTERN.fullmatch(
            candidate
        ):
            raise InvalidEvidenceSet("Attachments are referenced by object id.")
        if candidate not in object_ids:
            object_ids.append(candidate)
    if len(object_ids) > MAX_ATTACHMENTS:
        raise InvalidEvidenceSet(
            f"A revision may reference at most {MAX_ATTACHMENTS} attachments."
        )

    references = [_canonical_reference(item) for item in external_references or []]
    if len(references) > MAX_EXTERNAL_REFERENCES:
        raise InvalidEvidenceSet(
            f"A revision may carry at most {MAX_EXTERNAL_REFERENCES} references."
        )

    object_ids.sort()
    references.sort(key=lambda item: _canonical_json(item))
    return object_ids, references


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def compute_evidence_sha256(
    attachment_object_ids: Sequence[str],
    external_references: Sequence[dict[str, Optional[str]]],
) -> str:
    """Digest the evidence set so an approved bundle is provable afterwards.

    The digest covers the attachment object ids and the canonicalised external
    references only. It sorts both itself, so it is independent of insertion
    order regardless of how the caller ordered them, and it changes whenever the
    set changes.
    """
    payload = {
        "schema_version": 1,
        "workflow_version": WORKFLOW_VERSION,
        "attachment_object_ids": sorted(set(attachment_object_ids)),
        "external_references": sorted(external_references, key=_canonical_json),
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


async def resolve_attachments(
    db: AsyncSession, object_ids: Sequence[str], owner_user_id: int
) -> None:
    """Prove every referenced artifact exists and belongs to the submitter.

    An unknown id and another tenant's id produce the identical error, so this
    cannot be used to probe for the existence of someone else's evidence.
    """
    if not object_ids:
        return
    result = await db.execute(
        select(EvidenceArtifact.object_id).where(
            EvidenceArtifact.object_id.in_(list(object_ids)),
            EvidenceArtifact.user_id == owner_user_id,
            EvidenceArtifact.status.in_(sorted(ATTACHABLE_ARTIFACT_STATUSES)),
        )
    )
    found = set(result.scalars().all())
    missing = [object_id for object_id in object_ids if object_id not in found]
    if missing:
        raise UnknownAttachment(
            "One or more attachments are unknown or not available to you.",
            unknown_attachment_count=len(missing),
        )


# ----------------------------------------------------------------------------
# Provenance.
# ----------------------------------------------------------------------------


def _isoformat(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def build_envelope(
    *,
    collection_period_start: Optional[datetime],
    collection_period_end: Optional[datetime],
    expires_at: Optional[datetime],
    cadence: Optional[str],
) -> dict[str, Any]:
    """The accountability and period fields as they stood for this revision.

    The record row only ever shows the *current* envelope. Recording it on each
    revision means a later amendment cannot quietly erase the collection period
    or expiry that an approval was actually granted against.

    Deliberately structured values only. Free text a caller typed (owners,
    comments, rejection reasons, reference labels) stays in its own columns and
    never enters provenance, which must carry identifiers and digests alone.
    """
    return {
        "collection_period_start": _isoformat(collection_period_start),
        "collection_period_end": _isoformat(collection_period_end),
        "expires_at": _isoformat(expires_at),
        "cadence": cadence,
    }


def build_provenance(
    *,
    scan: Optional[Scan],
    record: ManualEvidenceRecord,
    action: str,
    status_after: str,
    evidence_sha256: str,
    request_id: Optional[str],
    attachment_count: int,
    external_reference_count: int,
    envelope: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Benchmark/mapping identity and correlation at decision time.

    Carries identifiers and digests only: never credentials, tenant payloads,
    filenames or evidence content.
    """
    return {
        "evidence_envelope": envelope,
        "schema_version": 1,
        "workflow_version": WORKFLOW_VERSION,
        "assurance_stream": ASSURANCE_STREAM,
        # Stated explicitly because the whole point of this stream is that an
        # approval here changes no automated result, count or score.
        "automated_coverage_effect": "none",
        "action": action,
        "status_after": status_after,
        "control_id": record.control_id,
        "evidence_source": record.evidence_source,
        "framework": getattr(scan, "framework", None),
        "benchmark": getattr(scan, "benchmark", None),
        "benchmark_version": getattr(scan, "version", None),
        "mapping_id": getattr(scan, "mapping_id", None),
        "mapping_version": getattr(scan, "mapping_version", None),
        "mapping_digest": getattr(scan, "mapping_digest", None),
        "metadata_digest": getattr(scan, "metadata_digest", None),
        "policy_corpus_digest": getattr(scan, "policy_corpus_digest", None),
        "evidence_version": getattr(scan, "evidence_version", None),
        "correlation_id": getattr(scan, "correlation_id", None),
        "request_id": safe_request_id(request_id),
        "evidence_sha256": evidence_sha256,
        "attachment_count": attachment_count,
        "external_reference_count": external_reference_count,
        "retention_policy_version": record.retention_policy_version,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


# ----------------------------------------------------------------------------
# Locking and lookup.
# ----------------------------------------------------------------------------


async def lock_record(
    db: AsyncSession, record_id: int
) -> Optional[ManualEvidenceRecord]:
    """SELECT ... FOR UPDATE, matching the Phase 6 scan lifecycle idiom."""
    result = await db.execute(
        select(ManualEvidenceRecord)
        .where(ManualEvidenceRecord.id == record_id)
        .with_for_update()
        # Without this, a record already in the identity map (every route loads
        # it once to authorize) is returned with its pre-lock attribute values.
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def get_record(
    db: AsyncSession,
    *,
    record_id: Optional[int] = None,
    scan_result_id: Optional[int] = None,
) -> Optional[ManualEvidenceRecord]:
    """Read one record without locking it."""
    query = select(ManualEvidenceRecord)
    if record_id is not None:
        query = query.where(ManualEvidenceRecord.id == record_id)
    elif scan_result_id is not None:
        query = query.where(ManualEvidenceRecord.scan_result_id == scan_result_id)
    else:  # pragma: no cover - defensive
        raise ValueError("A record id or scan result id is required")
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def list_revisions(
    db: AsyncSession, record_id: int
) -> list[ManualEvidenceRevision]:
    """Full immutable history, oldest first."""
    result = await db.execute(
        select(ManualEvidenceRevision)
        .where(ManualEvidenceRevision.record_id == record_id)
        .order_by(ManualEvidenceRevision.revision_number)
    )
    return list(result.scalars().all())


async def _current_revision(
    db: AsyncSession, record: ManualEvidenceRecord
) -> Optional[ManualEvidenceRevision]:
    result = await db.execute(
        select(ManualEvidenceRevision)
        .where(
            ManualEvidenceRevision.record_id == record.id,
            ManualEvidenceRevision.revision_number == record.current_revision_number,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


# ----------------------------------------------------------------------------
# Creation and transitions.
# ----------------------------------------------------------------------------


async def create_draft(
    db: AsyncSession,
    *,
    scan: Scan,
    scan_result_id: int,
    control_id: str,
    actor_user_id: int,
    actor_role: str,
    evidence_source: str = "manual",
    control_owner: Optional[str] = None,
    evidence_owner: Optional[str] = None,
    collection_period_start: Optional[datetime] = None,
    collection_period_end: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    cadence: Optional[str] = None,
    comment: Optional[str] = None,
    attachment_object_ids: Optional[Iterable[Any]] = None,
    external_references: Optional[Iterable[Any]] = None,
    request_id: Optional[str] = None,
) -> ManualEvidenceRecord:
    """Open a record in ``draft`` with revision 1, ``created``.

    The caller is responsible for having authorized the parent scan. The
    control id is taken from the frozen scan result, never from the request.
    """
    if evidence_source not in MANUAL_EVIDENCE_SOURCES:
        raise InvalidEvidenceSet("Unsupported evidence source.")
    if cadence is not None and cadence not in MANUAL_EVIDENCE_CADENCES:
        raise InvalidEvidenceSet("Unsupported recollection cadence.")

    period_start = to_naive_utc(collection_period_start)
    period_end = to_naive_utc(collection_period_end)
    if period_start and period_end and period_start > period_end:
        raise InvalidEvidenceSet("The collection period ends before it starts.")

    object_ids, references = normalise_evidence_set(
        attachment_object_ids, external_references
    )
    await resolve_attachments(db, object_ids, actor_user_id)

    record = ManualEvidenceRecord(
        scan_result_id=scan_result_id,
        scan_id=scan.id,
        control_id=control_id,
        user_id=actor_user_id,
        control_owner=_clean_text(control_owner, limit=200),
        evidence_owner=_clean_text(evidence_owner, limit=200),
        evidence_source=evidence_source,
        status="draft",
        collection_period_start=period_start,
        collection_period_end=period_end,
        expires_at=to_naive_utc(expires_at),
        cadence=cadence,
        retention_policy_version=get_settings().EVIDENCE_RETENTION_POLICY_VERSION,
        current_revision_number=1,
    )
    db.add(record)
    await db.flush()

    evidence_sha256 = compute_evidence_sha256(object_ids, references)
    db.add(
        ManualEvidenceRevision(
            record_id=record.id,
            revision_number=1,
            action="created",
            status_after="draft",
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            comment=_clean_text(comment),
            rejection_reason=None,
            attachment_object_ids=object_ids,
            external_references=references,
            evidence_sha256=evidence_sha256,
            provenance=build_provenance(
                scan=scan,
                record=record,
                action="created",
                status_after="draft",
                evidence_sha256=evidence_sha256,
                request_id=request_id,
                attachment_count=len(object_ids),
                external_reference_count=len(references),
                envelope=build_envelope(
                    collection_period_start=record.collection_period_start,
                    collection_period_end=record.collection_period_end,
                    expires_at=record.expires_at,
                    cadence=record.cadence,
                ),
            ),
        )
    )
    await db.commit()
    await db.refresh(record)
    return record


async def apply_transition(
    db: AsyncSession,
    *,
    record_id: int,
    action: str,
    actor_user_id: Optional[int],
    actor_role: str,
    comment: Optional[str] = None,
    rejection_reason: Optional[str] = None,
    attachment_object_ids: Optional[Iterable[Any]] = None,
    external_references: Optional[Iterable[Any]] = None,
    replace_evidence_set: bool = False,
    record_updates: Optional[dict[str, Any]] = None,
    request_id: Optional[str] = None,
    now: Optional[datetime] = None,
    precondition: Optional[Callable[[ManualEvidenceRecord], Optional[str]]] = None,
) -> ManualEvidenceRecord:
    """Move a record one legal step, writing exactly one new revision.

    The record row is locked first, so the state test and the write that
    depends on it cannot be split by a concurrent decision. Nothing is written
    when the transition is illegal.

    ``precondition`` is evaluated against the freshly locked row and refuses the
    transition (409) by returning a message. Use it for any condition a caller
    tested before taking the lock.
    """
    if action not in TRANSITIONS:  # pragma: no cover - defensive
        raise IllegalTransition("Unknown transition.", requested=str(action))
    allowed_from, status_after, revision_action = TRANSITIONS[action]

    record = await lock_record(db, record_id)
    if record is None:
        raise RecordNotFound("Manual evidence record not found.")

    if record.status not in allowed_from:
        raise IllegalTransition(
            f"A record in '{record.status}' cannot be {revision_action}.",
            current_status=record.status,
            requested_action=action,
            allowed_from=sorted(allowed_from),
        )

    refusal = precondition(record) if precondition is not None else None
    if refusal:
        raise IllegalTransition(
            refusal, current_status=record.status, requested_action=action
        )

    if action in REVIEWER_TRANSITIONS and actor_user_id == record.user_id:
        raise IndependentReviewRequired(
            "Manual evidence must be reviewed by someone other than its submitter."
        )

    reason = _clean_text(rejection_reason)
    if action == "reject" and not reason:
        raise RejectionReasonRequired("A rejection must state a reason.")
    if action != "reject":
        reason = None

    if replace_evidence_set:
        object_ids, references = normalise_evidence_set(
            attachment_object_ids, external_references
        )
        await resolve_attachments(db, object_ids, record.user_id)
    else:
        # Carry the reviewed bundle forward verbatim so an approval digests
        # exactly what was submitted.
        previous = await _current_revision(db, record)
        object_ids = list(getattr(previous, "attachment_object_ids", None) or [])
        references = list(getattr(previous, "external_references", None) or [])
        if action in REVALIDATED_TRANSITIONS:
            await resolve_attachments(db, object_ids, record.user_id)

    updates = dict(record_updates or {})
    period_start = to_naive_utc(
        updates.get("collection_period_start", record.collection_period_start)
    )
    period_end = to_naive_utc(
        updates.get("collection_period_end", record.collection_period_end)
    )
    if period_start and period_end and period_start > period_end:
        raise InvalidEvidenceSet("The collection period ends before it starts.")
    cadence = updates.get("cadence", record.cadence)
    if cadence is not None and cadence not in MANUAL_EVIDENCE_CADENCES:
        raise InvalidEvidenceSet("Unsupported recollection cadence.")
    control_owner = (
        _clean_text(updates["control_owner"], limit=200)
        if "control_owner" in updates
        else record.control_owner
    )
    evidence_owner = (
        _clean_text(updates["evidence_owner"], limit=200)
        if "evidence_owner" in updates
        else record.evidence_owner
    )
    expires_at = (
        to_naive_utc(updates["expires_at"])
        if "expires_at" in updates
        else record.expires_at
    )

    scan = await db.get(Scan, record.scan_id)
    evidence_sha256 = compute_evidence_sha256(object_ids, references)
    moment = to_naive_utc(now) or utc_now()

    revision = ManualEvidenceRevision(
        record_id=record.id,
        revision_number=record.current_revision_number + 1,
        action=revision_action,
        status_after=status_after,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        comment=_clean_text(comment),
        rejection_reason=reason,
        attachment_object_ids=object_ids,
        external_references=references,
        evidence_sha256=evidence_sha256,
        provenance=build_provenance(
            scan=scan,
            record=record,
            action=revision_action,
            status_after=status_after,
            evidence_sha256=evidence_sha256,
            request_id=request_id,
            attachment_count=len(object_ids),
            external_reference_count=len(references),
            envelope=build_envelope(
                collection_period_start=period_start,
                collection_period_end=period_end,
                expires_at=expires_at,
                cadence=cadence,
            ),
        ),
    )
    db.add(revision)

    # The record row and its new revision move together. The database refuses
    # an approved/rejected status change that does not advance this counter.
    record.current_revision_number = revision.revision_number
    record.status = status_after
    record.collection_period_start = period_start
    record.collection_period_end = period_end
    record.cadence = cadence
    record.control_owner = control_owner
    record.evidence_owner = evidence_owner
    record.expires_at = expires_at
    if action in REVIEWER_TRANSITIONS:
        record.reviewer_user_id = actor_user_id
        record.reviewed_at = moment

    await db.commit()
    await db.refresh(record)
    return record


# ----------------------------------------------------------------------------
# Expiry.
# ----------------------------------------------------------------------------


async def due_for_expiry(
    db: AsyncSession, *, now: Optional[datetime] = None, limit: int = 100
) -> list[int]:
    """Ids of approved records whose expiry has passed."""
    moment = to_naive_utc(now) or utc_now()
    result = await db.execute(
        select(ManualEvidenceRecord.id)
        .where(
            ManualEvidenceRecord.status == "approved",
            ManualEvidenceRecord.expires_at.is_not(None),
            ManualEvidenceRecord.expires_at <= moment,
        )
        .order_by(ManualEvidenceRecord.expires_at)
        .limit(limit)
    )
    return list(result.scalars().all())


async def expire_due_records(
    db: AsyncSession,
    *,
    now: Optional[datetime] = None,
    limit: int = 100,
    request_id: Optional[str] = None,
) -> list[int]:
    """Mark every approved record past its expiry as ``expired``.

    Each record gets its own locked transaction and its own ``expired``
    revision. Nothing is deleted: an expired record keeps its full history and
    its approved revision stays readable. Idempotent, so a concurrent runner
    that already expired a record is simply skipped.

    This is a plain callable. Running it on a schedule is deployment work and
    is deliberately not wired to a scheduler here.
    """
    moment = to_naive_utc(now) or utc_now()

    def still_due(record: ManualEvidenceRecord) -> Optional[str]:
        """Re-tested under the lock: the expiry may have moved since selection."""
        if record.expires_at is None or record.expires_at > moment:
            return "The record is no longer due for expiry."
        return None

    expired: list[int] = []
    for record_id in await due_for_expiry(db, now=moment, limit=limit):
        try:
            await apply_transition(
                db,
                record_id=record_id,
                action="expire",
                actor_user_id=None,
                actor_role="system",
                comment="Approved evidence reached its expiry date.",
                request_id=request_id,
                now=moment,
                precondition=still_due,
            )
        except (IllegalTransition, RecordNotFound):
            # Release the lock this attempt took before moving on.
            await db.rollback()
            continue
        expired.append(record_id)
    return expired


# ----------------------------------------------------------------------------
# Auditor instruction templates.
#
# The template file is read-only reference data. It is never copied into Python
# and never written back.
# ----------------------------------------------------------------------------


def _validated_segments(
    framework: str, benchmark: str, version: str
) -> tuple[str, ...]:
    """Reject anything that could escape the template directories."""
    if not _SLUG_PATTERN.fullmatch(framework or ""):
        raise InvalidEvidenceSet("Unsupported framework.")
    if not _SLUG_PATTERN.fullmatch(benchmark or ""):
        raise InvalidEvidenceSet("Unsupported benchmark.")
    if not _VERSION_PATTERN.fullmatch(version or ""):
        raise InvalidEvidenceSet("Unsupported benchmark version.")
    return framework, benchmark, version


def template_search_paths(framework: str, benchmark: str, version: str) -> list[Path]:
    """Candidate locations for ``manual_controls_<version>.json``.

    Ordered most specific first: an explicit deployment path, then the
    read-only policy mount beside the benchmark's metadata, then the source
    tree copy used in development.
    """
    framework, benchmark, version = _validated_segments(framework, benchmark, version)
    filename = f"manual_controls_{version}.json"
    candidates: list[Path] = []

    override = os.environ.get(TEMPLATE_DIR_ENV)
    if override:
        candidates.append(Path(override) / filename)

    policies_dir = Path(getattr(get_settings(), "POLICIES_DIR", "/app/policies"))
    candidates.append(policies_dir / framework / benchmark / version / filename)
    candidates.append(
        policies_dir / framework / benchmark / version / "manual_controls.json"
    )
    candidates.append(policies_dir / "templates" / filename)

    repository_root = Path(__file__).resolve().parents[3]
    candidates.append(repository_root / "docs" / "compliance" / "templates" / filename)
    return candidates


@lru_cache(maxsize=8)
def load_manual_control_templates(
    framework: str, benchmark: str, version: str
) -> dict[str, dict[str, Any]]:
    """Read the auditor instructions for one benchmark version.

    Returns an empty mapping when no template file is deployed, so a missing
    file reads as "no instructions available", never as a control result. The
    returned mapping is cached and must be treated as read-only.
    """
    for path in template_search_paths(framework, benchmark, version):
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(entries, list):
            continue
        templates: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            control_id = entry.get("control_id")
            if not isinstance(control_id, str) or not _CONTROL_ID_PATTERN.fullmatch(
                control_id
            ):
                continue
            if entry.get("version") not in (None, version):
                continue
            # A fallback directory holds one file per version; without these two
            # checks a request for another framework or benchmark would be
            # answered with this benchmark's instructions.
            if entry.get("framework") not in (None, framework):
                continue
            if entry.get("benchmark") not in (None, benchmark):
                continue
            templates[control_id] = entry
        if templates:
            return templates
    return {}


def get_manual_control_template(
    framework: str, benchmark: str, version: str, control_id: str
) -> Optional[dict[str, Any]]:
    """One control's auditor instructions, or None when it has none.

    A control absent from the template set is simply a control this benchmark
    version does not collect manual evidence instructions for. That is not a
    statement about whether the control passes.
    """
    if not _CONTROL_ID_PATTERN.fullmatch(control_id or ""):
        return None
    return load_manual_control_templates(framework, benchmark, version).get(control_id)


def clear_template_cache() -> None:
    """Drop the cached template files (deployment refresh and tests)."""
    load_manual_control_templates.cache_clear()
