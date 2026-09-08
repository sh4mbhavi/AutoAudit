"""Baseline governance and read access for configuration drift (Phase 8).

This module is deliberately *not* a second implementation of drift. The drift
algorithm — comparability, event derivation, severity transcription, routing —
exists exactly once, in ``engine/worker/drift.py``. Two implementations of one
audit rule can diverge behaviourally, and a report that says "no change" because
the reader's copy of the rule disagreed with the writer's copy is worse than no
report at all.

What lives here is therefore only:

* the two key constructions a *new* baseline needs at establishment time, which
  are byte-identical to the worker's, because a baseline is looked up by its
  ``configuration_key`` and the two sides must agree on the bytes;
* baseline governance — establish, list, read, revoke — which is a records
  decision, not a computation;
* read access to ``drift_run``, ``drift_event`` and the scan's drift position;
* an enqueue that asks the worker to recompute.

Three properties are structural rather than conventional:

* nothing here writes ``scan``, ``scan_result``, ``drift_run``, ``drift_event``
  or ``scan_result_factprint``. The ``Scan`` model is imported for one
  ownership-resolving SELECT and ``ScanResult`` is read through a bare column
  SELECT; neither is ever constructed, added or updated;
* every lookup resolves ownership inside the same SELECT, so a row belonging to
  another account is indistinguishable from a row that does not exist;
* no code path here creates, promotes, infers or alters a SOC 2 rating, a scan
  result or a score. ``soc2_drift_summary`` returns counts for a separate report
  stream and nothing else.

Errors are typed. Every failure carries an HTTP status and a stable machine
code, so a database constraint never reaches a caller as a 500.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.compliance import Scan
from app.models.drift import DriftBaseline, DriftEvent, DriftNotification, DriftRun
from app.models.scan_result import ScanResult
from app.models.scan_result_factprint import ScanResultFactprint
from app.services.celery_client import celery_app

# Identifies the drift semantics that produced a row, exactly as Phase 3 stamps
# semantics_version and Phase 6 stamps lifecycle_version. It is inside every
# comparability preimage, so rows written under different semantics can never be
# compared to each other by accident.
DRIFT_VERSION = "phase8-drift-v1"

# Binds every row this module writes to a named retention decision, exactly as
# Phase 7 bound evidence to "phase7-draft-1".
RETENTION_POLICY_VERSION = "phase8-draft-1"

# The only semantics a baseline may be established from. A scan assessed under
# different result semantics is not comparable and must not become a baseline.
REQUIRED_SEMANTICS_VERSION = "phase3-v1"

# The scan status a baseline may be established from.
REQUIRED_SCAN_STATUS = "completed"

# The connection fields that identify *which tenant, through which app
# registration* an observation came from. Byte-identical to the preimage in
# engine/worker/drift.py: the baseline is looked up by a key built from this
# digest, so a difference of one character here would make every baseline
# unfindable rather than merely wrong.
CONNECTION_IDENTITY_FIELDS = (
    "tenant_id",
    "client_id",
    "sharepoint_admin_url",
    "sharepoint_tenant_id",
    "sharepoint_certificate_alias",
)

# The two comparability axes. The configuration axis deliberately omits the
# policy corpus digest: editing a Rego policy cannot change tenant
# configuration. The evaluation axis includes it, because editing a policy can
# absolutely change a verdict.
COMPARABILITY_AXES = ("configuration", "evaluation")

# One honest sentence per code. The API returns the code for machines and the
# sentence for people; neither ever carries tenant evidence.
ERROR_MESSAGES: dict[str, str] = {
    "drift_scan_not_found": "Scan not found.",
    "drift_scan_not_completed": (
        "A baseline can only be established from a completed scan."
    ),
    "drift_scan_not_pinned": (
        "This scan did not pin the benchmark metadata, the policy corpus and the "
        "result semantics a comparison needs."
    ),
    "drift_facts_unavailable": (
        "This scan recorded no configuration facts, so it cannot become a "
        "baseline. A scan that predates fact capture, or that ran with no "
        "fingerprint key configured, has nothing to compare against."
    ),
    "drift_baseline_exists": "A baseline already exists for this scan.",
    "drift_baseline_active_conflict": (
        "Another active baseline for this configuration was established concurrently."
    ),
    "drift_baseline_not_found": "Drift baseline not found.",
    "drift_baseline_not_active": "This baseline is not active.",
    "drift_run_not_found": "Drift run not found.",
    "drift_run_exists": ("This baseline has already been compared against this scan."),
    "drift_queue_unavailable": (
        "The drift evaluation could not be queued. Nothing was computed and "
        "nothing was recorded."
    ),
    "drift_notification_not_found": "Drift notification thread not found.",
    "drift_notification_transition_invalid": (
        "That is not a legal transition from this thread's current state."
    ),
    "drift_remediation_not_evidenced": (
        "Remediation is not evidenced. A later completed run against this "
        "baseline, in which this finding does not recur, is required."
    ),
    "drift_not_storable": "The submitted values could not be stored.",
    "drift_conflict": "The record changed before this request could be stored.",
}

# Messages for GET /drift/scans/{scan_id}. Each says what is and is not known.
# "No baseline" and "not run" are answers, never an implied "nothing changed".
SCAN_STATUS_MESSAGES: dict[str, str] = {
    "no_baseline": (
        "No active drift baseline covers this scan's configuration, so no "
        "comparison was possible. This is not a statement about the tenant."
    ),
    "facts_unavailable": (
        "This scan recorded no configuration facts, so the configuration axis "
        "has nothing to compare. This is not a statement about the tenant."
    ),
    "not_run": (
        "A baseline covers this scan's configuration but no comparison has been "
        "run against it. Drift never fires on a timer."
    ),
    "completed": "This scan was compared against its baseline.",
    "not_comparable": (
        "This scan and its baseline were not comparable, so no comparison was "
        "made. The run records the reason for each axis."
    ),
    "fingerprints_unavailable": (
        "No fingerprint key was in force, so no configuration facts were "
        "recorded and the configuration axis could not be compared."
    ),
    "event_limit_exceeded": (
        "The comparison produced more events than one run may carry, so the run "
        "was recorded with no events. A truncated event set must never be "
        "readable as a complete one."
    ),
}


class DriftError(Exception):
    """A typed failure carrying the HTTP status and a stable machine code.

    Every refusal in this module is one of these, so a CHECK constraint or a
    unique index never surfaces to a caller as a 500 with a traceback.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: Optional[str] = None,
        **context: Any,
    ) -> None:
        resolved = message or ERROR_MESSAGES.get(code, code)
        super().__init__(resolved)
        self.status_code = status_code
        self.code = code
        self.message = resolved
        self.context = context

    def as_detail(self) -> dict[str, Any]:
        """Response body: a stable code and a message, never tenant evidence."""
        return {"code": self.code, "message": self.message, **self.context}


# ----------------------------------------------------------------------------
# Time and canonicalisation.
# ----------------------------------------------------------------------------


def utc_now() -> datetime:
    """Aware UTC.

    This deliberately differs from ``app.api.v1.evidence._now()`` and
    ``app.services.manual_evidence.utc_now()``, both of which strip the tzinfo.
    Those two feed the Phase 3 and Phase 6 ``timestamp without time zone``
    columns and must stay naive. Every Phase 8 column is ``timestamptz``
    (D-P8-10), so writing a naive value here would reintroduce exactly the
    non-UTC-server defect Phase 8 exists to stop repeating.
    """
    return datetime.now(timezone.utc)


def canonical_json(value: Any) -> str:
    """Deterministic JSON text; the preimage encoding for every digest here.

    Byte-identical to ``engine.worker.factprint.canonical_json``. The two sides
    must agree exactly: a baseline is *looked up* by a digest computed here and
    recomputed there.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _field(source: Any, name: str) -> Any:
    """Read one field from a mapping or an ORM row, so callers may pass either."""
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


# ----------------------------------------------------------------------------
# The two key constructions. Byte-identical to engine/worker/drift.py.
#
# These are the ONLY drift computation in the backend, and they exist for one
# reason: a baseline must be established under the same key the worker will
# later look it up by. There is no compare() here and there never will be.
# ----------------------------------------------------------------------------


def connection_identity_digest(connection_snapshot: Optional[Mapping[str, Any]]) -> str:
    """Digest the connection identity a scan was run through.

    Unkeyed sha256 is correct here: every input is a surrogate identifier or a
    tenant-chosen administrative URL already stored in the clear on the scan,
    not an observed tenant configuration value.
    """
    snapshot = connection_snapshot or {}
    payload = {key: snapshot.get(key) for key in CONNECTION_IDENTITY_FIELDS}
    return _sha256(canonical_json(payload))


def comparability_key(axis: str, scan: Any) -> str:
    """The lookup key for one comparability axis.

    Because a baseline is *found* by this key rather than merely checked against
    it, comparing two incomparable scans is structurally impossible: a scan with
    a different tenant, connection, benchmark, pinned metadata or result
    semantics simply does not resolve to the baseline.
    """
    if axis not in COMPARABILITY_AXES:
        raise ValueError(f"Unknown comparability axis: {axis!r}")
    base: dict[str, Any] = {
        "v": DRIFT_VERSION,
        "axis": axis,
        "user_id": _field(scan, "user_id"),
        "m365_connection_id": _field(scan, "m365_connection_id"),
        "framework": _field(scan, "framework"),
        "benchmark": _field(scan, "benchmark"),
        "version": _field(scan, "version"),
        "metadata_digest": _field(scan, "metadata_digest"),
        "semantics_version": _field(scan, "semantics_version"),
        "connection_identity_digest": connection_identity_digest(
            _field(scan, "connection_snapshot")
        ),
    }
    if axis == "evaluation":
        # A Rego edit can change a verdict, so it breaks evaluation
        # comparability. It cannot change tenant configuration, so the
        # configuration axis omits the key entirely — absent, not null.
        base["policy_corpus_digest"] = _field(scan, "policy_corpus_digest")
    return _sha256(canonical_json(base))


def observation_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    """Digest the whole observation a baseline pins.

    One entry per control: ``[control_id, status, reason_code,
    value_digest_map]``, sorted by the entry's own canonical JSON so the digest
    is independent of row order. The value digest map is that control's
    ``{field_name: value_digest}``; the digests are keyed pseudonyms produced by
    the worker, so no tenant value enters this preimage.
    """
    entries = [
        [
            row.get("control_id"),
            row.get("status"),
            row.get("reason_code"),
            row.get("value_digest_map") or {},
        ]
        for row in rows
    ]
    entries.sort(key=canonical_json)
    return _sha256(canonical_json(entries))


def _observation_rows(
    results: Iterable[Mapping[str, Any]],
    facts: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Fold the two immutable row sets into the observation digest's input."""
    by_control: dict[str, dict[str, str]] = {}
    for fact in facts:
        control_id = fact["control_id"]
        by_control.setdefault(control_id, {})[fact["field_name"]] = fact["value_digest"]
    return [
        {
            "control_id": result["control_id"],
            "status": result["status"],
            "reason_code": result["reason_code"],
            "value_digest_map": by_control.get(result["control_id"], {}),
        }
        for result in results
    ]


# ----------------------------------------------------------------------------
# Ownership-resolving reads. A row the caller may not see is a 404, never a 403:
# these routes must not be an existence oracle for another tenant's scans.
# ----------------------------------------------------------------------------


async def owned_scan(db: AsyncSession, scan_id: int, user_id: int) -> Scan:
    """Resolve one scan the caller owns, or refuse with 404."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise DriftError(404, "drift_scan_not_found")
    return scan


async def get_baseline(
    db: AsyncSession, baseline_id: int, user_id: int
) -> DriftBaseline:
    """Read one baseline the caller owns, or refuse with 404."""
    result = await db.execute(
        select(DriftBaseline).where(
            DriftBaseline.id == baseline_id, DriftBaseline.user_id == user_id
        )
    )
    baseline = result.scalar_one_or_none()
    if baseline is None:
        raise DriftError(404, "drift_baseline_not_found")
    return baseline


async def get_run(db: AsyncSession, run_id: int, user_id: int) -> DriftRun:
    """Read one run the caller owns, or refuse with 404."""
    result = await db.execute(
        select(DriftRun).where(DriftRun.id == run_id, DriftRun.user_id == user_id)
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise DriftError(404, "drift_run_not_found")
    return run


async def list_baselines(
    db: AsyncSession,
    *,
    user_id: int,
    framework: Optional[str] = None,
    benchmark: Optional[str] = None,
    version: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[DriftBaseline]:
    """One page of the caller's baselines, newest first. No COUNT is issued."""
    query = select(DriftBaseline).where(DriftBaseline.user_id == user_id)
    if framework is not None:
        query = query.where(DriftBaseline.framework == framework)
    if benchmark is not None:
        query = query.where(DriftBaseline.benchmark == benchmark)
    if version is not None:
        query = query.where(DriftBaseline.version == version)
    if status is not None:
        query = query.where(DriftBaseline.status == status)
    query = query.order_by(DriftBaseline.id.desc()).limit(limit).offset(offset)
    return list((await db.execute(query)).scalars().all())


async def list_runs(
    db: AsyncSession,
    *,
    user_id: int,
    baseline_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[DriftRun]:
    """One page of the caller's runs, newest first."""
    query = select(DriftRun).where(DriftRun.user_id == user_id)
    if baseline_id is not None:
        query = query.where(DriftRun.baseline_id == baseline_id)
    if scan_id is not None:
        query = query.where(DriftRun.current_scan_id == scan_id)
    if status is not None:
        query = query.where(DriftRun.status == status)
    query = query.order_by(DriftRun.id.desc()).limit(limit).offset(offset)
    return list((await db.execute(query)).scalars().all())


async def list_events(
    db: AsyncSession,
    *,
    run: DriftRun,
    event_class: Optional[str] = None,
    change_type: Optional[str] = None,
    severity: Optional[str] = None,
    control_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[DriftEvent]:
    """One page of one run's events.

    The run is passed in already resolved against the caller, so ownership is
    proved before this query runs and cannot be bypassed by a filter.
    """
    query = select(DriftEvent).where(DriftEvent.drift_run_id == run.id)
    if event_class is not None:
        query = query.where(DriftEvent.event_class == event_class)
    if change_type is not None:
        query = query.where(DriftEvent.change_type == change_type)
    if severity is not None:
        query = query.where(DriftEvent.severity == severity)
    if control_id is not None:
        query = query.where(DriftEvent.control_id == control_id)
    query = query.order_by(DriftEvent.id).limit(limit).offset(offset)
    return list((await db.execute(query)).scalars().all())


# ----------------------------------------------------------------------------
# Establishment.
# ----------------------------------------------------------------------------


def _require_pinned_scan(scan: Scan) -> None:
    """Refuse a scan that cannot honestly be a comparison point.

    The order is the specification's order, and it matters: "not completed" is a
    more useful answer than "not pinned" for a scan that is still running.
    """
    if getattr(scan, "status", None) != REQUIRED_SCAN_STATUS:
        raise DriftError(422, "drift_scan_not_completed")
    if getattr(scan, "semantics_version", None) != REQUIRED_SEMANTICS_VERSION:
        raise DriftError(422, "drift_scan_not_pinned")
    if not getattr(scan, "metadata_digest", None):
        raise DriftError(422, "drift_scan_not_pinned")
    if not getattr(scan, "policy_corpus_digest", None):
        raise DriftError(422, "drift_scan_not_pinned")


async def _scan_results(db: AsyncSession, scan_id: int) -> list[dict[str, Any]]:
    """Read-only column projection of one scan's results."""
    rows = await db.execute(
        select(ScanResult.control_id, ScanResult.status, ScanResult.reason_code).where(
            ScanResult.scan_id == scan_id
        )
    )
    return [dict(row) for row in rows.mappings().all()]


async def _scan_factprints(db: AsyncSession, scan_id: int) -> list[dict[str, Any]]:
    """Read-only column projection of one scan's declared facts."""
    rows = await db.execute(
        select(
            ScanResultFactprint.control_id,
            ScanResultFactprint.field_name,
            ScanResultFactprint.value_digest,
        ).where(ScanResultFactprint.scan_id == scan_id)
    )
    return [dict(row) for row in rows.mappings().all()]


def _facts_key_id(facts) -> Optional[str]:
    """The single fingerprint key id behind these facts, or None if not unique."""
    identifiers = {
        getattr(row, "key_id", None)
        or (row.get("key_id") if isinstance(row, dict) else None)
        for row in facts
    }
    identifiers.discard(None)
    if len(identifiers) == 1:
        return next(iter(identifiers))
    return None


async def _lock_active_baseline(
    db: AsyncSession, configuration_key: str
) -> Optional[DriftBaseline]:
    """Lock the active baseline for one configuration, if there is one."""
    result = await db.execute(
        select(DriftBaseline)
        .where(
            DriftBaseline.configuration_key == configuration_key,
            DriftBaseline.status == "active",
        )
        .with_for_update()
        # Without this, a row already in the identity map is returned with its
        # pre-lock attribute values.
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


def _baseline_conflict(error: IntegrityError) -> DriftError:
    """Name the index that refused, so the caller learns which conflict it hit."""
    text = str(getattr(error, "orig", error))
    if "uq_drift_baseline_scan" in text:
        return DriftError(409, "drift_baseline_exists")
    if "uq_drift_baseline_active_configuration" in text:
        return DriftError(409, "drift_baseline_active_conflict")
    return DriftError(409, "drift_conflict")


async def establish_baseline(
    db: AsyncSession,
    *,
    scan: Scan,
    actor_user_id: Optional[int],
    note: Optional[str] = None,
) -> DriftBaseline:
    """Pin one completed, fact-bearing scan as the comparison point.

    Every column is populated in the creating INSERT, following the Phase 3
    "frozen in the same INSERT" pattern: the identity of the observation a
    baseline was established from is immutable afterwards, so there is no later
    opportunity to fill it in. ``observation_digest`` is computed inside this
    same transaction from the scan's own immutable rows.

    Superseding is one transaction and never a delete: the previous active
    baseline is locked, marked superseded, and then pointed at its successor, so
    the history of what was compared against what stays readable.
    """
    _require_pinned_scan(scan)

    facts = await _scan_factprints(db, scan.id)
    if not facts:
        # A scan that predates fact capture, or that ran with no fingerprint key
        # in force, must never silently become a baseline: every later
        # comparison against it would report "no configuration change" for a
        # tenant nobody ever observed.
        raise DriftError(422, "drift_facts_unavailable")

    existing = await db.execute(
        select(DriftBaseline.id).where(DriftBaseline.scan_id == scan.id)
    )
    if existing.scalar_one_or_none() is not None:
        raise DriftError(409, "drift_baseline_exists")

    results = await _scan_results(db, scan.id)
    configuration_key = comparability_key("configuration", scan)
    evaluation_key = comparability_key("evaluation", scan)
    digest = observation_digest(_observation_rows(results, facts))
    moment = utc_now()

    superseded = await _lock_active_baseline(db, configuration_key)
    try:
        if superseded is not None:
            # Flushed before the insert: the partial unique index on
            # (configuration_key) WHERE status = 'active' is checked
            # immediately, so the slot must be released first.
            superseded.status = "superseded"
            superseded.superseded_at = moment
            await db.flush()

        baseline = DriftBaseline(
            user_id=scan.user_id,
            scan_id=scan.id,
            m365_connection_id=scan.m365_connection_id,
            framework=scan.framework,
            benchmark=scan.benchmark,
            version=scan.version,
            metadata_digest=scan.metadata_digest,
            policy_corpus_digest=scan.policy_corpus_digest,
            semantics_version=scan.semantics_version,
            connection_identity_digest=connection_identity_digest(
                scan.connection_snapshot
            ),
            configuration_key=configuration_key,
            evaluation_key=evaluation_key,
            observation_digest=digest,
            control_count=len(results),
            factprint_field_count=len(facts),
            # The fingerprint key the baseline's facts were produced under. A
            # later scan under a different key cannot be compared on the
            # configuration axis -- every value_digest is an HMAC, so a rotation
            # would otherwise report every fact as changed against an untouched
            # tenant. Recorded here so that comparison can refuse honestly.
            key_id=_facts_key_id(facts),
            status="active",
            superseded_by_id=None,
            established_by_user_id=actor_user_id,
            drift_version=DRIFT_VERSION,
            retention_policy_version=RETENTION_POLICY_VERSION,
            note=note,
            established_at=moment,
            superseded_at=None,
        )
        db.add(baseline)
        await db.flush()

        if superseded is not None:
            superseded.superseded_by_id = baseline.id
            await db.flush()

        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise _baseline_conflict(error) from None
    await db.refresh(baseline)
    return baseline


async def revoke_baseline(
    db: AsyncSession, *, baseline_id: int, user_id: int
) -> DriftBaseline:
    """Retire one active baseline. Nothing is deleted and no run is rewritten."""
    baseline = await get_baseline(db, baseline_id, user_id)
    locked = await db.execute(
        select(DriftBaseline)
        .where(DriftBaseline.id == baseline.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    baseline = locked.scalar_one_or_none()
    if baseline is None:  # pragma: no cover - deleted between the two reads
        raise DriftError(404, "drift_baseline_not_found")
    if baseline.status != "active":
        raise DriftError(409, "drift_baseline_not_active")
    baseline.status = "revoked"
    await db.commit()
    await db.refresh(baseline)
    return baseline


# ----------------------------------------------------------------------------
# Enqueue. The backend never computes drift and never writes drift_run.
# ----------------------------------------------------------------------------


def queue_drift_run(baseline_id: int, scan_id: int) -> str:
    """Ask the worker to compare one scan against one baseline.

    Nothing is written here. The task is the only thing that computes drift, and
    its UNIQUE (baseline_id, current_scan_id) makes a duplicate delivery a no-op
    rather than a second run.
    """
    try:
        task = celery_app.send_task(
            "worker.tasks.evaluate_drift",
            kwargs={"baseline_id": baseline_id, "scan_id": scan_id},
            queue="autoaudit",
        )
    except Exception:  # noqa: BLE001 - any broker fault is one honest answer
        # Deliberately broad: kombu raises OSError, ConnectionError and its own
        # OperationalError depending on the transport. A queue that cannot be
        # reached is 503 whichever of those it was, and it must never be a 500.
        raise DriftError(503, "drift_queue_unavailable") from None
    return str(getattr(task, "id", "") or "")


# ----------------------------------------------------------------------------
# Read models for a scan and for the SOC 2 report stream.
# ----------------------------------------------------------------------------


async def _latest_run_for_scan(
    db: AsyncSession, scan_id: int, user_id: int
) -> Optional[DriftRun]:
    result = await db.execute(
        select(DriftRun)
        .where(DriftRun.current_scan_id == scan_id, DriftRun.user_id == user_id)
        .order_by(DriftRun.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def scan_drift_status(
    db: AsyncSession, scan_id: int, user_id: int
) -> dict[str, Any]:
    """Where one scan stands with respect to drift.

    "No baseline", "facts unavailable" and "not run" are explicit answers rather
    than an empty list. Absence of a run is never evidence that the tenant did
    not change, and it is never evidence that a control passed.
    """
    scan = await owned_scan(db, scan_id, user_id)
    run = await _latest_run_for_scan(db, scan_id, user_id)
    if run is not None:
        return {
            "scan_id": scan_id,
            "drift_available": run.status == "completed",
            "status": run.status,
            "run": run,
            "message": SCAN_STATUS_MESSAGES[run.status],
        }

    configuration_key = comparability_key("configuration", scan)
    baseline = await db.execute(
        select(DriftBaseline.id).where(
            DriftBaseline.configuration_key == configuration_key,
            DriftBaseline.status == "active",
        )
    )
    if baseline.scalar_one_or_none() is None:
        status = "no_baseline"
    else:
        facts = await db.execute(
            select(ScanResultFactprint.id)
            .where(ScanResultFactprint.scan_id == scan_id)
            .limit(1)
        )
        if facts.scalar_one_or_none() is None:
            status = "facts_unavailable"
        else:
            status = "not_run"
    return {
        "scan_id": scan_id,
        "drift_available": False,
        "status": status,
        "run": None,
        "message": SCAN_STATUS_MESSAGES[status],
    }


async def _open_notification_count(db: AsyncSession, run_id: int) -> int:
    """Threads raised by one run whose newest revision still reads 'open'.

    State is derived, never stored: the newest revision per thread is the
    thread's state. A thread later acknowledged or accepted stops counting here
    without any row being rewritten.
    """
    threads = (
        select(DriftNotification.thread_key)
        .where(DriftNotification.drift_run_id == run_id)
        .distinct()
        .subquery()
    )
    newest = (
        select(
            DriftNotification.thread_key,
            func.max(DriftNotification.revision_number).label("revision_number"),
        )
        .where(DriftNotification.thread_key.in_(select(threads.c.thread_key)))
        .group_by(DriftNotification.thread_key)
        .subquery()
    )
    result = await db.execute(
        select(func.count())
        .select_from(DriftNotification)
        .join(
            newest,
            (DriftNotification.thread_key == newest.c.thread_key)
            & (DriftNotification.revision_number == newest.c.revision_number),
        )
        .where(DriftNotification.state_after == "open")
    )
    return int(result.scalar_one() or 0)


async def soc2_drift_summary(
    db: AsyncSession, scan_id: int, user_id: int
) -> Optional[dict[str, Any]]:
    """Counts for the SOC 2 report's separate drift stream, or None.

    Returns ``None`` when no run exists for the scan, which the report renders
    as "no drift run" rather than as an unreadable stream. Nothing here is a
    rating, and none of these numbers enters the automated coverage arithmetic.

    This raises no ``DriftError``: an absent scan, an absent baseline and an
    absent run are all simply ``None``. A genuine database fault propagates as
    ``SQLAlchemyError`` for the report to render as "unavailable", which is a
    different claim from "none".
    """
    run = await _latest_run_for_scan(db, scan_id, user_id)
    if run is None:
        return None
    return {
        "baseline_id": run.baseline_id,
        "baseline_scan_id": run.baseline_scan_id,
        "run_id": run.id,
        "run_status": run.status,
        "configuration_comparable": run.configuration_comparable,
        "evaluation_comparable": run.evaluation_comparable,
        "event_counts": run.event_counts or {},
        "event_count": run.event_count,
        "open_notification_count": await _open_notification_count(db, run.id),
    }
