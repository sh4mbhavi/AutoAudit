"""Drift notification threads: derived state over an append-only revision log.

``drift_notification`` is the history, not the state. One row is one immutable
revision; the *current* state of a thread is the ``state_after`` of its
highest-revision row. That is why there is no sixth table, no mutable status
column and no protect-trigger juggling: acknowledging, planning remediation,
accepting a risk and verifying remediation all append, and nothing is ever
rewritten.

Two properties are worth stating plainly because they are what make this a
records system rather than a task list:

* remediation is evidence-backed, not a checkbox. ``verify_remediation``
  requires a later *completed* run against the same baseline in which the
  finding's ``event_key`` does not recur. A claim that something was fixed is
  refused unless a comparison proves it;
* a notification carries a code and a count map and nothing else. There is no
  control id, fact name, member ref, digest or observed value on the table, so
  no revision written here can expose evidence.

Delivery is in-database and API-read only. There is no SMTP, no webhook and no
egress of any kind.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.drift import DriftEvent, DriftNotification, DriftRun
from app.services.drift import (
    DRIFT_VERSION,
    RETENTION_POLICY_VERSION,
    DriftError,
    utc_now,
)

# Legal moves, keyed by the state a thread is currently in. Declared once, at
# module level, the way app/services/manual_evidence.py declares TRANSITIONS.
# Every terminal state maps to the empty set rather than being absent, so an
# attempt to move on from one is refused by the same lookup as any other
# illegal move.
TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"acknowledged", "accepted_risk"}),
    "acknowledged": frozenset(
        {"remediation_planned", "accepted_risk", "remediation_verified"}
    ),
    "remediation_planned": frozenset({"remediation_verified", "accepted_risk"}),
    "remediation_verified": frozenset(),
    "accepted_risk": frozenset(),
    "superseded": frozenset(),
}

# Every revision an owner appends is an owner action; the automatic routing
# rules belong to the run that raised the thread.
OWNER_ACTION_ROUTING = "owner_action"

# The action whose row must name the run that proved it. Mirrored by
# ck_drift_notification_verified.
VERIFIED_ACTION = "remediation_verified"

# PostgreSQL rejects NUL in text and JSONB. Stripping the C0 range (keeping tab,
# newline and carriage return) means a free-text note can never turn into an
# untyped database error, and no control byte reaches a log line.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Matches the request id shape the API middleware issues, so provenance never
# carries an unvalidated caller-supplied string.
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

NOTE_MAX_LENGTH = 1000


def safe_request_id(value: Any) -> Optional[str]:
    """Keep only a request id shaped like the one the middleware issues."""
    if not isinstance(value, str) or not _REQUEST_ID_PATTERN.fullmatch(value):
        return None
    return value


def clean_note(value: Any) -> Optional[str]:
    """Trim a note to a bounded, storable string; blank input becomes NULL."""
    if value is None:
        return None
    text = _CONTROL_CHARACTERS.sub("", str(value)).strip()
    if not text:
        return None
    return text[:NOTE_MAX_LENGTH]


# The fields a derived thread carries. Selected explicitly rather than with a
# star so that adding a column to drift_notification cannot silently widen what
# this API publishes.
_THREAD_COLUMNS = (
    DriftNotification.thread_key,
    DriftNotification.scope,
    DriftNotification.baseline_id,
    DriftNotification.drift_run_id,
    DriftNotification.drift_event_id,
    DriftNotification.user_id,
    DriftNotification.severity,
    DriftNotification.summary_code,
    DriftNotification.summary_counts,
    DriftNotification.routing_rule,
    DriftNotification.state_after,
    DriftNotification.revision_number,
    DriftNotification.occurred_at,
)


def _thread_subquery(user_id: int):
    """SELECT DISTINCT ON (thread_key) ... ORDER BY thread_key, revision DESC.

    The window function is evaluated before DISTINCT ON, so ``raised_at`` is the
    first revision's timestamp even though the surviving row is the last one.
    """
    raised_at = (
        func.min(DriftNotification.occurred_at)
        .over(partition_by=DriftNotification.thread_key)
        .label("raised_at")
    )
    return (
        select(*_THREAD_COLUMNS, raised_at)
        .where(DriftNotification.user_id == user_id)
        .distinct(DriftNotification.thread_key)
        .order_by(
            DriftNotification.thread_key,
            DriftNotification.revision_number.desc(),
        )
        .subquery()
    )


def _thread(row: Any) -> dict[str, Any]:
    """One derived thread. State is computed here, never read from a column."""
    state = row.state_after
    return {
        "thread_key": row.thread_key,
        "scope": row.scope,
        "baseline_id": row.baseline_id,
        "drift_run_id": row.drift_run_id,
        "drift_event_id": row.drift_event_id,
        "user_id": row.user_id,
        "severity": row.severity,
        "summary_code": row.summary_code,
        "summary_counts": row.summary_counts or {},
        "routing_rule": row.routing_rule,
        "state": state,
        "current_revision_number": row.revision_number,
        # Derived, and deliberately narrow: only a verified remediation counts.
        # An acknowledgement is not a fix and an accepted risk is not a fix.
        "remediation_evidenced": state == VERIFIED_ACTION,
        "raised_at": row.raised_at,
        "updated_at": row.occurred_at,
    }


async def latest_revisions(
    db: AsyncSession,
    *,
    user_id: int,
    state: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """One page of the caller's threads, most recently updated first.

    The state filter is applied to the *derived* state, outside the DISTINCT ON,
    so it selects threads whose newest revision reads that state rather than
    threads that once passed through it.
    """
    inner = _thread_subquery(user_id)
    query = select(inner)
    if state is not None:
        query = query.where(inner.c.state_after == state)
    if severity is not None:
        query = query.where(inner.c.severity == severity)
    query = (
        query.order_by(inner.c.occurred_at.desc(), inner.c.thread_key)
        .limit(limit)
        .offset(offset)
    )
    rows = await db.execute(query)
    return [_thread(row) for row in rows.all()]


async def get_thread(db: AsyncSession, thread_key: str, user_id: int) -> dict[str, Any]:
    """The derived state of one thread the caller owns, or 404."""
    inner = _thread_subquery(user_id)
    rows = await db.execute(select(inner).where(inner.c.thread_key == thread_key))
    row = rows.first()
    if row is None:
        raise DriftError(404, "drift_notification_not_found")
    return _thread(row)


async def thread_history(
    db: AsyncSession, thread_key: str, user_id: int
) -> list[DriftNotification]:
    """The complete append-only history of one thread, oldest revision first."""
    rows = await db.execute(
        select(DriftNotification)
        .where(
            DriftNotification.thread_key == thread_key,
            DriftNotification.user_id == user_id,
        )
        .order_by(DriftNotification.revision_number)
    )
    revisions = list(rows.scalars().all())
    if not revisions:
        raise DriftError(404, "drift_notification_not_found")
    return revisions


async def _lock_latest_revision(
    db: AsyncSession, thread_key: str, user_id: Optional[int]
) -> DriftNotification:
    """Lock the newest revision of one thread; it is the thread's state."""
    query = select(DriftNotification).where(DriftNotification.thread_key == thread_key)
    if user_id is not None:
        query = query.where(DriftNotification.user_id == user_id)
    result = await db.execute(
        query.order_by(DriftNotification.revision_number.desc())
        .limit(1)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    revision = result.scalar_one_or_none()
    if revision is None:
        raise DriftError(404, "drift_notification_not_found")
    return revision


async def append_revision(
    db: AsyncSession,
    *,
    thread_key: str,
    action: str,
    actor_user_id: Optional[int],
    note: Optional[str] = None,
    request_id: Optional[str] = None,
    verified_run_id: Optional[int] = None,
    user_id: Optional[int] = None,
) -> dict[str, Any]:
    """Append one revision to a thread, or refuse.

    ``user_id`` scopes the lock to the recipient. It is additive to the declared
    signature and always supplied by the API: without it the lock would resolve
    a thread the caller may not see, which is exactly the cross-tenant read this
    API answers 404 for everywhere else.
    """
    latest = await _lock_latest_revision(db, thread_key, user_id)
    allowed = TRANSITIONS.get(latest.state_after, frozenset())
    if action not in allowed:
        raise DriftError(409, "drift_notification_transition_invalid")
    if (action == VERIFIED_ACTION) != (verified_run_id is not None):
        # Mirrors ck_drift_notification_verified: the row that claims a
        # remediation names the run that proved it, and no other row may.
        raise DriftError(409, "drift_notification_transition_invalid")

    revision = DriftNotification(
        baseline_id=latest.baseline_id,
        drift_run_id=latest.drift_run_id,
        drift_event_id=latest.drift_event_id,
        user_id=latest.user_id,
        thread_key=latest.thread_key,
        scope=latest.scope,
        channel=latest.channel,
        routing_rule=OWNER_ACTION_ROUTING,
        revision_number=latest.revision_number + 1,
        action=action,
        # ck_drift_notification_state_matches_action: every action other than
        # 'raised' names the state it produces.
        state_after=action,
        severity=latest.severity,
        summary_code=latest.summary_code,
        summary_counts=latest.summary_counts,
        actor_user_id=actor_user_id,
        verified_run_id=verified_run_id,
        note=clean_note(note),
        request_id=safe_request_id(request_id),
        drift_version=DRIFT_VERSION,
        retention_policy_version=RETENTION_POLICY_VERSION,
        occurred_at=utc_now(),
    )
    db.add(revision)
    try:
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        if "uq_drift_notification_revision" in str(getattr(error, "orig", error)):
            # Two concurrent actions on one thread: the unique
            # (thread_key, revision_number) index refused the second.
            raise DriftError(409, "drift_notification_transition_invalid") from None
        # Any other constraint refusal is re-raised for the API's generic
        # IntegrityError arm to answer as 409 drift_conflict. Claiming
        # "transition invalid" for a refusal that was not about the transition
        # would be a misleading answer, and misleading answers are the thing
        # this product exists to avoid.
        raise
    return await get_thread(db, thread_key, latest.user_id)


async def verify_remediation(
    db: AsyncSession,
    *,
    thread_key: str,
    scan_id: int,
    user_id: int,
    actor_user_id: Optional[int] = None,
    note: Optional[str] = None,
    request_id: Optional[str] = None,
) -> dict[str, Any]:
    """Record a remediation only when a later run proves the finding is gone.

    The evidence is a completed run against the *same* baseline, later than the
    run that raised the thread, that carries no event with this thread's
    ``event_key``. Nothing weaker is accepted: an acknowledgement, a note and an
    operator's assertion are all refused with
    ``drift_remediation_not_evidenced``.
    """
    latest = await _lock_latest_revision(db, thread_key, user_id)
    if latest.drift_run_id is None:
        # No originating run means there is no "later than" to prove.
        raise DriftError(422, "drift_remediation_not_evidenced")

    # The finding's own axis and control, read from the event that raised it.
    # Absence of an event only means "fixed" if the run actually LOOKED, and a
    # run is 'completed' whenever EITHER axis was comparable, so an absence in a
    # run that never compared this axis -- or never compared this control --
    # proves nothing. Turning "we could not look" into "it is remediated" is the
    # same error as turning a failed collection into a pass.
    origin = (
        await db.execute(
            select(DriftEvent.event_class, DriftEvent.control_id)
            .where(
                DriftEvent.baseline_id == latest.baseline_id,
                DriftEvent.event_key == thread_key,
            )
            .limit(1)
        )
    ).first()
    if origin is None:
        raise DriftError(422, "drift_remediation_not_evidenced")
    event_class, control_id = origin

    recurrence = (
        select(DriftEvent.id)
        .where(
            DriftEvent.drift_run_id == DriftRun.id,
            DriftEvent.event_key == thread_key,
        )
        .exists()
    )
    axis_compared = (
        DriftRun.configuration_comparable
        if event_class == "configuration"
        else DriftRun.evaluation_comparable
    )
    # controls_skipped is {reason: [control_id, ...]}. A control named under any
    # reason was not compared in that run, whatever the axis flags say.
    control_compared = text(
        "NOT EXISTS ("
        "SELECT 1 FROM jsonb_each(drift_run.controls_skipped) AS skipped(reason, ids)"
        " WHERE skipped.ids @> to_jsonb(CAST(:remediation_control_id AS text)))"
    ).bindparams(remediation_control_id=control_id)
    result = await db.execute(
        select(DriftRun.id)
        .where(
            DriftRun.baseline_id == latest.baseline_id,
            DriftRun.current_scan_id == scan_id,
            DriftRun.status == "completed",
            DriftRun.id > latest.drift_run_id,
            axis_compared.is_(True),
            control_compared,
            ~recurrence,
        )
        .order_by(DriftRun.id.desc())
        .limit(1)
    )
    run_id = result.scalar_one_or_none()
    if run_id is None:
        raise DriftError(422, "drift_remediation_not_evidenced")

    return await append_revision(
        db,
        thread_key=thread_key,
        action=VERIFIED_ACTION,
        actor_user_id=actor_user_id,
        note=note,
        request_id=request_id,
        verified_run_id=int(run_id),
        user_id=user_id,
    )
