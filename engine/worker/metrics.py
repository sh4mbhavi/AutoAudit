"""Operational metrics derived from the database, exported by the dispatcher.

Every alert rule in ``infrastructure/monitoring/alerts/`` referenced a metric
nothing produced. This module is the half of that gap the API cannot close:
scan lifecycle, control outcomes, dispatch backlog and scan staleness.

**Why the dispatcher, and why from the database.** The obvious design is an
in-process counter in the Celery worker, incremented as each control settles.
It is the wrong one here, for three reasons:

1.  The worker runs ``--pool=prefork --concurrency=4``: four forked children per
    container, each with its own counter that a scrape of the parent cannot see.
2.  A counter resets when its process restarts. An operator comparing "errors
    this hour" against the scan record would find two different numbers and no
    way to tell which is right.
3.  The database *is* the audit record. Phase 3 and Phase 6 made scan and result
    rows the durable, immutable statement of what happened. A metric read from
    those rows cannot disagree with the evidence; a parallel counter can, and
    the disagreement would surface as an alert nobody can reconcile.

So these are gauges computed from a single consistent read, and the dispatcher
-- already a supervised single process that polls the same tables on the same
interval -- is where they are exported.

**The cost of that choice, stated plainly.** A gauge sampled every poll cannot
measure something that begins and ends between two samples. Per-collection
latency is exactly that, and Phase 9's outbox deletes its row at settlement, so
it cannot be recovered afterwards either. This module therefore reports no
collection-duration series at all rather than a misleading one. What it can
measure honestly -- how long work has been *outstanding* -- it does.

**Timezone.** ``scan.last_progress_at``, ``scan.deadline_at`` and
``scan_dispatch.available_at`` are timezone-naive columns holding UTC, and
Phase 6's dispatcher compares them against ``(now() AT TIME ZONE 'UTC')`` for
that reason. Every age computed here uses the same expression. Comparing a naive
UTC column against a bare ``now()`` on a non-UTC server is the defect Phase 7
documented, and here it would report every scan as indefinitely stalled.

**Read then apply.** ``_collect`` gathers every value from the database *before*
it touches a gauge, and applies them in one pass at the end. Two reasons, both
found by the independent review:

* A failure part-way through a mutating collection would leave some gauges fresh
  and others stale, with ``up`` at 0 -- a state this module's own contract says
  cannot happen.
* ``Gauge.clear()`` followed by a database round-trip leaves a window in which a
  scrape (served on the exporter's own thread) sees the series missing
  altogether, which is not the same as seeing it at zero.
"""

from __future__ import annotations

import logging

from prometheus_client import CollectorRegistry, Gauge
from sqlalchemy import text

logger = logging.getLogger(__name__)

REGISTRY = CollectorRegistry()

# Terminal scan states never move again, so counting them without bound would
# make the series grow with history rather than describe the present. Only
# states a scan can leave are reported as live gauges.
LIVE_SCAN_STATES = ("pending", "running")

# The Phase 3 result vocabulary, in full. Every one is emitted on every
# collection, including as zero.
#
# This is load-bearing, not tidiness. `GROUP BY status` returns no row for a
# status with no results, so a status-labelled series would blink out of
# existence whenever its count reached zero. A series that disappears gets a
# staleness marker, which truncates the range `delta()` sees, resets the alert's
# `for:` timer, and leaves the result extrapolated over a shorter sampled
# interval than the one the rule asked for.
#
# Prometheus clamps that extrapolation -- it does not scale to the full window,
# as an earlier version of this comment claimed -- so the error is bounded at
# roughly 2x rather than an order of magnitude. Bounded is still wrong: an alert
# whose threshold means something different depending on whether the series
# happened to exist a moment ago is not a threshold. Emitting every status
# every time keeps the series continuous and the arithmetic honest.
RESULT_STATES = (
    "passed",
    "failed",
    "indeterminate",
    "error",
    "skipped",
    "not_assessable",
    "pending",
)

DISPATCH_BACKLOG_STATES = ("due", "deferred")

scans_in_state = Gauge(
    "autoaudit_scans_in_state",
    "Scans currently in a non-terminal state.",
    ["state"],
    registry=REGISTRY,
)

scan_oldest_progress_age_seconds = Gauge(
    "autoaudit_scan_oldest_progress_age_seconds",
    "Seconds since the least recently advanced live scan last made progress.",
    registry=REGISTRY,
)

scans_past_deadline = Gauge(
    "autoaudit_scans_past_deadline",
    "Live scans whose deadline has passed and which the reconciler has not yet failed.",
    registry=REGISTRY,
)

dispatch_backlog = Gauge(
    "autoaudit_dispatch_backlog",
    "Outbox rows awaiting publication.",
    ["state"],
    registry=REGISTRY,
)

dispatch_oldest_wait_seconds = Gauge(
    "autoaudit_dispatch_oldest_wait_seconds",
    "Seconds the oldest due-but-unpublished outbox row has been waiting.",
    registry=REGISTRY,
)

dispatch_attempts = Gauge(
    "autoaudit_dispatch_attempts",
    "Outbox rows by how many delivery attempts they have consumed.",
    ["attempts"],
    registry=REGISTRY,
)

control_results = Gauge(
    "autoaudit_control_results",
    "Control results recorded across all scans, by status.",
    ["status"],
    registry=REGISTRY,
)

scan_last_completion_timestamp_seconds = Gauge(
    "autoaudit_scan_last_completion_timestamp_seconds",
    "Unix time of the most recent scan that reached a terminal state, by status.",
    ["status"],
    registry=REGISTRY,
)

collector_exporter_up = Gauge(
    "autoaudit_collector_exporter_up",
    "1 when the last metric collection from the database succeeded, 0 otherwise.",
    registry=REGISTRY,
)


def _rows(session, sql: str, parameters: dict | None = None):
    return session.execute(text(sql), parameters or {}).mappings().all()


def collect(session, *, deadline_seconds: int | None = None) -> None:
    """Refresh every gauge from one database read.

    A failure sets ``autoaudit_collector_exporter_up`` to 0 and leaves every
    other gauge at its previous value. Zeroing them instead would look exactly
    like "the queue drained and every scan finished", which is the opposite of
    what a failed read means.
    """
    if deadline_seconds is None:
        # Imported lazily so this module stays importable without a configured
        # database, which is what lets the tests exercise it directly.
        from worker.config import settings

        deadline_seconds = settings.SCAN_DEADLINE_SECONDS
    try:
        snapshot = _read(session, deadline_seconds)
    except Exception:  # pylint: disable=broad-exception-caught
        # Never log exception text: a database URL carries credentials.
        collector_exporter_up.set(0)
        logger.error("metrics_collection_failed")
        return
    _apply(snapshot)
    collector_exporter_up.set(1)


def _read(session, deadline_seconds: int) -> dict:
    """Every value, read before any gauge is touched."""
    live = {
        row["status"]: row["count"]
        for row in _rows(
            session,
            "SELECT status, COUNT(*) AS count FROM scan "
            "WHERE status IN ('pending', 'running') GROUP BY status",
        )
    }

    staleness = _rows(
        session,
        # The overdue predicate mirrors the reconciler's own expiry SQL exactly,
        # COALESCE included. Requiring `deadline_at IS NOT NULL` here would have
        # been a quieter metric than the behaviour it describes: the reconciler
        # expires a scan whose deadline_at is null using
        # last_progress_at + SCAN_DEADLINE_SECONDS, so such a scan can be
        # genuinely overdue while a NOT NULL filter reports zero.
        "SELECT COALESCE(MAX(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC')"
        " - last_progress_at))), 0) AS age,"
        " COUNT(*) FILTER (WHERE (now() AT TIME ZONE 'UTC') >= COALESCE("
        "     deadline_at, last_progress_at + make_interval(secs => :deadline)"
        " )) AS overdue"
        " FROM scan WHERE status IN ('pending', 'running')",
        {"deadline": deadline_seconds},
    )[0]

    backlog = _rows(
        session,
        "SELECT COUNT(*) FILTER (WHERE available_at <= (now() AT TIME ZONE 'UTC')) AS due,"
        " COUNT(*) FILTER (WHERE available_at > (now() AT TIME ZONE 'UTC')) AS deferred,"
        " COALESCE(MAX(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - available_at)))"
        "   FILTER (WHERE available_at <= (now() AT TIME ZONE 'UTC')), 0) AS oldest"
        " FROM scan_dispatch",
    )[0]

    attempts = {
        str(row["attempts"]): row["count"]
        for row in _rows(
            session,
            "SELECT attempts, COUNT(*) AS count FROM scan_dispatch GROUP BY attempts",
        )
    }

    results = {
        row["status"]: row["count"]
        for row in _rows(
            session,
            "SELECT status, COUNT(*) AS count FROM scan_result "
            "WHERE selected IS TRUE GROUP BY status",
        )
    }

    # A last-success *timestamp* rather than a success counter: it lets an alert
    # ask "has a scan finished recently", which is answerable, instead of
    # `absent_over_time` on a metric that is absent whenever nobody scanned.
    completions = {
        row["status"]: float(row["finished"])
        for row in _rows(
            session,
            "SELECT status, EXTRACT(EPOCH FROM MAX(finished_at)) AS finished FROM scan "
            "WHERE finished_at IS NOT NULL GROUP BY status",
        )
        if row["finished"] is not None
    }

    return {
        "live": live,
        "age": float(staleness["age"] or 0),
        "overdue": int(staleness["overdue"] or 0),
        "backlog": {
            "due": int(backlog["due"] or 0),
            "deferred": int(backlog["deferred"] or 0),
        },
        "oldest_wait": float(backlog["oldest"] or 0),
        "attempts": attempts,
        "results": results,
        "completions": completions,
    }


def _apply(snapshot: dict) -> None:
    """Write the whole snapshot to the gauges, with no database call between."""
    for state in LIVE_SCAN_STATES:
        scans_in_state.labels(state=state).set(snapshot["live"].get(state, 0))

    scan_oldest_progress_age_seconds.set(snapshot["age"])
    scans_past_deadline.set(snapshot["overdue"])

    for state in DISPATCH_BACKLOG_STATES:
        dispatch_backlog.labels(state=state).set(snapshot["backlog"][state])
    dispatch_oldest_wait_seconds.set(snapshot["oldest_wait"])

    # Attempt counts are bounded by DISPATCH_MAX_ATTEMPTS. Clearing first stops a
    # drained bucket reporting a stale value; the clear and the sets happen back
    # to back with no I/O between, so the window a scrape could land in is a few
    # microseconds rather than a database round-trip.
    dispatch_attempts.clear()
    for attempts, count in snapshot["attempts"].items():
        dispatch_attempts.labels(attempts=attempts).set(count)

    # Every known status every time, including zero -- see RESULT_STATES.
    for status in RESULT_STATES:
        control_results.labels(status=status).set(snapshot["results"].get(status, 0))
    for status, count in snapshot["results"].items():
        if status not in RESULT_STATES:
            # An unrecognised status is reported rather than dropped: scan.status
            # has no database CHECK constraint, so a value outside the vocabulary
            # is possible and is exactly what an operator would want to see.
            control_results.labels(status=status).set(count)

    scan_last_completion_timestamp_seconds.clear()
    for status, finished in snapshot["completions"].items():
        scan_last_completion_timestamp_seconds.labels(status=status).set(finished)


def exposition() -> tuple[bytes, str]:
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
