"""Broker-independent outbox publisher and reconciler.

Run ``python -m worker.dispatcher --once`` for a single pass, or omit --once
for the supervised polling service. PostgreSQL owns retry state; no Beat or
Celery delivery is needed to recover from broker/process outages.
"""

import argparse
import logging
import time

from prometheus_client import start_http_server
from sqlalchemy import text

from worker import metrics
from worker.celery_app import celery_app
from worker.config import settings
from worker.db import get_db_session, get_scan, finalize_scan_if_complete
from worker.execution_plan import (
    COLLECTION_TASK,
    build_collection_plan,
    index_controls,
)
from worker.lifecycle import ACTIVE, enqueue, fail_scan

logger = logging.getLogger(__name__)


def _pending_pairs(session, scan_id: int, metadata):
    """Pending selected results paired with their frozen control metadata."""
    rows = (
        session.execute(
            text("""SELECT id, control_id FROM scan_result
            WHERE scan_id=:id AND status='pending' AND selected IS TRUE
            ORDER BY id"""),
            {"id": scan_id},
        )
        .mappings()
        .all()
    )
    controls = index_controls(metadata)
    return [(dict(row), controls.get(row["control_id"], {})) for row in rows]


def _unclaimed_pending_plan(session, scan_id: int, metadata):
    """The groups this scan's outbox should hold, and the results it should not.

    "Unclaimed" is the whole point: a control that already has a live per-result
    row is served by that row, and must not also appear in a collection group.
    Without this a scan orchestrated by a pre-Phase-9 build and reconciled by
    this one would carry both, and the dispatcher would publish both -- two
    collections and two remote sessions against the tenant for one control's
    evidence. The result write is still first-write-wins, so only one assessment
    could land; the second collection is pure waste.

    Both the retire pass and the recreate pass read this, so they cannot
    disagree about which collections are still live.
    """
    claimed = set(
        session.execute(
            text(
                "SELECT result_id FROM scan_dispatch "
                "WHERE scan_id=:id AND result_id IS NOT NULL"
            ),
            {"id": scan_id},
        )
        .scalars()
        .all()
    )
    pairs = [
        (result, control)
        for result, control in _pending_pairs(session, scan_id, metadata)
        if result["id"] not in claimed
    ]
    return build_collection_plan(pairs)


def _retire_settled_collections(session, scan_id: int, metadata) -> None:
    """Drop collection rows with no pending member of their own left.

    The result-keyed DELETE above cannot see these: a collection row carries no
    result_id, so without this a finished group's row would survive until the
    scan itself finalised and would keep being republished in the meantime.
    """
    groups, _ = _unclaimed_pending_plan(session, scan_id, metadata)
    live = {group.collector_id for group in groups}
    rows = session.execute(
        text(
            "SELECT id, collector_id FROM scan_dispatch WHERE scan_id=:id AND collector_id IS NOT NULL"
        ),
        {"id": scan_id},
    ).all()
    settled = [row.id for row in rows if row.collector_id not in live]
    for dispatch_id in settled:
        session.execute(
            text("DELETE FROM scan_dispatch WHERE id=:id"), {"id": dispatch_id}
        )


def _recreate_pending_children(session, scan_id: int, metadata) -> None:
    """Rebuild the outbox for work that is still pending.

    Enqueue is idempotent on the deterministic identity, so re-running this is
    free. A pending result whose control cannot be planned -- not ready, no
    collector, corrupt or truncated metadata -- falls back to the Phase 6
    per-result row, which is exactly what would have been written before Phase 9:
    recovery must never lose a control because its metadata became unreadable.

    A control that ALREADY has a live per-result row is left to that row; see
    _unclaimed_pending_plan for why.
    """
    groups, unplannable = _unclaimed_pending_plan(session, scan_id, metadata)
    for group in groups:
        enqueue(session, scan_id, collector_id=group.collector_id)
    for result in unplannable:
        enqueue(session, scan_id, result["id"])


def reconcile():
    # List without child locks; every mutation acquires the parent first.
    with get_db_session() as session:
        ids = (
            session.execute(
                text(
                    "SELECT id FROM scan WHERE status IN ('pending','running') OR EXISTS (SELECT 1 FROM scan_dispatch d WHERE d.scan_id=scan.id) ORDER BY id"
                )
            )
            .scalars()
            .all()
        )
    for scan_id in ids:
        with get_db_session() as session:
            # PostgreSQL now() is timestamptz; these columns are TIMESTAMP WITHOUT
            # TIME ZONE. AT TIME ZONE 'UTC' pins the comparison to UTC on any server
            # timezone. Removing it reintroduces the Phase 6 non-UTC dispatcher failure.
            scan = (
                session.execute(
                    text("""SELECT *, (now() AT TIME ZONE 'UTC') >= COALESCE(deadline_at,
                last_progress_at + make_interval(secs => :deadline)) AS expired
                FROM scan WHERE id=:id FOR UPDATE SKIP LOCKED"""),
                    {"id": scan_id, "deadline": settings.SCAN_DEADLINE_SECONDS},
                )
                .mappings()
                .first()
            )
            if not scan:
                continue
            if scan["status"] not in ACTIVE:
                session.execute(
                    text("DELETE FROM scan_dispatch WHERE scan_id=:id"), {"id": scan_id}
                )
                continue
            if scan["expired"]:
                fail_scan(session, scan_id, "scan_deadline_exceeded")
                continue
            # Missing historical deadlines become fixed on the first recovery pass.
            session.execute(
                text("""UPDATE scan SET deadline_at=COALESCE(deadline_at,
                last_progress_at+make_interval(secs => :deadline)) WHERE id=:id"""),
                {"id": scan_id, "deadline": settings.SCAN_DEADLINE_SECONDS},
            )
            if scan["semantics_version"] != "phase3-v1":
                fail_scan(session, scan_id, "legacy_scan_context")
                continue
            # Remove acknowledged work before assessing retry exhaustion.
            #
            # A collection row is acknowledged when NONE of the controls it was
            # created for is still pending. It is deliberately not enough for one
            # of them to have finished: a group whose collection succeeded but
            # whose later members were interrupted still has work to redeliver.
            session.execute(
                text("""DELETE FROM scan_dispatch d WHERE d.scan_id=:id AND
                ((d.result_id IS NULL AND d.collector_id IS NULL AND :running) OR EXISTS
                 (SELECT 1 FROM scan_result r WHERE r.id=d.result_id AND r.status <> 'pending'))"""),
                {"id": scan_id, "running": scan["status"] == "running"},
            )
            _retire_settled_collections(session, scan_id, scan["metadata_snapshot"])
            if finalize_scan_if_complete(session, scan_id):
                session.execute(
                    text("DELETE FROM scan_dispatch WHERE scan_id=:id"), {"id": scan_id}
                )
                continue
            exhausted = session.execute(
                text("""SELECT 1 FROM scan_dispatch WHERE scan_id=:id
                AND attempts >= :max_attempts
                AND available_at <= (now() AT TIME ZONE 'UTC') LIMIT 1"""),
                {"id": scan_id, "max_attempts": settings.DISPATCH_MAX_ATTEMPTS},
            ).first()
            if exhausted:
                fail_scan(session, scan_id, "dispatch_retry_exhausted")
                continue
            if scan["status"] == "pending":
                enqueue(session, scan_id, dispatch_id=scan["dispatch_id"])
            else:
                _recreate_pending_children(session, scan_id, scan["metadata_snapshot"])


def publish_due():
    published = 0
    with get_db_session() as session:
        candidates = session.execute(
            text("""SELECT d.id, d.scan_id FROM scan_dispatch d
            JOIN scan s ON s.id=d.scan_id WHERE s.status IN ('pending','running')
            AND d.available_at <= (now() AT TIME ZONE 'UTC') AND d.attempts < :attempts
            ORDER BY d.available_at, d.id LIMIT :batch FOR UPDATE OF s SKIP LOCKED"""),
            {
                "attempts": settings.DISPATCH_MAX_ATTEMPTS,
                "batch": settings.DISPATCH_BATCH_SIZE,
            },
        ).all()
    for dispatch_id, scan_id in candidates:
        with get_db_session() as session:
            parent = session.execute(
                text("SELECT status FROM scan WHERE id=:id FOR UPDATE SKIP LOCKED"),
                {"id": scan_id},
            ).first()
            if not parent or parent.status not in ACTIVE:
                continue
            row = (
                session.execute(
                    text("""SELECT * FROM scan_dispatch WHERE id=:id
                AND available_at <= (now() AT TIME ZONE 'UTC')
                AND attempts < :attempts FOR UPDATE SKIP LOCKED"""),
                    {"id": dispatch_id, "attempts": settings.DISPATCH_MAX_ATTEMPTS},
                )
                .mappings()
                .first()
            )
            if not row:
                continue
            scan = get_scan(session, scan_id)
            if row["collector_id"] is not None:
                # A collection group. It is still live while any control that
                # names this collector is pending; when none is, the group has
                # been fully written and the row is dropped rather than resent.
                # Exactly the controls evaluate_collection will resolve: same
                # collector, and READY. A predicate that is wider than the task's
                # would keep republishing a group the task refuses, until the
                # scan failed on retry exhaustion.
                controls = index_controls(scan["metadata_snapshot"])
                live = session.execute(
                    text("""SELECT 1 FROM scan_result r
                    WHERE r.scan_id=:scan_id AND r.status='pending' AND r.selected IS TRUE
                    AND r.control_id = ANY(:control_ids) LIMIT 1"""),
                    {
                        "scan_id": scan_id,
                        "control_ids": [
                            control_id
                            for control_id, control in controls.items()
                            if control.get("data_collector_id") == row["collector_id"]
                            and control.get("automation_status", "ready") == "ready"
                        ],
                    },
                ).first()
                if not live:
                    session.execute(
                        text("DELETE FROM scan_dispatch WHERE id=:id"),
                        {"id": dispatch_id},
                    )
                    continue
                task_name = COLLECTION_TASK
                kwargs = {
                    "scan_id": scan_id,
                    "collector_id": row["collector_id"],
                    "connection_id": scan["m365_connection_id"],
                }
            elif row["result_id"] is None:
                if parent.status != "pending":
                    session.execute(
                        text("DELETE FROM scan_dispatch WHERE id=:id"),
                        {"id": dispatch_id},
                    )
                    continue
                task_name, kwargs = "worker.tasks.run_scan", {"scan_id": scan_id}
            else:
                pending = session.execute(
                    text(
                        "SELECT 1 FROM scan_result WHERE id=:id AND scan_id=:scan_id AND status='pending' AND selected IS TRUE"
                    ),
                    {"id": row["result_id"], "scan_id": scan_id},
                ).first()
                if not pending:
                    session.execute(
                        text("DELETE FROM scan_dispatch WHERE id=:id"),
                        {"id": dispatch_id},
                    )
                    continue
                task_name = "worker.tasks.evaluate_control"
                kwargs = {
                    "scan_id": scan_id,
                    "result_id": row["result_id"],
                    "connection_id": scan["m365_connection_id"],
                }
            attempts = row["attempts"] + 1
            error = None
            try:
                # The lock serializes cancellation/deletion with publication. A crash after
                # send but before commit may duplicate delivery; result writes are immutable.
                celery_app.send_task(
                    task_name,
                    kwargs=kwargs,
                    task_id=dispatch_id,
                    headers={"correlation_id": scan["correlation_id"]},
                    retry=False,
                )
            except Exception:
                error = "broker_unavailable"
            delay = (
                min(settings.DISPATCH_RETRY_SECONDS * (2 ** min(attempts - 1, 10)), 300)
                if error
                else settings.DISPATCH_STALL_SECONDS
            )
            session.execute(
                text("""UPDATE scan_dispatch SET attempts=:attempts,
                available_at=(now() AT TIME ZONE 'UTC')+make_interval(secs => :delay),
                last_error=:error, dispatched_at=CASE WHEN :ok
                THEN (now() AT TIME ZONE 'UTC') ELSE dispatched_at END WHERE id=:id"""),
                {
                    "id": dispatch_id,
                    "attempts": attempts,
                    "delay": delay,
                    "error": error,
                    "ok": error is None,
                },
            )
            if error is None:
                published += 1
                session.execute(
                    text(
                        "UPDATE scan SET dispatch_count=dispatch_count+1 WHERE id=:id"
                    ),
                    {"id": scan_id},
                )
    return published


def collect_metrics(*, cycle_failed: bool = False):
    """Refresh the exported gauges from the same tables this loop already reads.

    Deliberately outside ``tick``: a metrics read must never be able to fail a
    dispatch cycle, and a dispatch cycle that raises must still leave the
    exporter reporting why. ``metrics.collect`` swallows its own errors and
    lowers ``autoaudit_collector_exporter_up`` rather than propagating.

    ``cycle_failed`` is why this is called after a failed tick as well as a
    successful one. Opening a fresh session usually fails too when the cycle
    failed for database reasons, which lowers the gauge on its own -- but a cycle
    can fail for reasons a fresh session would not reproduce (a broker error, a
    single locked scan), and in that case the gauge must still be lowered
    explicitly rather than left reporting healthy.
    """
    try:
        with get_db_session() as session:
            metrics.collect(session)
    except Exception:  # pylint: disable=broad-exception-caught
        # Could not even open a session. Never log exception text.
        metrics.collector_exporter_up.set(0)
        logger.error("dispatcher_metrics_session_failed")
        return
    if cycle_failed:
        metrics.collector_exporter_up.set(0)


def tick():
    reconcile()
    published = publish_due()
    return published


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    # Also accept the convenient positional form documented in runbooks.
    parser.add_argument("mode", nargs="?", choices=["once"])
    args = parser.parse_args()
    once = args.once or args.mode == "once"

    # The dispatcher is the one supervised, single-threaded process that already
    # polls these tables, which makes it the only place a database-derived gauge
    # can be sampled consistently. A single pass is a diagnostic run, not a
    # service, so it starts no server.
    if not once and settings.METRICS_PORT:
        # addr is explicit rather than inherited. The DEFAULT is still 0.0.0.0,
        # which inside a container on the private network is correct and is what
        # a Prometheus scrape needs -- this does not narrow it. What it does is
        # make the bind a stated, overridable decision, so a host-networked
        # deployment can set METRICS_BIND to a loopback or private address
        # without patching code. Saying it "prevents" exposure would be false.
        start_http_server(
            settings.METRICS_PORT,
            addr=settings.METRICS_BIND,
            registry=metrics.REGISTRY,
        )
        logger.info("dispatcher_metrics_listening port=%s", settings.METRICS_PORT)

    while True:
        failed = False
        try:
            tick()
        except Exception:
            # Never log exception text: URLs/drivers may include authentication data.
            failed = True
            logger.error("dispatcher_cycle_failed")
            if once:
                raise SystemExit(1) from None

        if not once:
            # Deliberately OUTSIDE the else: a failed cycle is exactly when the
            # exporter must be sampled, because that is when it needs to report
            # itself down. An earlier version refreshed only after a successful
            # tick, so a database outage left the HTTP server happily serving a
            # stale `autoaudit_collector_exporter_up 1` -- and ScanExporterDown,
            # the alert that exists to catch a dead dispatcher, could never fire.
            # Found by the independent review pass.
            #
            # `collect_metrics` opens its own session and swallows its own
            # errors, lowering the gauge rather than propagating, so calling it
            # here cannot turn a metrics problem into a dispatch failure.
            collect_metrics(cycle_failed=failed)

        if once:
            return
        time.sleep(settings.DISPATCH_POLL_SECONDS)


if __name__ == "__main__":
    main()
