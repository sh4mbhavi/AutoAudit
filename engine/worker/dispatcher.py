"""Broker-independent outbox publisher and reconciler.

Run ``python -m worker.dispatcher --once`` for a single pass, or omit --once
for the supervised polling service. PostgreSQL owns retry state; no Beat or
Celery delivery is needed to recover from broker/process outages.
"""

import argparse
import logging
import time

from sqlalchemy import text

from worker.celery_app import celery_app
from worker.config import settings
from worker.db import get_db_session, get_scan, finalize_scan_if_complete
from worker.lifecycle import ACTIVE, enqueue, fail_scan

logger = logging.getLogger(__name__)


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
            scan = (
                session.execute(
                    text("""SELECT *, now() >= COALESCE(deadline_at,
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
            session.execute(
                text("""DELETE FROM scan_dispatch d WHERE d.scan_id=:id AND
                ((d.result_id IS NULL AND :running) OR EXISTS
                 (SELECT 1 FROM scan_result r WHERE r.id=d.result_id AND r.status <> 'pending'))"""),
                {"id": scan_id, "running": scan["status"] == "running"},
            )
            if finalize_scan_if_complete(session, scan_id):
                session.execute(
                    text("DELETE FROM scan_dispatch WHERE scan_id=:id"), {"id": scan_id}
                )
                continue
            exhausted = session.execute(
                text("""SELECT 1 FROM scan_dispatch WHERE scan_id=:id
                AND attempts >= :max_attempts AND available_at <= now() LIMIT 1"""),
                {"id": scan_id, "max_attempts": settings.DISPATCH_MAX_ATTEMPTS},
            ).first()
            if exhausted:
                fail_scan(session, scan_id, "dispatch_retry_exhausted")
                continue
            if scan["status"] == "pending":
                enqueue(session, scan_id, dispatch_id=scan["dispatch_id"])
            else:
                pending = session.execute(
                    text(
                        "SELECT id FROM scan_result WHERE scan_id=:id AND status='pending' AND selected IS TRUE"
                    ),
                    {"id": scan_id},
                ).scalars()
                for result_id in pending:
                    enqueue(session, scan_id, result_id)


def publish_due():
    published = 0
    with get_db_session() as session:
        candidates = session.execute(
            text("""SELECT d.id, d.scan_id FROM scan_dispatch d
            JOIN scan s ON s.id=d.scan_id WHERE s.status IN ('pending','running')
            AND d.available_at <= now() AND d.attempts < :attempts
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
                AND available_at <= now() AND attempts < :attempts FOR UPDATE SKIP LOCKED"""),
                    {"id": dispatch_id, "attempts": settings.DISPATCH_MAX_ATTEMPTS},
                )
                .mappings()
                .first()
            )
            if not row:
                continue
            scan = get_scan(session, scan_id)
            if row["result_id"] is None:
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
                available_at=now()+make_interval(secs => :delay), last_error=:error,
                dispatched_at=CASE WHEN :ok THEN now() ELSE dispatched_at END WHERE id=:id"""),
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


def tick():
    reconcile()
    return publish_due()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    # Also accept the convenient positional form documented in runbooks.
    parser.add_argument("mode", nargs="?", choices=["once"])
    args = parser.parse_args()
    while True:
        try:
            tick()
        except Exception:
            # Never log exception text: URLs/drivers may include authentication data.
            logger.error("dispatcher_cycle_failed")
            if args.once or args.mode == "once":
                raise SystemExit(1) from None
        if args.once or args.mode == "once":
            return
        time.sleep(settings.DISPATCH_POLL_SECONDS)


if __name__ == "__main__":
    main()
