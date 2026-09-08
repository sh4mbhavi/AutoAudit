"""Database-only lifecycle primitives; never publish inside orchestration."""

import json
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import text

from worker.db import (
    finalize_scan_if_complete,
    lock_scan,
    get_scan,
    get_pending_scan_results,
)
from worker.provenance import initial_provenance

ACTIVE = {"pending", "running"}
TERMINAL = {"completed", "failed", "cancelled"}


def enqueue(
    session, scan_id: int, result_id: int | None = None, dispatch_id: str | None = None
):
    """Deterministic row identity makes orchestration and recovery replay safe."""
    identity = dispatch_id or str(
        uuid5(NAMESPACE_URL, f"autoaudit:scan:{scan_id}:result:{result_id}")
    )
    session.execute(
        text("""
        INSERT INTO scan_dispatch (id, scan_id, result_id, task_name)
        VALUES (:id, :scan_id, :result_id, :task_name) ON CONFLICT (id) DO NOTHING
    """),
        {
            "id": identity,
            "scan_id": scan_id,
            "result_id": result_id,
            "task_name": "worker.tasks.run_scan"
            if result_id is None
            else "worker.tasks.evaluate_control",
        },
    )


def fail_scan(session, scan_id: int, reason_code: str):
    """Finish unresolved work without inventing compliance outcomes."""
    scan = lock_scan(session, scan_id)
    if not scan or scan["status"] not in ACTIVE:
        return False
    context = get_scan(session, scan_id)
    legacy = context["semantics_version"] != "phase3-v1"
    if legacy:
        reason_code = "legacy_scan_context"
    metadata = {} if legacy else (context.get("metadata_snapshot") or {})
    entries = metadata.get("controls") if isinstance(metadata, dict) else []
    controls = {
        c["control_id"]: c
        for c in (entries if isinstance(entries, list) else [])
        if isinstance(c, dict) and isinstance(c.get("control_id"), str)
    }
    for result in get_pending_scan_results(session, scan_id):
        control = controls.get(
            result["control_id"], {"control_id": result["control_id"]}
        )
        provenance = initial_provenance(
            context["framework"],
            context["benchmark"],
            context["version"],
            control,
            {} if legacy else context,
        )
        if legacy:
            provenance["provenance_status"] = "legacy_unknown"
        # Recovery closes unresolved execution even when old selection attribution
        # is NULL. Keep that attribution unchanged; ordinary assessment writes still
        # require selected=TRUE. The parent lock and pending predicate protect both
        # legacy and versioned terminal rows from concurrent/duplicate deliveries.
        session.execute(
            text("""
            UPDATE scan_result SET status='error', reason_code=:reason,
                message='Scan execution could not finish; no assessment was recorded.',
                provenance=CAST(:provenance AS jsonb), updated_at=now()
            WHERE id=:id AND scan_id=:scan_id AND status='pending'
        """),
            {
                "id": result["id"],
                "scan_id": scan_id,
                "reason": reason_code,
                "provenance": json.dumps(provenance),
            },
        )
    complete = finalize_scan_if_complete(session, scan_id, final_status="failed")
    if not complete:
        return False
    if context["selected_count"] is None:
        # Historical outcomes cannot establish Phase 3 assessment/coverage scores.
        session.execute(
            text("""UPDATE scan SET compliance_score=NULL,
            coverage_score=NULL WHERE id=:id"""),
            {"id": scan_id},
        )
    session.execute(
        text("DELETE FROM scan_dispatch WHERE scan_id=:id"), {"id": scan_id}
    )
    return True
