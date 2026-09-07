"""Celery tasks for compliance scanning."""

import asyncio
import hashlib
import logging


from worker.celery_app import celery_app
from worker.config import settings
from worker.result_contract import OPAResult
from worker.provenance import (
    initial_provenance,
    capture_policy,
    engine_identity,
    canonical_digest,
    utc_now,
)

from worker.db import (
    get_db_session,
    get_scan,
    lock_scan,
    get_collection_results,
    get_execution_result,
    get_execution_credentials,
    get_pending_scan_results,
    update_scan_status,
    update_scan_result,
    finalize_scan_if_complete,
)

from worker.execution_plan import (
    PlannedControl,
    build_collection_plan,
    index_controls,
)

from worker.lifecycle import TERMINAL, enqueue, fail_scan

from worker.factprint import project_facts, persist_factprint

# Imported as a module so drift can be replaced wholesale in a test without
# rebinding a name this module resolved at import time.
from worker import drift as drift_module


logger = logging.getLogger(__name__)


def powershell_enabled(collector_id: str) -> bool:
    """False only when this is a PowerShell collector and PowerShell is disabled."""
    from collectors.routing import uses_powershell

    return settings.ENABLE_POWERSHELL_CONTROLS or not uses_powershell(collector_id)


def _drift_after_finalisation(scan_id: int, completed: bool) -> None:
    """Drift is computed on finalisation. A drift failure never affects a scan."""
    if not completed:
        return
    try:
        with get_db_session() as session:
            drift_module.evaluate_scan_drift(session, scan_id, trigger="scan_finalised")
    except Exception:
        # Never log exception text: URLs/drivers may include authentication data.
        logger.error("drift_cycle_failed scan_id=%s", scan_id)


class EvaluationFailure(Exception):
    """Redacted execution failure with the provenance captured before failure.

    ``provenances`` maps control_id to that control's provenance record: one
    shared collection can fail for several controls at once, and each of them
    still owns its own audit record. ``provenance`` remains the first (and, for a
    single-control group, the only) record, so every existing caller and test
    that reads ``.provenance`` is unchanged.

    ``retryable`` is False for a failure a retry cannot change -- an
    authorization or invalid-request answer from the tenant, a collector error
    envelope, malformed evidence, a missing policy file. Phase 9's anti-pattern
    guard is explicit that those must not be retried: today a tenant whose Global
    Administrator role object is absent costs four full collections and four
    minutes of Celery backoff before settling on the same terminal error.
    """

    def __init__(
        self,
        reason_code: str,
        provenance: dict,
        provenances: dict | None = None,
        retryable: bool = True,
        reason_codes: dict | None = None,
    ):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.provenance = provenance
        self.provenances = provenances or {}
        # Per control, where the members of a group failed for different
        # reasons. A group failure carries one headline reason_code, but each
        # control's row must record why THAT control failed: a control whose
        # policy file is missing is `provenance_unavailable`, not the
        # `evaluation_error` of whichever control happened to be listed first.
        self.reason_codes = reason_codes or {}
        self.retryable = retryable

    def reason_for(self, control_id: str) -> str:
        return self.reason_codes.get(control_id, self.reason_code)


# Deterministic HTTP answers about the request or the caller's authorization.
# A retry produces the same status and spends another tenant request doing it.
#
# 401 is deliberately absent from Phase 9's list even though it is a 4xx: the
# pooled client caches one token for a whole collection group, so a token that
# expires mid-group presents as 401 and a fresh attempt acquires a new one.
NON_RETRYABLE_STATUS = frozenset({400, 403, 404, 405, 409, 410, 422})


def _is_retryable(exc: BaseException, stage: str = "collection") -> bool:
    """Whether re-running this stage could plausibly succeed.

    The stage matters, and getting it wrong in either direction is a real
    defect. A blanket "ValueError is deterministic" rule is wrong for the
    evaluation stage: ``opa_client._execute`` raises a bare ValueError for ANY
    non-zero exit of the ``opa`` subprocess, including a transient one, so that
    rule would write a permanent error row for a momentary OPA blip. A blanket
    "retry everything" rule is wrong for the collection stage, which is where
    the anti-pattern guard applies: an authorization answer, an invalid request
    or a collector error envelope is deterministic and retrying it only spends
    more tenant requests arriving at the same error.
    """
    import httpx

    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code not in NON_RETRYABLE_STATUS
    if stage == "provenance_unavailable":
        # A missing or unreadable policy file. Nothing about a retry changes it.
        return False
    if stage == "evaluation_error":
        # OPA is a subprocess (or a service). Its failures are not our
        # validation of the evidence, and they are not deterministic.
        return True
    # Collection stage. Every ValueError here is our own validation of the
    # evidence or the operation registry -- all deterministic.
    return not isinstance(exc, ValueError)


def get_control_metadata(metadata: dict, control_id: str) -> dict | None:
    """Get control metadata by control_id from the metadata dict."""
    for control in metadata.get("controls", []):
        if control["control_id"] == control_id:
            return control
    return None


@celery_app.task(name="worker.tasks.evaluate_drift")
def evaluate_drift(baseline_id: int, scan_id: int) -> dict:
    """Compare one completed scan against one baseline, on explicit request.

    backend-api/app/services/drift.py:queue_drift_run sends this name; the
    endpoint is a no-op unless the worker registers it, so the name is a
    contract between the two and is asserted by
    engine/tests/test_phase8_worker_drift_hook.py.

    Drift is computed in exactly one place -- worker.drift -- and the run's
    UNIQUE (baseline_id, current_scan_id) makes a duplicate delivery a no-op
    rather than a second run, so this task is safely redeliverable.
    """
    if type(baseline_id) is not int or baseline_id <= 0:
        raise ValueError("Invalid baseline identifier")
    if type(scan_id) is not int or scan_id <= 0:
        raise ValueError("Invalid scan identifier")
    with get_db_session() as session:
        return drift_module.evaluate_scan_drift(
            session, scan_id, trigger="api_request", baseline_id=baseline_id
        )


@celery_app.task(name="worker.tasks.run_scan")
def run_scan(scan_id: int) -> dict:
    """Build durable child work atomically with the pending-to-running transition."""
    if type(scan_id) is not int or scan_id <= 0:
        raise ValueError("Invalid scan identifier")
    with get_db_session() as session:
        parent = lock_scan(session, scan_id)
        if not parent:
            return {"scan_id": scan_id, "status": "ignored"}
        scan = get_scan(session, scan_id)
        logger.info(
            "scan_dispatch_started scan_id=%s correlation_id=%s",
            scan_id,
            scan.get("correlation_id") if scan else None,
        )
        if not scan or scan["status"] in TERMINAL:
            return {"scan_id": scan_id, "status": scan["status"] if scan else "ignored"}
        if scan["semantics_version"] != "phase3-v1":
            fail_scan(session, scan_id, "legacy_scan_context")
            return {"scan_id": scan_id, "status": "failed"}
        metadata = scan["metadata_snapshot"]
        if canonical_digest(metadata) != scan["metadata_digest"]:
            fail_scan(session, scan_id, "metadata_digest_mismatch")
            return {"scan_id": scan_id, "status": "failed"}
        update_scan_status(session, scan_id, status="running")
        context = {
            "metadata_digest": scan["metadata_digest"],
            "correlation_id": scan["correlation_id"],
        }
        not_assessable = 0
        dispatchable: list[tuple[dict, dict]] = []
        for result in get_pending_scan_results(session, scan_id):
            control = get_control_metadata(metadata, result["control_id"])
            reason = None
            outcome = "error"
            if not control:
                reason = "metadata_control_missing"
            elif control.get("automation_status", "ready") != "ready":
                reason, outcome = "not_automated", "not_assessable"
            else:
                collector_id = control.get("data_collector_id")
                if not isinstance(collector_id, str) or not collector_id:
                    # Non-string as well as empty: `or ""` accepted any truthy
                    # value, and uses_powershell short-circuits on isinstance,
                    # so a list or an int reached dispatch as an unroutable id.
                    collector_id = ""
                    reason = "collector_not_configured"
                elif not powershell_enabled(collector_id):
                    reason, outcome = "automation_disabled", "not_assessable"
            if reason:
                update_scan_result(
                    session,
                    result_id=result["id"],
                    status=outcome,
                    message="Selected control could not be assessed automatically.",
                    reason_code=reason,
                    provenance=initial_provenance(
                        scan["framework"],
                        scan["benchmark"],
                        scan["version"],
                        control or {"control_id": result["control_id"]},
                        context,
                    ),
                )
                not_assessable += outcome == "not_assessable"
            else:
                dispatchable.append((result, control))
        # Phase 9: the unit of durable work is a collection, not a control. One
        # outbox row per distinct collector, fanned out to every control that
        # names it, so 69 ready controls cost 43 collections instead of 69.
        groups, unplannable = build_collection_plan(dispatchable)
        for group in groups:
            enqueue(session, scan_id, collector_id=group.collector_id)
        for result in unplannable:  # pragma: no cover - rejected above already
            enqueue(session, scan_id, result["id"])
        dispatched = sum(len(group.members) for group in groups) + len(unplannable)
        complete = finalize_scan_if_complete(session, scan_id)
        summary = {
            "scan_id": scan_id,
            "status": "completed" if complete else "running",
            "dispatched": dispatched,
            "collections": len(groups),
            "not_assessable": not_assessable,
        }
    # Outside the session block: the finalisation is committed before drift reads it.
    _drift_after_finalisation(scan_id, complete)
    return summary


def _frozen_context(session, scan_id: int, connection_id: int) -> tuple[dict, dict]:
    """Re-verify the frozen execution context before any collector runs.

    Identical to the Phase 3/5 checks the per-control task performed; hoisted so
    the control task and the collection task cannot drift apart.
    """
    scan = get_scan(session, scan_id)
    if not scan:
        raise LookupError("Execution context unavailable")
    if scan["m365_connection_id"] != connection_id:
        raise ValueError("Execution context unavailable")
    metadata = scan["metadata_snapshot"]
    if (
        scan["semantics_version"] != "phase3-v1"
        or canonical_digest(metadata) != scan["metadata_digest"]
    ):
        raise ValueError("Frozen execution context invalid")
    return scan, metadata


def _scan_identity(scan: dict) -> tuple[str, str, str, dict]:
    framework, benchmark, version = (
        scan[key] for key in ("framework", "benchmark", "version")
    )
    return (
        framework,
        benchmark,
        version,
        {
            "metadata_digest": scan["metadata_digest"],
            "correlation_id": scan["correlation_id"],
        },
    )


MESSAGES = {
    "passed": "Evidence satisfies the control.",
    "failed": "Evidence demonstrates a control violation.",
    "indeterminate": "Evidence is insufficient or ambiguous; no assessment was possible.",
}


def _persist_outcome(
    session,
    result_id: int,
    control_id: str,
    collector_id: str,
    scan_id: int,
    outcome: dict,
) -> tuple[bool, "OPAResult"]:
    """Write one control's assessment and, only if that write won, its factprint."""
    provenance = outcome.pop("provenance", None)
    # OPAResult forbids extra keys, so the projection is removed before
    # validation. A failed, unverified or unusable collection never carries one.
    factprint = outcome.pop("factprint", None)
    validated = OPAResult.model_validate(outcome)
    reason = (
        "insufficient_evidence"
        if validated.compliant is None
        else "policy_satisfied"
        if validated.compliant
        else "policy_violation"
    )
    if validated.compliant is None and provenance and provenance.get("reason_code"):
        reason = provenance["reason_code"]
    changed = update_scan_result(
        session,
        result_id=result_id,
        status=validated.status,
        message=MESSAGES[validated.status],
        evidence={"affected_resource_count": len(validated.affected_resources)},
        reason_code=reason,
        provenance=provenance,
    )
    if changed and factprint:
        # Same session, same transaction, gated on first-write-wins: a
        # redelivered message can never add a second observation.
        persist_factprint(
            session,
            scan_id=scan_id,
            control_id=control_id,
            collector_id=collector_id,
            fields=factprint,
        )
    return changed, validated


def _run_collection(
    task,
    scan_id: int,
    connection_id: int,
    collector_id: str,
    members: list[PlannedControl],
    scan: dict,
) -> dict:
    """Collect once, fan the evidence out to every member, write each result.

    This is the whole Phase 9 execution change. Everything the per-control task
    did is still done per control -- its own policy capture, its own OPA
    evaluation, its own provenance record, its own factprint row, its own
    first-write-wins result row. What is done once is the collection.
    """
    framework, benchmark, version, scan_context = _scan_identity(scan)
    credentials: dict = {}
    try:
        with get_db_session() as session:
            credentials = get_execution_credentials(session, scan_id, connection_id)
        # A group of one goes through the single-control entry point, which is a
        # pure delegation to the group helper. Same code, one extra frame -- and
        # it keeps _evaluate_control_async the seam it has been since Phase 3,
        # rather than leaving a public name nothing calls.
        if len(members) == 1:
            member = members[0]
            outcomes = asyncio.run(
                _run_single(
                    control_id=member.control_id,
                    collector_id=collector_id,
                    policy_file=member.policy_file,
                    credentials=credentials,
                    framework=framework,
                    benchmark=benchmark,
                    version=version,
                    scan_context=scan_context,
                )
            )
        else:
            outcomes = asyncio.run(
                _evaluate_collection_async(
                    collector_id=collector_id,
                    members=[(m.control_id, m.policy_file) for m in members],
                    credentials=credentials,
                    framework=framework,
                    benchmark=benchmark,
                    version=version,
                    scan_context=scan_context,
                )
            )
        written = 0
        assessments: dict[str, dict] = {}
        # A member whose own failure is recoverable must not be written
        # terminally just because its siblings succeeded. The successes are
        # written first -- they are already durable and first-write-wins makes
        # the retry's repeat of them a no-op -- and then the group is failed so
        # the retry budget applies to the member that could still be assessed.
        recoverable = [
            member
            for member in members
            if isinstance(outcomes.get(member.control_id), EvaluationFailure)
            and outcomes[member.control_id].retryable
        ]
        with get_db_session() as session:
            for member in members:
                outcome = outcomes.get(member.control_id)
                if outcome is None:  # pragma: no cover - defensive
                    continue
                if isinstance(outcome, EvaluationFailure):
                    if member in recoverable:
                        continue
                    # A policy-specific failure inside an otherwise successful
                    # collection. Its siblings judged the same evidence with the
                    # same OPA, so re-running the group cannot change this one.
                    written += update_scan_result(
                        session,
                        result_id=member.result_id,
                        status="error",
                        message="Control execution failed; no compliance assessment was recorded.",
                        reason_code=outcome.reason_code,
                        provenance=outcome.provenance,
                    )
                    assessments[member.control_id] = {
                        "compliant": None,
                        "status": "error",
                    }
                    continue
                changed, validated = _persist_outcome(
                    session,
                    member.result_id,
                    member.control_id,
                    collector_id,
                    scan_id,
                    dict(outcome),
                )
                written += changed
                assessments[member.control_id] = {
                    "compliant": validated.compliant,
                    "status": validated.status,
                }
            completed = finalize_scan_if_complete(session, scan_id)
        # Outside the session block: the result writes are committed before
        # drift reads them.
        _drift_after_finalisation(scan_id, completed)
        if recoverable:
            # The successes above are committed. Fail so the recoverable
            # members get the retry budget; on exhaustion the terminal branch
            # below writes them, and first-write-wins keeps the successes.
            first = outcomes[recoverable[0].control_id]
            raise EvaluationFailure(
                first.reason_code,
                first.provenance,
                {
                    member.control_id: outcomes[member.control_id].provenance
                    for member in recoverable
                },
                retryable=True,
                reason_codes={
                    member.control_id: outcomes[member.control_id].reason_code
                    for member in recoverable
                },
            )
        return {
            "scan_id": scan_id,
            "collector_id": collector_id,
            "controls": len(members),
            "written": written,
            "assessments": assessments,
            "status": "recorded" if written else "ignored",
        }
    except Exception as exc:
        retryable = _is_retryable(exc)
        if isinstance(exc, EvaluationFailure):
            retryable = exc.retryable
            # On exhaustion only the members that still have no result are
            # written; the ones already written are protected by
            # first-write-wins either way, but naming them here keeps the
            # terminal record to the controls this failure is actually about.
            if exc.provenances:
                members = [
                    member for member in members if member.control_id in exc.provenances
                ] or members
        exhausted = (
            task.max_retries is not None and task.request.retries >= task.max_retries
        )
        if retryable and not exhausted:
            raise task.retry(exc=RuntimeError("Control execution failed")) from None
        # Terminal. Every control that depended on this collection gets its own
        # error row with its own provenance -- a shared collection fans its
        # failure out exactly as it fans its evidence out.
        #
        # The message says what actually happened: "after retries" is only true
        # when the retry budget was spent. A deterministic failure is refused on
        # the first attempt, and saying otherwise would misdescribe the record.
        message = (
            "Control execution failed after retries; no compliance assessment was recorded."
            if retryable
            else "Control execution failed; no compliance assessment was recorded."
        )
        with get_db_session() as session:
            written = 0
            for member in members:
                provenance = (
                    exc.provenances.get(member.control_id) or exc.provenance
                    if isinstance(exc, EvaluationFailure)
                    else initial_provenance(
                        framework,
                        benchmark,
                        version,
                        {
                            "control_id": member.control_id,
                            "data_collector_id": collector_id,
                            "policy_file": member.policy_file,
                        },
                        scan_context,
                    )
                )
                written += update_scan_result(
                    session,
                    result_id=member.result_id,
                    status="error",
                    message=message,
                    reason_code=exc.reason_for(member.control_id)
                    if isinstance(exc, EvaluationFailure)
                    else "evaluation_error",
                    provenance=provenance,
                )
            completed = finalize_scan_if_complete(session, scan_id)
            session.commit()
        # Outside the session block, exactly as the success path does: the
        # result write is committed before drift reads it. Without this a scan
        # whose LAST collection exhausts its retries is finalised and never
        # compared, so whether drift runs at all would depend on which
        # collection happened to finish last.
        _drift_after_finalisation(scan_id, completed)
        return {
            "scan_id": scan_id,
            "collector_id": collector_id,
            "controls": len(members),
            "written": written,
            "assessments": {
                member.control_id: {"compliant": None, "status": "error"}
                for member in members
            },
            "status": "error" if written else "ignored",
            "error": "Control execution failed",
        }
    finally:
        credentials.clear()


@celery_app.task(
    name="worker.tasks.evaluate_collection",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def evaluate_collection(
    self,
    scan_id: int,
    collector_id: str,
    connection_id: int,
) -> dict:
    """Evaluate every pending control that shares one collector's evidence.

    The broker message stays identifier-only: a scan id, a registered collector
    id and a connection id. No evidence, no credential and no metadata crosses
    it, exactly as the per-control message never did.
    """
    if any(type(value) is not int or value <= 0 for value in (scan_id, connection_id)):
        raise ValueError("Invalid execution identifiers")
    if type(collector_id) is not str or not collector_id or len(collector_id) > 200:
        raise ValueError("Invalid collector identifier")
    try:
        with get_db_session() as session:
            scan = get_scan(session, scan_id)
    except Exception:
        raise self.retry(exc=RuntimeError("Execution context unavailable")) from None
    if not scan:
        return {"scan_id": scan_id, "collector_id": collector_id, "status": "ignored"}
    if scan["status"] in TERMINAL:
        return {"scan_id": scan_id, "collector_id": collector_id, "status": "ignored"}
    with get_db_session() as session:
        scan, metadata = _frozen_context(session, scan_id, connection_id)
        controls = {
            control_id: control
            for control_id, control in index_controls(metadata).items()
            if control.get("data_collector_id") == collector_id
            and control.get("automation_status", "ready") == "ready"
        }
        rows = get_collection_results(session, scan_id, sorted(controls))
    if not controls:
        raise ValueError("Control execution unavailable")
    members = [
        PlannedControl(
            result_id=row["id"],
            control_id=row["control_id"],
            policy_file=controls[row["control_id"]].get("policy_file"),
        )
        for row in rows
    ]
    if not members:
        return {"scan_id": scan_id, "collector_id": collector_id, "status": "ignored"}
    logger.info(
        "collection_started scan_id=%s collector_id=%s controls=%s correlation_id=%s",
        scan_id,
        collector_id,
        len(members),
        scan["correlation_id"],
    )
    return _run_collection(self, scan_id, connection_id, collector_id, members, scan)


@celery_app.task(
    name="worker.tasks.evaluate_control",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def evaluate_control(
    self,
    scan_id: int,
    result_id: int,
    connection_id: int,
) -> dict:
    """Evaluate one control. A collection group of exactly one.

    Retained after Phase 9 moved orchestration onto collection groups: an outbox
    row written before the deploy still names this task, and a redelivery of one
    must not be stranded. The execution path is the shared one, so a single
    control cannot diverge from a fanned-out one.
    """
    if any(
        type(value) is not int or value <= 0
        for value in (scan_id, result_id, connection_id)
    ):
        raise ValueError("Invalid execution identifiers")
    try:
        with get_db_session() as session:
            scan = get_scan(session, scan_id)
            execution = get_execution_result(session, scan_id, result_id)
    except Exception:
        raise self.retry(exc=RuntimeError("Execution context unavailable")) from None
    if not scan or not execution:
        return {"scan_id": scan_id, "result_id": result_id, "status": "ignored"}
    if scan["m365_connection_id"] != connection_id:
        raise ValueError("Execution context unavailable")
    if (
        execution["status"] != "pending"
        or not execution["selected"]
        or scan["status"] in TERMINAL
    ):
        return {"scan_id": scan_id, "result_id": result_id, "status": "ignored"}
    logger.info(
        "control_started scan_id=%s result_id=%s correlation_id=%s",
        scan_id,
        result_id,
        scan["correlation_id"],
    )
    metadata = scan["metadata_snapshot"]
    if (
        scan["semantics_version"] != "phase3-v1"
        or canonical_digest(metadata) != scan["metadata_digest"]
    ):
        raise ValueError("Frozen execution context invalid")
    control = get_control_metadata(metadata, execution["control_id"])
    if not control or control.get("automation_status", "ready") != "ready":
        raise ValueError("Control execution unavailable")
    member = PlannedControl(
        result_id=result_id,
        control_id=control["control_id"],
        policy_file=control.get("policy_file"),
    )
    outcome = _run_collection(
        self,
        scan_id,
        connection_id,
        control.get("data_collector_id"),
        [member],
        scan,
    )
    if outcome["status"] == "ignored":
        return {"scan_id": scan_id, "result_id": result_id, "status": "ignored"}
    assessment = outcome["assessments"].get(member.control_id) or {
        "compliant": None,
        "status": "error",
    }
    if outcome["status"] == "error" or assessment["status"] == "error":
        return {
            "control_id": member.control_id,
            "compliant": None,
            "status": "error",
            "error": "Control execution failed",
        }
    return {
        "control_id": member.control_id,
        "compliant": assessment["compliant"],
        "status": assessment["status"],
    }


def _package_path(framework: str, benchmark: str, version: str, control_id: str) -> str:
    """Build the OPA package path from the frozen benchmark identity.

    Rego package: "cis.microsoft_365_foundations.v3_1_0.control_1_1_1"
    OPA REST API path: "cis/microsoft_365_foundations/v3_1_0/control_1_1_1"

    - framework: "essential-eight" -> "essential_eight"
    - benchmark: "microsoft-365-foundations" -> "microsoft_365_foundations"
    - version: "v3.1.0" -> "v3_1_0"
    - control_id: "1.1.1" -> "control_1_1_1", "E8-MAC-2.1" -> "control_e8_mac_2_1"
    """
    control_suffix = control_id.replace(".", "_").replace("-", "_").lower()
    return "/".join(
        (
            framework.replace("-", "_"),
            benchmark.replace("-", "_"),
            version.replace(".", "_"),
            f"control_{control_suffix}",
        )
    )


async def _run_single(control_id: str, **kwargs) -> dict:
    """Adapt the single-control entry point to the group result shape."""
    return {control_id: await _evaluate_control_async(control_id=control_id, **kwargs)}


async def _evaluate_collection_async(
    collector_id: str,
    members: list[tuple[str, str | None]],
    credentials: dict,
    framework: str,
    benchmark: str,
    version: str,
    scan_context: dict | None = None,
) -> dict:
    """Collect once for ``collector_id``; evaluate every member's own policy.

    Returns control_id -> either a result payload or an EvaluationFailure that is
    specific to that control's policy. Raises EvaluationFailure when the failure
    belongs to the whole group -- the collection itself, or an evaluator that
    failed for every member -- because that is the case a retry can address.

    What is shared: the client, the token, the engine identity, the collection
    and its input digest, and the declared scalar projection of that collection.
    What stays per control: the policy source and digest, the OPA evaluation, the
    evaluation timestamps, the provenance record and the result row.
    """
    # Import here to avoid circular imports
    from collectors.registry import get_collector
    from collectors.graph_client import GraphClient
    from collectors.powershell_client import PowerShellClient
    from collectors.routing import uses_powershell
    from opa_client import opa_client
    from worker.correlation import request_id, safe_request_id, event

    correlation_token = request_id.set(
        safe_request_id((scan_context or {}).get("correlation_id"))
    )

    order = [control_id for control_id, _ in members]
    policies = dict(members)
    provenances = {
        control_id: initial_provenance(
            framework,
            benchmark,
            version,
            {
                "control_id": control_id,
                "data_collector_id": collector_id,
                "policy_file": policy_file,
            },
            scan_context,
        )
        for control_id, policy_file in members
    }
    reason = "provenance_unavailable"
    client = None
    try:
        # One identity for one collection: every control judged on this evidence
        # was executed by this engine, at this moment, in one process.
        identity = engine_identity()
        sources: dict[str, str] = {}
        capture_failed: set[str] = set()
        for control_id in order:
            provenance = provenances[control_id]
            provenance.update(identity)
            try:
                source = capture_policy(
                    framework, benchmark, version, policies[control_id]
                )
            except Exception:
                # A missing or malformed policy file belongs to one control.
                capture_failed.add(control_id)
                continue
            sources[control_id] = source
            provenance.update(
                policy_source=source,
                policy_digest=hashlib.sha256(source.encode()).hexdigest(),
            )
        if len(capture_failed) == len(order):
            raise ValueError("Invalid policy path")

        reason = "collection_error"
        started_at = utc_now()
        for provenance in provenances.values():
            provenance["collection_started_at"] = started_at
        event("collector_started")
        if collector_id.startswith("sharepoint.pnp."):
            from worker.tenant_binding import verify_sharepoint_tenant

            if not await verify_sharepoint_tenant(credentials, GraphClient):
                completed_at = utc_now()
                unverified = {}
                for control_id in order:
                    provenance = provenances[control_id]
                    provenance.update(
                        reason_code="sharepoint_tenant_unverified",
                        provenance_status="not_executed",
                        collection_completed_at=completed_at,
                    )
                    unverified[control_id] = {
                        "compliant": None,
                        "message": "Selected SharePoint tenant identity could not be verified.",
                        "affected_resources": [],
                        "details": {},
                        "provenance": provenance,
                    }
                return unverified
        # Get collector
        collector = get_collector(collector_id)

        # One client, one token, one connection pool for the whole group.
        # Determine client type from the single routing rule in collectors.routing.
        if uses_powershell(collector_id):
            client = PowerShellClient(
                tenant_id=credentials["tenant_id"],
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
                service_url=settings.POWERSHELL_SERVICE_URL,
                service_secret=settings.POWERSHELL_SERVICE_SECRET,
                service_ca_file=settings.POWERSHELL_CA_FILE,
                sharepoint_admin_url=credentials.get("sharepoint_admin_url"),
                certificate_alias=credentials.get("sharepoint_certificate_alias"),
                # Kept separate from the SharePoint alias so a SharePoint
                # certificate can never authenticate an IPPS session. Without
                # these a promoted compliance.* control fails ExecuteRequest
                # validation before it reaches the tenant.
                compliance_certificate_alias=credentials.get(
                    "compliance_certificate_alias"
                ),
                compliance_organization=credentials.get("compliance_organization"),
                batch_size=settings.POWERSHELL_MAX_BATCH,
            )
        else:
            # Entra and other collectors use Graph API
            client = GraphClient(
                tenant_id=credentials["tenant_id"],
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
            )

        # Collect data using the appropriate client -- once, for every member.
        collected_data = await collector.collect(client)
        event("collector_completed")
        completed_at = utc_now()
        for provenance in provenances.values():
            provenance["collection_completed_at"] = completed_at
        digest = canonical_digest(collected_data)
        for provenance in provenances.values():
            provenance["input_digest"] = digest
        if isinstance(collected_data, dict) and (
            collected_data.get("error") is not None
            or collected_data.get("collection_error") is not None
            or collected_data.get("collector_error") is not None
            or collected_data.get("success") is False
        ):
            raise ValueError("Collector reported an execution failure")
        if not isinstance(collected_data, dict):
            unusable = {}
            for control_id in order:
                provenance = provenances[control_id]
                provenance["provenance_status"] = "collection_only"
                # A non-object cannot fulfill any registered collector contract.
                unusable[control_id] = {
                    "compliant": None,
                    "message": "Unusable collector evidence",
                    "affected_resources": [],
                    "details": {},
                    "provenance": provenance,
                }
            return unusable
        # Declared scalar projection of a collection that reached this line, which
        # means it was neither an error envelope nor a non-object payload. Only the
        # success return below carries it. Computed once: the projection is a pure
        # function of (collector_id, collected_data, tenant_id), and every member
        # still persists its own row under its own control id.
        factprint = project_facts(
            collector_id, collected_data, credentials.get("tenant_id")
        )
        reason = "evaluation_error"
        runtime_version = await opa_client.runtime_version()

        outcomes: dict = {}
        failures = 0
        for control_id in order:
            provenance = provenances[control_id]
            if control_id in capture_failed:
                provenance["provenance_status"] = "incomplete"
                outcomes[control_id] = EvaluationFailure(
                    "provenance_unavailable",
                    provenance,
                    {control_id: provenance},
                    retryable=False,
                )
                failures += 1
                continue
            provenance["evaluation_started_at"] = utc_now()
            provenance["opa_version"] = runtime_version
            try:
                evaluated = await opa_client.evaluate_snapshot(
                    _package_path(framework, benchmark, version, control_id),
                    collected_data,
                    sources[control_id],
                )
            except Exception as exc:
                # This control's own policy failed against evidence its siblings
                # judged successfully. Recorded as that control's error; the
                # group is not failed and its siblings are not discarded.
                provenance["evaluated_at"] = utc_now()
                provenance["provenance_status"] = "incomplete"
                outcomes[control_id] = EvaluationFailure(
                    "evaluation_error",
                    provenance,
                    {control_id: provenance},
                    retryable=_is_retryable(exc, "evaluation_error"),
                )
                failures += 1
                continue
            provenance.update(
                opa_version=evaluated.opa_version,
                evaluated_at=utc_now(),
                provenance_status="captured",
            )
            outcomes[control_id] = {
                **evaluated.result.model_dump(),
                "provenance": provenance,
                "factprint": factprint,
            }
        if failures and failures == len(order):
            # Nothing was evaluated. That is the shared evaluator, not one
            # control's policy, so it is the group that failed and the group
            # that may be retried.
            #
            # The members can have failed for DIFFERENT reasons -- one missing
            # policy file, one transient OPA outage -- so each keeps its own
            # reason code, and the group is retryable if ANY member's failure is
            # one a retry could clear. Taking the first member's verdict would
            # let one deterministic failure suppress the retry that would have
            # recovered every other control in the group.
            first = outcomes[order[0]]
            raise EvaluationFailure(
                first.reason_code,
                first.provenance,
                provenances,
                retryable=any(
                    outcome.retryable
                    for outcome in outcomes.values()
                    if isinstance(outcome, EvaluationFailure)
                ),
                reason_codes={
                    control_id: outcome.reason_code
                    for control_id, outcome in outcomes.items()
                    if isinstance(outcome, EvaluationFailure)
                },
            )
        return outcomes

    except EvaluationFailure:
        raise
    except Exception as exc:
        for provenance in provenances.values():
            if provenance["evaluation_started_at"] is not None:
                provenance["evaluated_at"] = utc_now()
            provenance["provenance_status"] = "incomplete"
        raise EvaluationFailure(
            reason,
            provenances[order[0]],
            provenances,
            retryable=_is_retryable(exc, reason),
        ) from None
    finally:
        # Release the pooled transport. `release` never raises, so a cleanup
        # failure cannot become the outcome of the collection.
        from collectors.graph_client import release

        await release(client)
        request_id.reset(correlation_token)


async def _evaluate_control_async(
    control_id: str,
    collector_id: str,
    policy_file: str,
    credentials: dict,
    framework: str,
    benchmark: str,
    version: str,
    scan_context: dict | None = None,
) -> dict:
    """One control's collection and evaluation: a group of exactly one.

    Kept with its Phase 3 positional signature because five test modules call it
    positionally, and because a single control must take exactly the path a
    fanned-out one takes.
    """
    outcomes = await _evaluate_collection_async(
        collector_id=collector_id,
        members=[(control_id, policy_file)],
        credentials=credentials,
        framework=framework,
        benchmark=benchmark,
        version=version,
        scan_context=scan_context,
    )
    outcome = outcomes[control_id]
    if isinstance(outcome, EvaluationFailure):  # pragma: no cover - defensive
        raise outcome
    return outcome
