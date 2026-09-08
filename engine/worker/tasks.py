"""Celery tasks for compliance scanning."""

import asyncio
import hashlib
from datetime import datetime

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
    get_pending_scan_results,
    update_scan_status,
    update_scan_result,
    finalize_scan_if_complete,
)


class EvaluationFailure(Exception):
    """Redacted execution failure with the provenance captured before failure."""

    def __init__(self, reason_code: str, provenance: dict):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.provenance = provenance


def get_control_metadata(metadata: dict, control_id: str) -> dict | None:
    """Get control metadata by control_id from the metadata dict."""
    for control in metadata.get("controls", []):
        if control["control_id"] == control_id:
            return control
    return None


@celery_app.task(name="worker.tasks.run_scan")
def run_scan(scan_id: int) -> dict:
    """Orchestrator task: Dispatches control evaluation tasks.

    This task:
    1. Updates scan status to "running"
    2. Gets pending ScanResult records
    3. Dispatches evaluate_control tasks for each pending result
    4. Returns immediately (fire-and-forget)

    Each evaluate_control task writes results directly to PostgreSQL.
    The last task to complete will finalize the scan.

    Args:
        scan_id: The scan ID to process

    Returns:
        Summary dict with dispatch info
    """
    with get_db_session() as session:
        # Get scan details
        scan = get_scan(session, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        if scan["status"] in {"completed", "failed"}:
            return {"scan_id": scan_id, "status": scan["status"]}
        if scan["semantics_version"] != "phase3-v1":
            update_scan_status(
                session,
                scan_id,
                status="failed",
                finished_at=datetime.utcnow(),
                notes="Legacy pending scan: create a new scan to capture selection and provenance.",
            )
            return {"scan_id": scan_id, "status": "failed"}

        # Update status to running
        update_scan_status(session, scan_id, status="running")
        session.commit()

        # Get pending scan results (controls that need to be evaluated)
        pending_results = get_pending_scan_results(session, scan_id)

    total_pending = len(pending_results)

    if total_pending == 0:
        with get_db_session() as session:
            finalize_scan_if_complete(session, scan_id)
        return {"scan_id": scan_id, "status": "completed", "total_pending": 0}

    # Selection and metadata are frozen by the API, never reread during a scan.
    metadata = scan["metadata_snapshot"]
    context = {
        "metadata_digest": scan["metadata_digest"],
        "correlation_id": scan["correlation_id"],
    }
    if canonical_digest(metadata) != scan["metadata_digest"]:
        raise ValueError("Frozen metadata digest mismatch")

    # Build credentials dict for passing to tasks
    credentials = {
        "tenant_id": scan["tenant_id"],
        "client_id": scan["client_id"],
        "client_secret": scan["client_secret"],
    }

    # Dispatch all tasks for parallel execution (fire-and-forget)
    dispatched = 0
    not_assessable = 0

    for result in pending_results:
        control = get_control_metadata(metadata, result["control_id"])
        if not control:
            # Control not found in metadata (possible ID format mismatch)
            with get_db_session() as session:
                update_scan_result(
                    session,
                    result_id=result["id"],
                    status="error",
                    message="Control missing from frozen metadata.",
                    reason_code="metadata_control_missing",
                    provenance=initial_provenance(
                        scan["framework"],
                        scan["benchmark"],
                        scan["version"],
                        {"control_id": result["control_id"]},
                        context,
                    ),
                )
                finalize_scan_if_complete(session, scan_id)
                session.commit()
            continue

        # Check automation_status before dispatching
        status = control.get("automation_status", "ready")
        collector_id = control.get("data_collector_id") or ""

        if status == "ready":
            # Optional fast-scan mode: allow skipping slow PowerShell-based controls only when
            # explicitly disabled via ENABLE_POWERSHELL_CONTROLS=false.
            if (
                settings.ENABLE_POWERSHELL_CONTROLS is False
                and collector_id.startswith(
                    ("exchange.", "compliance.", "teams.", "sharepoint.pnp.")
                )
                and not collector_id.startswith("exchange.dns.")
            ):
                with get_db_session() as session:
                    update_scan_result(
                        session,
                        result_id=result["id"],
                        status="not_assessable",
                        message="PowerShell assessment is disabled for this worker.",
                        reason_code="automation_disabled",
                        provenance=initial_provenance(
                            scan["framework"],
                            scan["benchmark"],
                            scan["version"],
                            control,
                            context,
                        ),
                    )
                    finalize_scan_if_complete(session, scan_id)
                    session.commit()
                not_assessable += 1
                continue

            # Verify collector exists before dispatching
            if not control.get("data_collector_id"):
                with get_db_session() as session:
                    update_scan_result(
                        session,
                        result_id=result["id"],
                        status="error",
                        message="Control marked ready but has no collector.",
                        reason_code="collector_not_configured",
                        provenance=initial_provenance(
                            scan["framework"],
                            scan["benchmark"],
                            scan["version"],
                            control,
                            context,
                        ),
                    )
                    finalize_scan_if_complete(session, scan_id)
                    session.commit()
                continue

            evaluate_control.delay(
                scan_id=scan_id,
                result_id=result["id"],
                control=control,
                credentials=credentials,
                framework=scan["framework"],
                benchmark=scan["benchmark"],
                version=scan["version"],
                scan_context=context,
            )
            dispatched += 1
        else:
            # Selected controls outside current automation stay in the coverage denominator.
            with get_db_session() as session:
                update_scan_result(
                    session,
                    result_id=result["id"],
                    status="not_assessable",
                    message="Selected control is outside automated assessment capability.",
                    reason_code="not_automated",
                    provenance=initial_provenance(
                        scan["framework"],
                        scan["benchmark"],
                        scan["version"],
                        control,
                        context,
                    ),
                )
                finalize_scan_if_complete(session, scan_id)
                session.commit()
            not_assessable += 1

    # If no tasks were dispatched, finalize the scan immediately
    # (selected controls may be not assessable or in error)
    if dispatched == 0:
        with get_db_session() as session:
            finalize_scan_if_complete(session, scan_id)
            session.commit()
        return {
            "scan_id": scan_id,
            "status": "completed",
            "dispatched": dispatched,
            "not_assessable": not_assessable,
        }

    # Return immediately - don't wait for results
    # Each evaluate_control task will update PostgreSQL directly
    # The last task to complete will finalize the scan
    return {
        "scan_id": scan_id,
        "status": "running",
        "dispatched": dispatched,
        "not_assessable": not_assessable,
    }


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
    control: dict,
    credentials: dict,
    framework: str,
    benchmark: str,
    version: str,
    scan_context: dict | None = None,
) -> dict:
    """Evaluate a single control.

    This task:
    1. Collects data using the appropriate collector
    2. Evaluates the policy using OPA
    3. Updates the ScanResult record with the outcome
    4. Derives scan progress from terminal result rows
    5. If this was the last pending control, finalizes the scan

    Args:
        scan_id: The scan ID
        result_id: The scan_result.id to update
        control: Control metadata dict from metadata.json
        credentials: M365 credentials dict
        framework: Framework name (e.g., "cis")
        benchmark: Benchmark slug (e.g., "microsoft-365-foundations")
        version: Version string (e.g., "v3.1.0")

    Returns:
        Result dict with control evaluation outcome
    """
    control_id = control["control_id"]
    collector_id = control.get("data_collector_id")
    policy_file = control.get("policy_file")

    try:
        # Run async collector and OPA evaluation
        result = asyncio.run(
            _evaluate_control_async(
                control_id=control_id,
                collector_id=collector_id,
                policy_file=policy_file,
                credentials=credentials,
                framework=framework,
                benchmark=benchmark,
                version=version,
                scan_context=scan_context,
            )
        )

        provenance = result.pop("provenance", None)
        outcome = OPAResult.model_validate(result)
        reason = (
            "insufficient_evidence"
            if outcome.compliant is None
            else "policy_satisfied"
            if outcome.compliant
            else "policy_violation"
        )
        messages = {
            "passed": "Evidence satisfies the control.",
            "failed": "Evidence demonstrates a control violation.",
            "indeterminate": "Evidence is insufficient or ambiguous; no assessment was possible.",
        }
        with get_db_session() as session:
            update_scan_result(
                session,
                result_id=result_id,
                status=outcome.status,
                message=messages[outcome.status],
                evidence={"affected_resource_count": len(outcome.affected_resources)},
                reason_code=reason,
                provenance=provenance,
            )
            finalize_scan_if_complete(session, scan_id)
        return {
            "control_id": control_id,
            "compliant": outcome.compliant,
            "status": outcome.status,
        }

    except Exception as exc:
        # self.request.retries is the number of retries already performed.
        # Once the retry limit is reached, persist the terminal error
        # instead of scheduling another retry.
        if self.max_retries is not None and self.request.retries >= self.max_retries:
            with get_db_session() as session:
                update_scan_result(
                    session,
                    result_id=result_id,
                    status="error",
                    message="Control execution failed after retries; no compliance assessment was recorded.",
                    reason_code=exc.reason_code
                    if isinstance(exc, EvaluationFailure)
                    else "evaluation_error",
                    provenance=exc.provenance
                    if isinstance(exc, EvaluationFailure)
                    else initial_provenance(
                        framework, benchmark, version, control, scan_context
                    ),
                )
                # Check if this was the last control and finalize scan if complete
                finalize_scan_if_complete(session, scan_id)
                session.commit()

            return {
                "control_id": control_id,
                "compliant": None,
                "status": "error",
                "error": "Control execution failed",
            }

        raise self.retry(exc=RuntimeError("Control execution failed")) from None


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
    """Async helper to collect data and evaluate policy.

    Args:
        control_id: The control ID (e.g., "CIS-1.1.1")
        collector_id: The data collector ID from registry
        policy_file: The Rego policy filename (e.g., "1.1.1_admin_cloud_only.rego")
        credentials: M365 credentials
        framework: Framework name (e.g., "cis")
        benchmark: Benchmark slug (e.g., "microsoft-365-foundations")
        version: Version string (e.g., "v3.1.0")

    Returns:
        OPA evaluation result
    """
    # Import here to avoid circular imports
    from collectors.registry import get_collector
    from collectors.graph_client import GraphClient
    from collectors.powershell_client import PowerShellClient
    from opa_client import opa_client

    provenance = initial_provenance(
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
    reason = "provenance_unavailable"
    try:
        provenance.update(engine_identity())
        source = capture_policy(framework, benchmark, version, policy_file)
        provenance.update(
            policy_source=source,
            policy_digest=hashlib.sha256(source.encode()).hexdigest(),
        )
        reason = "collection_error"
        provenance["collection_started_at"] = utc_now()
        # Get collector
        collector = get_collector(collector_id)

        # Determine client type based on collector_id prefix.
        #
        # Most Exchange and Compliance collectors require PowerShell, but a few Exchange
        # collectors use Graph (e.g. domain metadata).
        if collector_id.startswith(
            ("exchange.", "compliance.", "sharepoint.pnp.")
        ) and not collector_id.startswith("exchange.dns."):
            client = PowerShellClient(
                tenant_id=credentials["tenant_id"],
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
                service_url=settings.POWERSHELL_SERVICE_URL,
                sharepoint_admin_url=settings.SHAREPOINT_ADMIN_URL,
                certificate_alias=settings.SHAREPOINT_CERT_ALIAS,
            )
        else:
            # Entra and other collectors use Graph API
            client = GraphClient(
                tenant_id=credentials["tenant_id"],
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
            )

        # Collect data using the appropriate client
        collected_data = await collector.collect(client)
        provenance["collection_completed_at"] = utc_now()
        provenance["input_digest"] = canonical_digest(collected_data)
        if isinstance(collected_data, dict) and (
            collected_data.get("error") is not None
            or collected_data.get("collection_error") is not None
            or collected_data.get("collector_error") is not None
            or collected_data.get("success") is False
        ):
            raise ValueError("Collector reported an execution failure")
        if not isinstance(collected_data, dict):
            provenance["provenance_status"] = "collection_only"
            # A non-object cannot fulfill any registered collector contract.
            return {
                "compliant": None,
                "message": "Unusable collector evidence",
                "affected_resources": [],
                "details": {},
                "provenance": provenance,
            }
        provenance["input_digest"] = canonical_digest(collected_data)
        reason = "evaluation_error"
        provenance["evaluation_started_at"] = utc_now()
        provenance["opa_version"] = await opa_client.runtime_version()

        # Build OPA package path to match the Rego package declaration
        # Rego package: "cis.microsoft_365_foundations.v3_1_0.control_1_1_1"
        # OPA REST API path: "cis/microsoft_365_foundations/v3_1_0/control_1_1_1"
        #
        # Transform:
        # - framework: "essential-eight" -> "essential_eight"
        # - benchmark: "microsoft-365-foundations" -> "microsoft_365_foundations"
        # - version: "v3.1.0" -> "v3_1_0"
        # - control_id: "1.1.1" -> "control_1_1_1", "E8-MAC-2.1" -> "control_e8_mac_2_1"
        framework_normalized = framework.replace("-", "_")
        benchmark_normalized = benchmark.replace("-", "_")
        version_normalized = version.replace(".", "_")

        # Convert control_id to a valid Rego identifier (lowercase, hyphens/dots to underscores)
        control_suffix = control_id.replace(".", "_").replace("-", "_").lower()
        control_package = f"control_{control_suffix}"

        package_path = f"{framework_normalized}/{benchmark_normalized}/{version_normalized}/{control_package}"

        # Evaluate policy with OPA
        evaluated = await opa_client.evaluate_snapshot(
            package_path, collected_data, source
        )
        provenance.update(
            opa_version=evaluated.opa_version,
            evaluated_at=utc_now(),
            provenance_status="captured",
        )
        return {**evaluated.result.model_dump(), "provenance": provenance}

    except Exception:
        if provenance["evaluation_started_at"] is not None:
            provenance["evaluated_at"] = utc_now()
        provenance["provenance_status"] = "incomplete"
        raise EvaluationFailure(reason, provenance) from None
