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
    get_execution_result,
    get_execution_credentials,
    get_pending_scan_results,
    update_scan_status,
    update_scan_result,
    finalize_scan_if_complete,
)

from worker.lifecycle import TERMINAL, enqueue, fail_scan


logger = logging.getLogger(__name__)


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
        dispatched = not_assessable = 0
        for result in get_pending_scan_results(session, scan_id):
            control = get_control_metadata(metadata, result["control_id"])
            reason = None
            outcome = "error"
            if not control:
                reason = "metadata_control_missing"
            elif control.get("automation_status", "ready") != "ready":
                reason, outcome = "not_automated", "not_assessable"
            else:
                collector_id = control.get("data_collector_id") or ""
                if not collector_id:
                    reason = "collector_not_configured"
                elif (
                    not settings.ENABLE_POWERSHELL_CONTROLS
                    and collector_id.startswith(
                        ("exchange.", "compliance.", "teams.", "sharepoint.pnp.")
                    )
                    and not collector_id.startswith("exchange.dns.")
                ):
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
                enqueue(session, scan_id, result["id"])
                dispatched += 1
        complete = finalize_scan_if_complete(session, scan_id)
        return {
            "scan_id": scan_id,
            "status": "completed" if complete else "running",
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
    connection_id: int,
) -> dict:
    """Evaluate frozen database context; broker arguments contain only identifiers."""
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
    control_id = control["control_id"]
    collector_id = control.get("data_collector_id")
    policy_file = control.get("policy_file")
    framework, benchmark, version = (
        scan[key] for key in ("framework", "benchmark", "version")
    )
    scan_context = {
        "metadata_digest": scan["metadata_digest"],
        "correlation_id": scan["correlation_id"],
    }
    credentials = {}
    try:
        with get_db_session() as session:
            credentials = get_execution_credentials(session, scan_id, connection_id)
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
        if outcome.compliant is None and provenance and provenance.get("reason_code"):
            reason = provenance["reason_code"]
        messages = {
            "passed": "Evidence satisfies the control.",
            "failed": "Evidence demonstrates a control violation.",
            "indeterminate": "Evidence is insufficient or ambiguous; no assessment was possible.",
        }
        with get_db_session() as session:
            changed = update_scan_result(
                session,
                result_id=result_id,
                status=outcome.status,
                message=messages[outcome.status],
                evidence={"affected_resource_count": len(outcome.affected_resources)},
                reason_code=reason,
                provenance=provenance,
            )
            finalize_scan_if_complete(session, scan_id)
        if not changed:
            return {"scan_id": scan_id, "result_id": result_id, "status": "ignored"}
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
                changed = update_scan_result(
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

            if not changed:
                return {"scan_id": scan_id, "result_id": result_id, "status": "ignored"}
            return {
                "control_id": control_id,
                "compliant": None,
                "status": "error",
                "error": "Control execution failed",
            }

        raise self.retry(exc=RuntimeError("Control execution failed")) from None
    finally:
        credentials.clear()


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
    from worker.correlation import request_id, safe_request_id, event

    correlation_token = request_id.set(
        safe_request_id((scan_context or {}).get("correlation_id"))
    )

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
        event("collector_started")
        if collector_id.startswith("sharepoint.pnp."):
            from worker.tenant_binding import verify_sharepoint_tenant

            if not await verify_sharepoint_tenant(credentials, GraphClient):
                provenance.update(
                    reason_code="sharepoint_tenant_unverified",
                    provenance_status="not_executed",
                    collection_completed_at=utc_now(),
                )
                return {
                    "compliant": None,
                    "message": "Selected SharePoint tenant identity could not be verified.",
                    "affected_resources": [],
                    "details": {},
                    "provenance": provenance,
                }
        # Get collector
        collector = get_collector(collector_id)

        # Determine client type based on collector_id prefix.
        #
        # Most Exchange and Compliance collectors require PowerShell, but a few Exchange
        # collectors use Graph (e.g. domain metadata).
        if collector_id.startswith(
            ("exchange.", "compliance.", "teams.", "sharepoint.pnp.")
        ) and not collector_id.startswith("exchange.dns."):
            client = PowerShellClient(
                tenant_id=credentials["tenant_id"],
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
                service_url=settings.POWERSHELL_SERVICE_URL,
                service_secret=settings.POWERSHELL_SERVICE_SECRET,
                service_ca_file=settings.POWERSHELL_CA_FILE,
                sharepoint_admin_url=credentials.get("sharepoint_admin_url"),
                certificate_alias=credentials.get("sharepoint_certificate_alias"),
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
        event("collector_completed")
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
    finally:
        request_id.reset(correlation_token)
