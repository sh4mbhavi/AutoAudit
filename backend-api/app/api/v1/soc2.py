"""SOC 2 report projection for a single scan (plan item 15.1.4).

The projection renders from the mapping **pinned onto the scan** and the
**metadata pinned onto the scan**, never from whatever is on disk now. A report
produced today for a scan run in March must still be the March report, so a
disk-backed fallback is not offered at all: a scan without a pinned mapping is
reported as having no SOC 2 projection.

Three rules are enforced structurally rather than by convention.

* Ratings are copied. ``configuration_rating`` is the human-owned Yes/Partial/No
  from the mapping and travels with ``rating_is_computed: false``. A tenant that
  passes every mapped control does not turn a "No" into anything else.
* Manual and inherited evidence is a separate stream. It is listed beside a
  point of focus and can never enter the automated coverage arithmetic.
* Absent, errored, indeterminate and not-assessable results are not assessed and
  not compliant, and they stay in the coverage denominator. A control the scan
  never selected is out of scope for the scan rather than a gap.
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.db.session import get_async_session
from app.models.compliance import Scan
from app.models.manual_evidence import ManualEvidenceRecord
from app.models.scan_result import ScanResult
from app.models.user import User
from app.schemas.soc2 import (
    Soc2ControlEvidence,
    Soc2Coverage,
    Soc2CriterionCoverage,
    Soc2Identity,
    Soc2Limitations,
    Soc2ManualEvidence,
    Soc2ManualEvidenceStream,
    Soc2PointOfFocus,
    Soc2Provenance,
    Soc2ReportHeader,
    Soc2ReportResponse,
    Soc2Totals,
)
from app.services.crosswalk_reader import check_control_resolution

router = APIRouter(prefix="/scans", tags=["SOC 2"])

# The one selector the mapping uses today: every control the pinned benchmark
# marks ready for automated assessment.
SELECTOR_ALL_AUTOMATED = "all_automated_cis_m365_v6"

# Result states that count as an assessment having happened.
ASSESSED_STATUSES = ("passed", "failed")

# Synthetic statuses for a control with no result row. The pinned benchmark
# defines it but the scan lost the row, versus the pinned benchmark never had it.
MISSING_RESULT = "missing_result"
NOT_IN_BENCHMARK = "not_in_benchmark"

# Selected controls that produced no assessment. They stay in the denominator.
UNASSESSED_STATUSES = (
    "indeterminate",
    "error",
    "not_assessable",
    "pending",
)

# Execution provenance that may be published. Strictly an allowlist: collected
# tenant payloads, messages and any future field are excluded by default.
# ``policy_source`` is deliberately absent - the worker stores the complete Rego
# source text there, and file content never leaves in a response. The filename
# and its digest identify the policy without reproducing it.
PUBLISHABLE_PROVENANCE_FIELDS = (
    "schema_version",
    "provenance_status",
    "reason_code",
    "collector_id",
    "policy_file",
    "policy_digest",
    "input_digest",
    "engine_git_sha",
    "engine_image_digest",
    "opa_version",
    "metadata_digest",
    "correlation_id",
    "collection_started_at",
    "collection_completed_at",
    "evaluation_started_at",
    "evaluated_at",
    "recorded_at",
)

NO_PROJECTION_MESSAGE = (
    "This scan has no SOC 2 projection. No crosswalk mapping was pinned when it "
    "was created, either because the scan predates mapping pinning or because "
    "its benchmark is not the benchmark the mapping covers. The current mapping "
    "on disk is deliberately not substituted."
)

MANUAL_STREAM_NOTE = (
    "Approved manual and inherited evidence is reported beside the automated "
    "results and is never counted as automated configuration coverage."
)

MANUAL_STREAM_UNAVAILABLE_NOTE = (
    "The manual and inherited evidence stream could not be read, so none is "
    "shown. Absence here means unknown, not none, and never means compliant."
)


def _as_dict(value: Any) -> dict[str, Any]:
    """A pinned snapshot is frozen data, not necessarily well-formed data.

    The loader validates a mapping before it is pinned, but the column is JSONB
    and nothing revalidates it on the way out: a row written by an older build,
    a restore or a future import path could hold anything. Rendering coerces
    rather than trusts, so a malformed pin degrades to a thin report instead of
    an unhandled 500 on an audit endpoint.
    """
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """Same contract as ``_as_dict``. A string is not a list of control ids."""
    return value if isinstance(value, list) else []


def _as_text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _verbatim_approval(raw: Any) -> dict[str, Any]:
    """The approval block as pinned, with one hardening: ``approved`` fails closed.

    Every other key is reproduced verbatim. ``approved`` is reduced to identity
    against ``True`` because Pydantic's lax boolean parsing would otherwise turn
    a string like "yes" in a malformed pin into a rendered ``approved: true``.
    The loader already rejects a non-boolean flag at pin time, so this only ever
    fires on a pin that did not come through it.
    """
    approval = dict(_as_dict(raw))
    approval["approved"] = approval.get("approved") is True
    return approval


def _verbatim_identity(raw: Any) -> dict[str, Any]:
    """The mapping's SOC 2 identity block, coerced only where a type would raise."""
    identity = dict(_as_dict(raw))
    identity["framework"] = _as_text(identity.get("framework"))
    identity["criteria_family"] = _as_text(identity.get("criteria_family"))
    identity["authoritative_criteria"] = [
        item
        for item in _as_list(identity.get("authoritative_criteria"))
        if isinstance(item, str)
    ]
    return identity


def _criterion_row(row: dict[str, Any]) -> dict[str, Any]:
    """One criteria-coverage row, verbatim apart from a non-string classification."""
    return {
        **row,
        "criterion": row["criterion"],
        "configuration_coverage_classification": _as_text(
            row.get("configuration_coverage_classification")
        ),
    }


def _control_sort_key(control_id: str) -> list[tuple[int, int, str]]:
    """Sort '1.1.10' after '1.1.9' rather than lexically."""
    key: list[tuple[int, int, str]] = []
    for chunk in str(control_id).split("."):
        if chunk.isdigit():
            key.append((0, int(chunk), ""))
        else:
            key.append((1, 0, chunk))
    return key


def _publishable_provenance(provenance: Any) -> dict[str, Any] | None:
    """Project execution provenance through the allowlist above."""
    if not isinstance(provenance, dict):
        return None
    projected = {
        field: provenance[field]
        for field in PUBLISHABLE_PROVENANCE_FIELDS
        if field in provenance
    }
    return projected or None


def _pinned_controls(scan: Scan) -> dict[str, dict[str, Any]]:
    """Controls from the scan's pinned metadata snapshot, by control id."""
    controls = _as_list(_as_dict(scan.metadata_snapshot).get("controls"))
    return {
        control["control_id"]: control
        for control in controls
        if isinstance(control, dict) and isinstance(control.get("control_id"), str)
    }


def _listed_control_ids(point: dict[str, Any]) -> list[str]:
    """The control ids a point of focus names explicitly, ignoring junk."""
    return [
        control_id
        for control_id in _as_list(point.get("cis_control_ids"))
        if isinstance(control_id, str) and control_id
    ]


def _resolve_point_controls(
    point: dict[str, Any], pinned_controls: dict[str, dict[str, Any]]
) -> tuple[list[str], bool]:
    """Control ids a point of focus maps to, resolved against pinned metadata.

    Returns the ids and whether every selector was understood. An unrecognised
    selector resolves to the explicitly listed ids only and is flagged, so an
    unknown selector can never silently widen or narrow reported coverage.
    """
    listed = _listed_control_ids(point)
    selector = _as_text(point.get("evidence_selector"))
    if not selector:
        return sorted(set(listed), key=_control_sort_key), True
    if selector == SELECTOR_ALL_AUTOMATED:
        # Deliberately the pinned snapshot, not the live metadata: the scan was
        # run against that control population and the report must say so.
        expanded = {
            control_id
            for control_id, control in pinned_controls.items()
            if control.get("automation_status") == "ready"
        }
        return sorted(set(listed) | expanded, key=_control_sort_key), True
    return sorted(set(listed), key=_control_sort_key), False


def _coverage_statement(
    mapped: int, applicable: int, assessed: int, not_in_scope: int, missing: int
) -> str:
    if mapped == 0:
        return (
            "This point of focus maps to no automated Microsoft 365 "
            "configuration control."
        )
    if applicable == 0:
        return (
            f"None of the {mapped} mapped controls were selected for this scan, "
            "so this point of focus is out of scope for it."
        )
    statement = (
        f"{assessed} of {applicable} selected controls were assessed "
        f"({mapped} mapped, {not_in_scope} not selected for this scan)."
    )
    if missing:
        statement += (
            f" {missing} of them have no result row at all and are counted as "
            "unassessed."
        )
    return statement


def _build_coverage(
    evidence: list[Soc2ControlEvidence], mapped_count: int
) -> Soc2Coverage:
    """Phase 3 arithmetic, applied to one point of focus's mapped controls.

    Two kinds of absence are kept apart, because conflating them is exactly how a
    partial assessment turns into a clean bill of health:

    * the pinned benchmark does not define the control at all - genuinely out of
      scope for this scan, excluded from the denominator;
    * the pinned benchmark defines it but the scan holds no result row - an
      integrity gap. It stays in the denominator, unassessed, so a scan that lost
      rows reports as incomplete rather than as fully covered.
    """
    in_scan = [row for row in evidence if row.in_scan]
    # Missing rows for controls the scan should have had are applicable and
    # unassessed. Never silently dropped from the denominator.
    missing_results = [row for row in evidence if row.status == MISSING_RESULT]
    applicable = [row for row in in_scan if row.selected] + missing_results
    counts = {
        state: sum(1 for row in applicable if row.status == state)
        for state in ASSESSED_STATUSES + UNASSESSED_STATUSES
    }
    passed = counts["passed"]
    failed = counts["failed"]
    assessed = passed + failed
    applicable_count = len(applicable)
    absent = sum(1 for row in evidence if row.status == NOT_IN_BENCHMARK)
    not_in_scope = (len(in_scan) - len([r for r in in_scan if r.selected])) + absent

    if mapped_count == 0:
        completeness = "no_automated_coverage"
    elif applicable_count == 0:
        completeness = "not_applicable"
    elif assessed == 0:
        completeness = "not_assessed"
    elif assessed < applicable_count:
        completeness = "partial"
    else:
        completeness = "complete"

    return Soc2Coverage(
        mapped_control_count=mapped_count,
        in_scan_count=len(in_scan),
        applicable_count=applicable_count,
        assessed_count=assessed,
        passed_count=passed,
        failed_count=failed,
        indeterminate_count=counts["indeterminate"],
        error_count=counts["error"],
        not_assessable_count=counts["not_assessable"],
        pending_count=counts["pending"],
        missing_result_count=len(missing_results),
        unassessed_count=applicable_count - assessed,
        not_in_scope_count=not_in_scope,
        missing_from_benchmark_count=absent,
        coverage_percent=(
            round(100 * assessed / applicable_count, 2) if applicable_count else None
        ),
        compliance_percent=(round(100 * passed / assessed, 2) if assessed else None),
        assessment_completeness=completeness,
        partial_assessment=applicable_count > 0 and assessed < applicable_count,
        coverage_statement=_coverage_statement(
            mapped_count,
            applicable_count,
            assessed,
            not_in_scope,
            len(missing_results),
        ),
    )


def _control_evidence(
    control_id: str,
    result: ScanResult | None,
    pinned_controls: dict[str, dict[str, Any]],
) -> Soc2ControlEvidence:
    control = pinned_controls.get(control_id)
    in_benchmark = control is not None
    control = control or {}
    if result is None:
        # Absent for one of two very different reasons. Neither is ever a pass,
        # but only one of them is legitimately out of scope.
        return Soc2ControlEvidence(
            control_id=control_id,
            title=control.get("title"),
            in_benchmark=in_benchmark,
            in_scan=False,
            selected=None,
            status=MISSING_RESULT if in_benchmark else NOT_IN_BENCHMARK,
            reason_code=(
                "result_row_missing"
                if in_benchmark
                else "not_present_in_pinned_benchmark"
            ),
            automation_status=control.get("automation_status"),
            provenance=None,
        )
    if result.selected is None:
        # Legacy rows carry no selection flag. Falling back to the stored state
        # can only remove a control from the denominator when it was explicitly
        # skipped; it can never manufacture an assessment.
        selected = result.status != "skipped"
    else:
        selected = bool(result.selected)
    return Soc2ControlEvidence(
        control_id=control_id,
        title=control.get("title"),
        in_benchmark=in_benchmark,
        in_scan=True,
        selected=selected,
        status=result.status,
        reason_code=result.reason_code,
        automation_status=control.get("automation_status"),
        provenance=_publishable_provenance(result.provenance),
    )


def _manual_evidence_item(record: ManualEvidenceRecord) -> Soc2ManualEvidence:
    return Soc2ManualEvidence(
        record_id=record.id,
        control_id=record.control_id,
        evidence_source=record.evidence_source,
        status=record.status,
        control_owner=record.control_owner,
        evidence_owner=record.evidence_owner,
        collection_period_start=record.collection_period_start,
        collection_period_end=record.collection_period_end,
        expires_at=record.expires_at,
        cadence=record.cadence,
        reviewed_at=record.reviewed_at,
        current_revision_number=record.current_revision_number or 0,
    )


async def _approved_manual_evidence(
    db: AsyncSession, scan_id: int
) -> tuple[bool, dict[str, list[Soc2ManualEvidence]]]:
    """Read-only view of another team's model. Tolerates an empty table.

    Runs last so that a failure here cannot disturb the automated reads, and
    reports unavailability explicitly rather than presenting "no manual
    evidence" when the truth is "manual evidence could not be read".
    """
    try:
        rows = await db.execute(
            select(ManualEvidenceRecord).where(
                ManualEvidenceRecord.scan_id == scan_id,
                ManualEvidenceRecord.status == "approved",
            )
        )
        records = list(rows.scalars().all())
    except SQLAlchemyError:
        return False, {}
    grouped: dict[str, list[Soc2ManualEvidence]] = {}
    for record in records:
        grouped.setdefault(record.control_id, []).append(_manual_evidence_item(record))
    return True, grouped


def _no_projection(scan: Scan) -> Soc2ReportResponse:
    return Soc2ReportResponse(
        scan_id=scan.id,
        projection_available=False,
        projection_status="no_projection",
        message=NO_PROJECTION_MESSAGE,
    )


@router.get("/{scan_id}/soc2-report", response_model=Soc2ReportResponse)
async def get_soc2_report(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> Soc2ReportResponse:
    """Project one scan through its pinned SOC 2 crosswalk.

    Owner-authorized. A scan belonging to another user is a 404, not a 403, so
    the endpoint does not confirm that a scan id exists.
    """
    found = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = found.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    document = scan.mapping_snapshot if isinstance(scan.mapping_snapshot, dict) else {}
    # A pin with no renderable point of focus is no projection. Reporting an
    # empty document as an available projection would read as "nothing to see".
    pinned_points = [
        point
        for point in _as_list(document.get("points_of_focus"))
        if isinstance(point, dict)
    ]
    if not pinned_points:
        return _no_projection(scan)

    rows = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id))
    results = {result.control_id: result for result in rows.scalars().all()}
    pinned_controls = _pinned_controls(scan)

    manual_available, manual_by_control = await _approved_manual_evidence(db, scan.id)

    points: list[Soc2PointOfFocus] = []
    rating_counts: dict[str, int] = {}
    listed_control_ids: set[str] = set()
    criteria: set[str] = set()

    for point in pinned_points:
        control_ids, selector_resolved = _resolve_point_controls(point, pinned_controls)
        listed_control_ids.update(_listed_control_ids(point))
        criteria.add(str(point.get("criterion", "")))
        evidence = [
            _control_evidence(control_id, results.get(control_id), pinned_controls)
            for control_id in control_ids
        ]
        manual: list[Soc2ManualEvidence] = []
        for control_id in control_ids:
            manual.extend(manual_by_control.get(control_id, []))
        # The rating is transcribed, not derived. Nothing above this line feeds it.
        rating = str(point.get("rating"))
        rating_counts[rating] = rating_counts.get(rating, 0) + 1
        points.append(
            Soc2PointOfFocus(
                point_id=str(point.get("point_id")),
                criterion=str(point.get("criterion")),
                point_of_focus=str(point.get("point_of_focus")),
                configuration_rating=rating,
                evidence_selector=_as_text(point.get("evidence_selector")),
                selector_resolved=selector_resolved,
                mapped_control_ids=control_ids,
                automated_evidence=evidence,
                coverage=_build_coverage(evidence, len(control_ids)),
                manual_residual_evidence=manual,
                limitations=Soc2Limitations(
                    residual_limitation=_as_text(point.get("residual_limitation")),
                    residual_scope=_as_text(point.get("residual_scope")),
                ),
            )
        )

    approval = _verbatim_approval(document.get("approval"))
    header = Soc2ReportHeader(
        mapping_id=str(document.get("mapping_id") or scan.mapping_id or ""),
        mapping_version=str(
            document.get("mapping_version") or scan.mapping_version or ""
        ),
        mapping_digest=str(scan.mapping_digest or ""),
        mapping_status=_as_text(document.get("status")),
        schema_version=(
            document.get("schema_version")
            if isinstance(document.get("schema_version"), int)
            else None
        ),
        soc2=Soc2Identity(**_verbatim_identity(document.get("soc2"))),
        benchmark=_as_dict(document.get("benchmark")),
        source=_as_dict(document.get("source")) or None,
        rating_vocabulary=[
            word
            for word in _as_list(document.get("rating_vocabulary"))
            if isinstance(word, str)
        ],
        approval=approval,
        # Identity, not truthiness: only a real ``true`` counts as approved. An
        # unreadable approval block is never approved.
        approval_pending=approval.get("approved") is not True,
    )

    manual_count = sum(len(items) for items in manual_by_control.values())
    return Soc2ReportResponse(
        scan_id=scan.id,
        projection_available=True,
        projection_status="available",
        message=(
            "SOC 2 configuration projection rendered from the mapping pinned to "
            "this scan."
        ),
        header=header,
        provenance=Soc2Provenance(
            scan_id=scan.id,
            scan_status=scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            framework=scan.framework,
            benchmark=scan.benchmark,
            benchmark_version=scan.version,
            metadata_digest=scan.metadata_digest,
            policy_corpus_digest=scan.policy_corpus_digest,
            mapping_id=scan.mapping_id,
            mapping_version=scan.mapping_version,
            mapping_digest=scan.mapping_digest,
            correlation_id=scan.correlation_id,
            semantics_version=scan.semantics_version,
            lifecycle_version=scan.lifecycle_version,
            evidence_version=scan.evidence_version,
            connection_snapshot_present=scan.connection_snapshot is not None,
            generated_at=datetime.now(timezone.utc),
        ),
        criteria_coverage_summary=[
            Soc2CriterionCoverage(**_criterion_row(row))
            for row in _as_list(document.get("criteria_coverage_summary"))
            if isinstance(row, dict) and isinstance(row.get("criterion"), str)
        ],
        points_of_focus=points,
        totals=Soc2Totals(
            points_of_focus_count=len(points),
            # Explicitly listed ids only. The CC7.1 selector expands at render
            # time against the pinned benchmark and would otherwise inflate this.
            unique_mapped_control_ids=len(listed_control_ids),
            rating_counts=rating_counts,
            criteria_count=len({item for item in criteria if item}),
        ),
        manual_evidence_stream=Soc2ManualEvidenceStream(
            available=manual_available,
            approved_record_count=manual_count,
            note=(
                MANUAL_STREAM_NOTE
                if manual_available
                else MANUAL_STREAM_UNAVAILABLE_NOTE
            ),
        ),
        mapping_resolution_findings=check_control_resolution(
            document, scan.metadata_snapshot
        ),
    )
