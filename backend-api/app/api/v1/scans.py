"""Scan API endpoints."""

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import get_current_user
from app.db.session import get_async_session
from app.models.compliance import Scan
from app.models.m365_connection import M365Connection
from app.models.scan_result import ScanResult
from app.models.scan_dispatch import ScanDispatch
from app.core.config import get_settings
from app.models.user import User
from app.schemas.scan import (
    ResultStatus,
    ScanCreate,
    ScanCreatedResponse,
    ControlCategoryBreakdown,
    ScanListItem,
    ScanProvenanceRead,
    ScanReadinessCheck,
    ScanReadinessResponse,
    ScanRead,
    ScanResultRead,
    ScanSummary,
)
from app.services.benchmark_reader import get_file_reader
from app.services.crosswalk_reader import (
    CrosswalkError,
    CrosswalkNotFoundError,
    get_crosswalk_reader,
)
from app.services.encryption import decrypt
from app.services.scan_readiness import (
    evaluate_scan_readiness,
    extract_required_permissions,
)

router = APIRouter(prefix="/scans", tags=["Scans"])

# Evidence semantics this build writes. Bumped when the shape of what a scan
# freezes changes, so a reader never has to guess which contract a row follows.
EVIDENCE_VERSION = "phase7-v1"


def _resolve_mapping_pin(
    framework: str, benchmark: str, version: str
) -> dict[str, object]:
    """Freeze the SOC 2 crosswalk and policy corpus identity for a new scan.

    Returns the six Phase 7 scan columns. They are written in the creating
    INSERT and never updated: the Phase 3 scan-input trigger now covers them, so
    an UPDATE raises rather than quietly rewriting an audit input.

    Three outcomes, all deliberate:

    * No mapping corpus is mounted - SOC 2 projection is not deployed here. The
      mapping columns stay null and the scan proceeds. This is a configuration
      state, not corruption.
    * A mapping is mounted but does not cover this benchmark - the columns stay
      null. A scan of another benchmark is still a valid scan; it simply has no
      SOC 2 projection, and stretching this mapping over it would be inventing
      an authority nobody granted.
    * A mapping is mounted, covers this benchmark, but is unreadable or invalid
      - refuse the scan. Creating a scan that silently loses its pin would
      produce evidence nobody can reproduce later.

    ``policy_corpus_digest`` is recorded regardless of the mapping, because it
    describes what the scan evaluates rather than how it is projected.
    """
    reader = get_crosswalk_reader()
    # ``mapping_snapshot`` is deliberately absent rather than None: a JSONB column
    # assigned Python None stores the JSON literal ``null``, which is not SQL NULL
    # and would make an unpinned scan look pinned to any query that tests the
    # column for NULL. Leaving the key out lets the column default to SQL NULL.
    pin: dict[str, object] = {
        "mapping_id": None,
        "mapping_version": None,
        "mapping_digest": None,
        "policy_corpus_digest": None,
        "evidence_version": EVIDENCE_VERSION,
    }
    try:
        pin["policy_corpus_digest"] = reader.policy_corpus_digest(
            framework, benchmark, version
        )
    except CrosswalkNotFoundError:
        # Policies are not on this filesystem (a mocked or metadata-only
        # deployment). Recording null is honest; guessing a digest is not.
        pin["policy_corpus_digest"] = None
    except CrosswalkError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "policy_corpus_unreadable",
                "message": "Benchmark policies could not be digested for this scan.",
            },
        ) from error

    if not reader.mappings_available():
        return pin
    try:
        mapping = reader.load_configured_mapping()
    except CrosswalkNotFoundError:
        # The configured mapping is absent from a mounted corpus. Other mappings
        # may exist; this scan simply has no projection under this configuration.
        return pin
    except CrosswalkError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "soc2_mapping_unavailable",
                "message": "The SOC 2 crosswalk mapping could not be read.",
            },
        ) from error

    if not mapping.applies_to(framework, benchmark, version):
        return pin
    pin.update(
        mapping_id=mapping.mapping_id,
        mapping_version=mapping.mapping_version,
        mapping_digest=mapping.digest,
        # Copied so the pin can never be mutated through the ORM, and so it is
        # independent of the file on disk from here on.
        mapping_snapshot=deepcopy(mapping.document),
    )
    return pin


@router.post(
    "/", response_model=ScanCreatedResponse, status_code=status.HTTP_201_CREATED
)
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ScanCreatedResponse:
    """Create a new compliance scan.

    Commits the scan, all results, and a durable dispatch intent atomically.
    The scan runs asynchronously - poll GET /scans/{id} for status.
    """
    # Verify the connection exists and belongs to the user
    result = await db.execute(
        select(M365Connection).where(
            M365Connection.id == scan_data.m365_connection_id,
            M365Connection.user_id == current_user.id,
            M365Connection.is_active.is_(True),
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"M365 connection {scan_data.m365_connection_id} not found or inactive",
        )

    # Load benchmark metadata to get all controls
    file_reader = get_file_reader()
    try:
        metadata = deepcopy(
            file_reader.get_benchmark_metadata(
                scan_data.framework, scan_data.benchmark, scan_data.version
            )
        )
        all_controls = metadata.get("controls", [])
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark {scan_data.framework}/{scan_data.benchmark}/{scan_data.version} not found",
        )

    # Validate platform matches (benchmark must be for m365)
    if metadata.get("platform", "").lower() != "m365":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Benchmark platform '{metadata.get('platform')}' does not match M365 connection",
        )

    available_ids = {control["control_id"] for control in all_controls}
    if not available_ids or scan_data.control_ids == []:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "empty_selection",
                "message": "Select at least one control from a non-empty benchmark.",
            },
        )
    selected_ids = (
        available_ids if scan_data.control_ids is None else set(scan_data.control_ids)
    )
    unknown_ids = sorted(selected_ids - available_ids)
    if unknown_ids:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "unknown_control_ids",
                "unknown_control_ids": unknown_ids,
                "message": "Some selected controls do not exist in this benchmark.",
            },
        )
    metadata_digest = hashlib.sha256(
        json.dumps(
            metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    # Frozen in the same INSERT as the metadata snapshot below. These columns are
    # immutable afterwards, so there is no later opportunity to fill them in.
    mapping_pin = _resolve_mapping_pin(
        scan_data.framework, scan_data.benchmark, scan_data.version
    )

    # Create scan record only after validating the complete selection.
    scan = Scan(
        user_id=current_user.id,
        m365_connection_id=scan_data.m365_connection_id,
        framework=scan_data.framework,
        benchmark=scan_data.benchmark,
        version=scan_data.version,
        status="pending",
        total_controls=len(all_controls),
        selected_count=len(selected_ids),
        semantics_version="phase3-v1",
        metadata_snapshot=metadata,
        metadata_digest=metadata_digest,
        correlation_id=getattr(request.state, "request_id", str(uuid4())),
        dispatch_id=str(uuid4()),
        dispatch_count=0,
        last_progress_at=datetime.now(timezone.utc).replace(tzinfo=None),
        deadline_at=datetime.now(timezone.utc).replace(tzinfo=None)
        + timedelta(seconds=get_settings().SCAN_DEADLINE_SECONDS),
        lifecycle_version="phase6-v1",
        connection_snapshot={
            key: getattr(connection, key, None)
            for key in (
                "tenant_id",
                "client_id",
                "sharepoint_admin_url",
                "sharepoint_tenant_id",
                "sharepoint_certificate_alias",
            )
        },
        **mapping_pin,
    )
    db.add(scan)
    await db.flush()  # Get scan.id

    # Create ScanResult records for ALL controls
    skipped = 0
    for control in all_controls:
        is_selected = control["control_id"] in selected_ids
        result_status = "pending" if is_selected else "skipped"
        if result_status == "skipped":
            skipped += 1
        scan_result = ScanResult(
            scan_id=scan.id,
            control_id=control["control_id"],
            status=result_status,
            selected=is_selected,
            reason_code=None if is_selected else "unselected",
            provenance=(
                None
                if is_selected
                else {
                    "schema_version": 1,
                    "framework": scan.framework,
                    "benchmark": scan.benchmark,
                    "benchmark_version": scan.version,
                    "metadata_digest": metadata_digest,
                    "correlation_id": scan.correlation_id,
                    "control_id": control["control_id"],
                    "collector_id": control.get("data_collector_id"),
                    "policy_file": control.get("policy_file"),
                    "policy_digest": None,
                    "policy_source": None,
                    "engine_git_sha": None,
                    "engine_image_digest": None,
                    "input_digest": None,
                    "evaluation_started_at": None,
                    "opa_version": None,
                    "collection_started_at": None,
                    "collection_completed_at": None,
                    "evaluated_at": None,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "provenance_status": "not_executed",
                    "reason_code": "unselected",
                }
            ),
        )
        db.add(scan_result)

    scan.skipped_count = skipped
    db.add(
        ScanDispatch(
            id=scan.dispatch_id, scan_id=scan.id, task_name="worker.tasks.run_scan"
        )
    )
    await db.commit()
    await db.refresh(scan)

    return ScanCreatedResponse(
        id=scan.id,
        status="pending",
        message="Scan accepted for durable dispatch.",
    )


@router.get("/", response_model=list[ScanListItem])
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
    limit: int = 50,
    offset: int = 0,
) -> list[Scan]:
    """List scans for the current user."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.m365_connection))
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


# Get scan readiness status for a given M365 connection and benchmark. This is used by the frontend before starting a scan to validate the connection and provide feedback on any issues that might cause the scan to fail or have incomplete results.
@router.get("/readiness", response_model=ScanReadinessResponse)
async def get_scan_readiness(
    m365_connection_id: int,
    framework: str,
    benchmark: str,
    version: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ScanReadinessResponse:
    """Validate whether a scan can run successfully before queueing it."""
    # Readiness uses the saved M365 connection exactly as the user configured it.
    result = await db.execute(
        select(M365Connection).where(
            M365Connection.id == m365_connection_id,
            M365Connection.user_id == current_user.id,
            M365Connection.is_active.is_(True),
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"M365 connection {m365_connection_id} not found or inactive",
        )

    # Benchmark metadata is the source of truth for which controls are runnable and which permissions those controls declare.
    file_reader = get_file_reader()
    try:
        metadata = file_reader.get_benchmark_metadata(framework, benchmark, version)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark {framework}/{benchmark}/{version} not found",
        )

    if metadata.get("platform", "").lower() != "m365":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Benchmark platform '{metadata.get('platform')}' does not match M365 connection",
        )

    # The API layer only prepares inputs here. The actual readiness logic lives in scan_readiness.py so the route stays thin.
    required_permissions = extract_required_permissions(metadata.get("controls", []))
    readiness = await evaluate_scan_readiness(
        tenant_id=connection.tenant_id,
        client_id=connection.client_id,
        client_secret=decrypt(connection.encrypted_client_secret),
        required_permissions=required_permissions,
    )

    # Convert the service result into the response model returned to the frontend.
    return ScanReadinessResponse(
        ready=readiness.ready,
        summary=readiness.summary,
        required_permissions=readiness.required_permissions,
        missing_permissions=readiness.missing_permissions,
        unverified_permissions=readiness.unverified_permissions,
        checks=[
            ScanReadinessCheck(
                key=check.key,
                label=check.label,
                status=check.status,
                severity=check.severity,
                message=check.message,
            )
            for check in readiness.checks
        ],
    )


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> Scan:
    """Get scan details by ID including results."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.results), selectinload(Scan.m365_connection))
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )
    return scan


@router.get("/{scan_id}/provenance", response_model=ScanProvenanceRead)
async def get_scan_provenance(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ScanProvenanceRead:
    """Everything frozen at creation, without the two large snapshots.

    The snapshots themselves are megabyte-scale and are deliberately not part of
    any list or detail response; this endpoint reports their digests, their
    presence and their shape instead. The SOC 2 report renders the pinned
    mapping; the pinned metadata is already reflected in the result rows.
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Snapshots are JSONB columns frozen at creation. Shape is checked rather
    # than assumed so a malformed or legacy row degrades instead of raising.
    def _mapping_of(value):
        return value if isinstance(value, dict) else {}

    snapshot = _mapping_of(scan.metadata_snapshot)
    mapping = _mapping_of(scan.mapping_snapshot)
    approval = _mapping_of(mapping.get("approval"))
    connection = _mapping_of(scan.connection_snapshot)
    controls = snapshot.get("controls")
    points = mapping.get("points_of_focus")
    return ScanProvenanceRead(
        scan_id=scan.id,
        status=scan.status,
        framework=scan.framework,
        benchmark=scan.benchmark,
        version=scan.version,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        semantics_version=scan.semantics_version,
        lifecycle_version=scan.lifecycle_version,
        evidence_version=scan.evidence_version,
        correlation_id=scan.correlation_id,
        dispatch_id=scan.dispatch_id,
        selected_count=scan.selected_count,
        total_controls=scan.total_controls,
        metadata_digest=scan.metadata_digest,
        metadata_snapshot_present=scan.metadata_snapshot is not None,
        metadata_control_count=len(controls) if isinstance(controls, list) else 0,
        policy_corpus_digest=scan.policy_corpus_digest,
        connection_snapshot_present=scan.connection_snapshot is not None,
        # Field names only. No tenant, client or SharePoint value is returned.
        connection_snapshot_fields=sorted(
            key for key, value in connection.items() if value is not None
        ),
        mapping_id=scan.mapping_id,
        mapping_version=scan.mapping_version,
        mapping_digest=scan.mapping_digest,
        mapping_snapshot_present=scan.mapping_snapshot is not None,
        mapping_status=(
            mapping.get("status") if isinstance(mapping.get("status"), str) else None
        ),
        # Identity, not truthiness: a truthy string never reads as approved.
        mapping_approved=approval.get("approved") is True,
        mapping_points_of_focus_count=len(points) if isinstance(points, list) else 0,
        soc2_projection_available=bool(isinstance(points, list) and points),
    )


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def get_scan_summary(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ScanSummary:
    """Get a lightweight  summary for a scan."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    results = await db.execute(
        select(ScanResult.control_id, ScanResult.status).where(
            ScanResult.scan_id == scan_id
        )
    )
    rows = results.all()

    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "pending": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "error": 0,
            "indeterminate": 0,
            "not_assessable": 0,
        }
    )
    for control_id, status_ in rows:
        prefix = (
            control_id.split(".")[0] if "." in control_id else control_id.split("-")[0]
        )
        buckets[prefix]["total"] += 1
        if status_ in buckets[prefix]:
            buckets[prefix][status_] += 1

    categories = [
        ControlCategoryBreakdown(category=cat, **counts)
        for cat, counts in sorted(buckets.items())
    ]

    return ScanSummary(
        id=scan.id,
        status=scan.status,
        framework=scan.framework,
        benchmark=scan.benchmark,
        version=scan.version,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        compliance_score=scan.compliance_score,
        total_controls=scan.total_controls,
        passed_count=scan.passed_count,
        failed_count=scan.failed_count,
        skipped_count=scan.skipped_count,
        error_count=scan.error_count,
        pending_count=scan.pending_count,
        indeterminate_count=scan.indeterminate_count,
        not_assessable_count=scan.not_assessable_count,
        selected_count=scan.selected_count,
        coverage_score=scan.coverage_score,
        semantics_version=scan.semantics_version,
        metadata_digest=scan.metadata_digest,
        correlation_id=scan.correlation_id,
        dispatch_id=getattr(scan, "dispatch_id", None),
        dispatch_count=getattr(scan, "dispatch_count", 0),
        last_progress_at=getattr(scan, "last_progress_at", None),
        deadline_at=getattr(scan, "deadline_at", None),
        lifecycle_version=getattr(scan, "lifecycle_version", None),
        mapping_id=getattr(scan, "mapping_id", None),
        mapping_version=getattr(scan, "mapping_version", None),
        mapping_digest=getattr(scan, "mapping_digest", None),
        policy_corpus_digest=getattr(scan, "policy_corpus_digest", None),
        evidence_version=getattr(scan, "evidence_version", None),
        categories=categories,
    )


@router.get("/{scan_id}/results", response_model=list[ScanResultRead])
async def get_scan_results(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
    status_filter: ResultStatus | None = None,
) -> list[ScanResult]:
    """Get results for a scan.

    Optionally filter by any pending or terminal result status.
    """
    # Verify scan exists and user has access
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Build query
    query = select(ScanResult).where(ScanResult.scan_id == scan_id)
    if status_filter:
        query = query.where(ScanResult.status == status_filter)
    query = query.order_by(ScanResult.control_id)

    results = await db.execute(query)
    return list(results.scalars().all())


@router.post("/{scan_id}/cancel", response_model=ScanCreatedResponse)
async def cancel_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ScanCreatedResponse:
    """Serialize cancellation against every worker terminal write."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
        .with_for_update()
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan.status in {"completed", "failed", "cancelled"}:
        return ScanCreatedResponse(
            id=scan_id, status=scan.status, message="Scan is already terminal."
        )
    pending = await db.execute(
        select(ScanResult).where(
            ScanResult.scan_id == scan_id, ScanResult.status == "pending"
        )
    )
    metadata = {
        control["control_id"]: control
        for control in (scan.metadata_snapshot or {}).get("controls", [])
    }
    for row in pending.scalars():
        control = metadata.get(row.control_id, {})
        row.status = "indeterminate"
        row.reason_code = "scan_cancelled"
        row.message = "Scan cancelled before assessment completed."
        row.provenance = {
            "schema_version": 1,
            "framework": scan.framework,
            "benchmark": scan.benchmark,
            "benchmark_version": scan.version,
            "control_id": row.control_id,
            "collector_id": control.get("data_collector_id"),
            "policy_file": control.get("policy_file"),
            "metadata_digest": scan.metadata_digest,
            "correlation_id": scan.correlation_id,
            "provenance_status": "not_executed",
            "reason_code": "scan_cancelled",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            **{
                key: None
                for key in (
                    "policy_digest",
                    "policy_source",
                    "engine_git_sha",
                    "engine_image_digest",
                    "input_digest",
                    "evaluation_started_at",
                    "opa_version",
                    "collection_started_at",
                    "collection_completed_at",
                    "evaluated_at",
                )
            },
        }
    await db.flush()
    rows = await db.execute(
        select(ScanResult.status, func.count())
        .where(ScanResult.scan_id == scan_id)
        .group_by(ScanResult.status)
    )
    counts = dict(rows.all())
    for state in (
        "passed",
        "failed",
        "indeterminate",
        "error",
        "skipped",
        "not_assessable",
    ):
        setattr(scan, state + "_count", counts.get(state, 0))
    assessed = scan.passed_count + scan.failed_count
    scan.compliance_score = (
        round(100 * scan.passed_count / assessed, 2) if assessed else None
    )
    scan.coverage_score = (
        round(100 * assessed / scan.selected_count, 2) if scan.selected_count else None
    )
    scan.status = "cancelled"
    scan.finished_at = scan.last_progress_at = datetime.now(timezone.utc).replace(
        tzinfo=None
    )
    await db.execute(delete(ScanDispatch).where(ScanDispatch.scan_id == scan_id))
    await db.commit()
    return ScanCreatedResponse(
        id=scan_id, status="cancelled", message="Scan cancelled."
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> None:
    """Delete a scan (hard delete) and its results."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
        .with_for_update()
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Delete dependent results first (FK is not ON DELETE CASCADE).
    await db.execute(delete(ScanDispatch).where(ScanDispatch.scan_id == scan_id))
    await db.execute(delete(ScanResult).where(ScanResult.scan_id == scan_id))
    await db.delete(scan)
    await db.commit()
