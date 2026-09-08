"""Scan API endpoints."""

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import get_current_user
from app.db.session import get_async_session
from app.models.compliance import Scan
from app.models.m365_connection import M365Connection
from app.models.scan_result import ScanResult
from app.models.user import User
from app.schemas.scan import (
    ResultStatus,
    ScanCreate,
    ScanCreatedResponse,
    ControlCategoryBreakdown,
    ScanListItem,
    ScanReadinessCheck,
    ScanReadinessResponse,
    ScanRead,
    ScanResultRead,
    ScanSummary,
)
from app.services.benchmark_reader import get_file_reader
from app.services.celery_client import queue_scan
from app.services.encryption import decrypt
from app.services.scan_readiness import (
    evaluate_scan_readiness,
    extract_required_permissions,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "/", response_model=ScanCreatedResponse, status_code=status.HTTP_201_CREATED
)
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ScanCreatedResponse:
    """Create a new compliance scan.

    Creates a scan record with all ScanResult records and queues a Celery task.
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
        correlation_id=str(uuid4()),
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
    await db.commit()
    await db.refresh(scan)

    # Queue Celery task
    task = queue_scan(scan.id)

    return ScanCreatedResponse(
        id=scan.id,
        status="pending",
        message=f"Scan queued successfully. Task ID: {task.id}",
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


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> None:
    """Delete a scan (hard delete) and its results."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Delete dependent results first (FK is not ON DELETE CASCADE).
    await db.execute(delete(ScanResult).where(ScanResult.scan_id == scan_id))
    await db.delete(scan)
    await db.commit()
