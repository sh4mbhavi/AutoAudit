"""Manual / inherited evidence approval workflow API (Phase 7, plan item 15.1.5).

Every route is authenticated. Submitter actions are authorized through the
parent ``Scan``, which is the authoritative owner of a scan result; reviewer
actions additionally require the auditor or admin role and an actor who is not
the record's submitter.

A record that the caller may not read returns 404, identical to a record that
does not exist, so these routes cannot be used to discover another tenant's
evidence.

Nothing here writes ``scan_result`` or ``scan``. Approving manual evidence
records assurance in a separate residual stream; it never changes a control's
assessed status, the scan's counters, the compliance score or the coverage
score.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.permissions import require_auditor_or_above
from app.db.session import get_async_session
from app.models.compliance import Scan
from app.models.manual_evidence import ManualEvidenceRecord
from app.models.scan_result import ScanResult
from app.models.user import Role, User
from app.schemas.manual_evidence import (
    ManualControlTemplateRead,
    ManualEvidenceAmend,
    ManualEvidenceComment,
    ManualEvidenceCreate,
    ManualEvidenceRead,
    ManualEvidenceReject,
    ManualEvidenceRevisionRead,
    ManualEvidenceWithHistory,
)
from app.services import manual_evidence as workflow

router = APIRouter(prefix="/manual-evidence", tags=["Manual Evidence"])

# The benchmark version the shipped auditor instruction templates cover. Callers
# override it explicitly, or pass a scan id to use that scan's pinned identity.
DEFAULT_TEMPLATE_FRAMEWORK = "cis"
DEFAULT_TEMPLATE_BENCHMARK = "microsoft-365-foundations"
DEFAULT_TEMPLATE_VERSION = "v6.0.0"

CONTROL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$"
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
VERSION_PATTERN = r"^v[0-9]+(\.[0-9]+){0,3}$"

_NOT_FOUND = "Manual evidence record not found"


def _fail(error: workflow.ManualEvidenceError) -> HTTPException:
    """Map a workflow error onto its HTTP status with a stable code."""
    return HTTPException(status_code=error.status_code, detail=error.as_detail())


def _is_reviewer(user: User) -> bool:
    """Reviewer authority comes from the existing global role column."""
    return getattr(user, "role", None) in {Role.ADMIN.value, Role.AUDITOR.value}


async def _owns_scan(db: AsyncSession, scan_id: int, user: User) -> bool:
    result = await db.execute(
        select(Scan.id).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    return result.scalar_one_or_none() is not None


async def _readable_record(
    db: AsyncSession,
    user: User,
    *,
    record_id: Optional[int] = None,
    scan_result_id: Optional[int] = None,
) -> ManualEvidenceRecord:
    """Fetch a record the caller may see, or 404 without disclosing existence."""
    record = await workflow.get_record(
        db, record_id=record_id, scan_result_id=scan_result_id
    )
    if record is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    if record.user_id == user.id and await _owns_scan(db, record.scan_id, user):
        return record
    # A reviewer sees what has entered review. Someone else's draft is private
    # working state and stays invisible until it is submitted.
    if _is_reviewer(user) and record.status != "draft":
        return record
    raise HTTPException(status_code=404, detail=_NOT_FOUND)


def _require_submitter(record: ManualEvidenceRecord, user: User) -> None:
    """Submit, amend and withdraw belong to the account that submitted."""
    if record.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the submitting account can change this record",
        )


def _request_id(request: Request) -> Optional[str]:
    return workflow.safe_request_id(getattr(request.state, "request_id", None))


# ---------------------------------------------------------------------------
# Specific paths first: an integer {record_id} would otherwise shadow them.
# ---------------------------------------------------------------------------


@router.get("/review-queue", response_model=list[ManualEvidenceRead])
async def review_queue(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> list[ManualEvidenceRead]:
    """Records awaiting review, never including the caller's own submissions."""
    result = await db.execute(
        select(ManualEvidenceRecord)
        .where(
            ManualEvidenceRecord.status == "submitted",
            ManualEvidenceRecord.user_id != current_user.id,
        )
        .order_by(ManualEvidenceRecord.updated_at, ManualEvidenceRecord.id)
        .limit(limit)
        .offset(offset)
    )
    return [ManualEvidenceRead.from_record(row) for row in result.scalars().all()]


@router.get("/controls/{control_id}/template", response_model=ManualControlTemplateRead)
async def control_template(
    control_id: str = Path(pattern=CONTROL_ID_PATTERN),
    scan_id: Optional[int] = Query(default=None),
    framework: str = Query(default=DEFAULT_TEMPLATE_FRAMEWORK, pattern=SLUG_PATTERN),
    benchmark: str = Query(default=DEFAULT_TEMPLATE_BENCHMARK, pattern=SLUG_PATTERN),
    version: str = Query(default=DEFAULT_TEMPLATE_VERSION, pattern=VERSION_PATTERN),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualControlTemplateRead:
    """Read-only auditor instructions for a manual control.

    A control with no template entry returns 404. That means "this benchmark
    version ships no manual collection instructions for this control", which is
    not a statement about the control's result either way.
    """
    if scan_id is not None:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        framework, benchmark, version = scan.framework, scan.benchmark, scan.version

    try:
        template = workflow.get_manual_control_template(
            framework, benchmark, version, control_id
        )
    except workflow.ManualEvidenceError as error:
        raise _fail(error) from None
    if template is None:
        raise HTTPException(
            status_code=404,
            detail="No manual evidence template for this control",
        )
    return ManualControlTemplateRead(
        framework=str(template.get("framework") or framework),
        benchmark=str(template.get("benchmark") or benchmark),
        version=str(template.get("version") or version),
        control_id=control_id,
        title=template.get("title"),
        severity=template.get("severity"),
        evidence_type=template.get("evidence_type"),
        keywords=template.get("keywords"),
        instructions=template.get("instructions"),
    )


@router.get("/by-scan-result/{scan_result_id}", response_model=ManualEvidenceRead)
async def get_by_scan_result(
    scan_result_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Read the record for one scan result."""
    record = await _readable_record(db, current_user, scan_result_id=scan_result_id)
    return ManualEvidenceRead.from_record(record)


# ---------------------------------------------------------------------------
# Record lifecycle.
# ---------------------------------------------------------------------------


@router.post(
    "/", response_model=ManualEvidenceRead, status_code=status.HTTP_201_CREATED
)
async def create_record(
    payload: ManualEvidenceCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Open a draft for a scan result the caller owns through its parent scan."""
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == payload.scan_result_id)
    )
    scan_result = result.scalar_one_or_none()
    if scan_result is None:
        raise HTTPException(status_code=404, detail="Scan result not found")

    owner = await db.execute(
        select(Scan).where(
            Scan.id == scan_result.scan_id, Scan.user_id == current_user.id
        )
    )
    scan = owner.scalar_one_or_none()
    if scan is None:
        # Same answer as a missing scan result: no cross-tenant existence oracle.
        raise HTTPException(status_code=404, detail="Scan result not found")

    try:
        record = await workflow.create_draft(
            db,
            scan=scan,
            scan_result_id=scan_result.id,
            control_id=scan_result.control_id,
            actor_user_id=current_user.id,
            actor_role=str(getattr(current_user, "role", Role.VIEWER.value)),
            evidence_source=payload.evidence_source,
            control_owner=payload.control_owner,
            evidence_owner=payload.evidence_owner,
            collection_period_start=payload.collection_period_start,
            collection_period_end=payload.collection_period_end,
            expires_at=payload.expires_at,
            cadence=payload.cadence,
            comment=payload.comment,
            attachment_object_ids=payload.attachment_object_ids,
            external_references=payload.external_references,
            request_id=_request_id(request),
        )
    except workflow.ManualEvidenceError as error:
        await db.rollback()
        raise _fail(error) from None
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "manual_evidence_exists",
                "message": "Manual evidence already exists for this scan result.",
            },
        ) from None
    except DBAPIError:
        # A driver-level rejection (for example an unrepresentable character)
        # must still be a typed answer with a clean session, never a 500.
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "manual_evidence_not_storable",
                "message": "The submitted values could not be stored.",
            },
        ) from None
    return ManualEvidenceRead.from_record(record)


@router.get("/{record_id}", response_model=ManualEvidenceRead)
async def get_record(
    record_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Read one record."""
    record = await _readable_record(db, current_user, record_id=record_id)
    return ManualEvidenceRead.from_record(record)


@router.get("/{record_id}/revisions", response_model=ManualEvidenceWithHistory)
async def get_revisions(
    record_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceWithHistory:
    """The complete append-only decision history for one record."""
    record = await _readable_record(db, current_user, record_id=record_id)
    revisions = await workflow.list_revisions(db, record.id)
    return ManualEvidenceWithHistory(
        **ManualEvidenceRead.from_record(record).model_dump(),
        revisions=[
            ManualEvidenceRevisionRead.model_validate(revision)
            for revision in revisions
        ],
    )


async def _transition(
    db: AsyncSession,
    *,
    record: ManualEvidenceRecord,
    action: str,
    actor: User,
    request: Request,
    **kwargs,
) -> ManualEvidenceRead:
    try:
        updated = await workflow.apply_transition(
            db,
            record_id=record.id,
            action=action,
            actor_user_id=actor.id,
            actor_role=str(getattr(actor, "role", Role.VIEWER.value)),
            request_id=_request_id(request),
            **kwargs,
        )
    except workflow.ManualEvidenceError as error:
        await db.rollback()
        raise _fail(error) from None
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "manual_evidence_conflict",
                "message": "The record changed before this decision could be stored.",
            },
        ) from None
    except DBAPIError:
        # A driver-level rejection (for example an unrepresentable character)
        # must still be a typed answer with a clean session, never a 500.
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "manual_evidence_not_storable",
                "message": "The submitted values could not be stored.",
            },
        ) from None
    return ManualEvidenceRead.from_record(updated)


@router.post("/{record_id}/submit", response_model=ManualEvidenceRead)
async def submit_record(
    record_id: int,
    request: Request,
    payload: Optional[ManualEvidenceComment] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Send a draft for independent review."""
    record = await _readable_record(db, current_user, record_id=record_id)
    _require_submitter(record, current_user)
    return await _transition(
        db,
        record=record,
        action="submit",
        actor=current_user,
        request=request,
        comment=payload.comment if payload else None,
    )


@router.post("/{record_id}/amend", response_model=ManualEvidenceRead)
async def amend_record(
    record_id: int,
    payload: ManualEvidenceAmend,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Write a new revision. Earlier revisions are never modified."""
    record = await _readable_record(db, current_user, record_id=record_id)
    _require_submitter(record, current_user)
    return await _transition(
        db,
        record=record,
        action="amend",
        actor=current_user,
        request=request,
        comment=payload.comment,
        attachment_object_ids=payload.attachment_object_ids,
        external_references=payload.external_references,
        replace_evidence_set=True,
        record_updates={
            "control_owner": payload.control_owner,
            "evidence_owner": payload.evidence_owner,
            "collection_period_start": payload.collection_period_start,
            "collection_period_end": payload.collection_period_end,
            "expires_at": payload.expires_at,
            "cadence": payload.cadence,
        },
    )


@router.post("/{record_id}/withdraw", response_model=ManualEvidenceRead)
async def withdraw_record(
    record_id: int,
    request: Request,
    payload: Optional[ManualEvidenceComment] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Retract a record. Nothing is deleted; the history stays readable."""
    record = await _readable_record(db, current_user, record_id=record_id)
    _require_submitter(record, current_user)
    return await _transition(
        db,
        record=record,
        action="withdraw",
        actor=current_user,
        request=request,
        comment=payload.comment if payload else None,
    )


@router.post("/{record_id}/approve", response_model=ManualEvidenceRead)
async def approve_record(
    record_id: int,
    request: Request,
    payload: Optional[ManualEvidenceComment] = None,
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Approve submitted evidence.

    Approval is a statement about the evidence, not about the control. It does
    not change the scan result, the scan counters or either score.
    """
    record = await _readable_record(db, current_user, record_id=record_id)
    return await _transition(
        db,
        record=record,
        action="approve",
        actor=current_user,
        request=request,
        comment=payload.comment if payload else None,
    )


@router.post("/{record_id}/reject", response_model=ManualEvidenceRead)
async def reject_record(
    record_id: int,
    payload: ManualEvidenceReject,
    request: Request,
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> ManualEvidenceRead:
    """Reject submitted evidence. A reason is required and is recorded."""
    record = await _readable_record(db, current_user, record_id=record_id)
    return await _transition(
        db,
        record=record,
        action="reject",
        actor=current_user,
        request=request,
        comment=payload.comment,
        rejection_reason=payload.reason,
    )
