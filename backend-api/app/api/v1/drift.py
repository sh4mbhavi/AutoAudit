"""Configuration drift API (Phase 8, plan item 16.2).

Reports only. No route in this file creates, promotes, infers or alters a SOC 2
rating, a scan result or a score, and no drift row is ever counted as automated
coverage. The backend also never *computes* drift: the algorithm lives once, in
the worker. ``POST /v1/drift/runs`` enqueues a computation and writes nothing.

Four conventions hold on every route, and each closes a specific failure:

* authentication is a router-level dependency, so a route added later cannot
  regress to anonymous access (the ``evidence.py`` idiom);
* every scan-, baseline-, run- and thread-addressed lookup resolves ownership
  *inside the same SELECT*, and a row belonging to another account answers 404
  rather than 403. These routes are not an existence oracle for another
  tenant's scans;
* list endpoints are bounded and return ``{items, limit, offset, returned}``.
  There is no COUNT and no total anywhere in this codebase;
* every error body is ``{"code": ..., "message": ...}``. An ``IntegrityError``
  becomes 409 and a ``DBAPIError`` becomes 422 after a rollback, so a database
  constraint never reaches a caller as a 500 with a traceback.

Every response that can carry events also carries ``no_events_means``. An empty
event list is the single most misreadable thing this API returns: it means the
compared observations were identical, never that the tenant did not change and
never that a control passed.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.permissions import require_auditor_or_above
from app.db.session import get_async_session
from app.models.user import User
from app.schemas.drift import (
    DriftBaselineCreate,
    DriftBaselineList,
    DriftBaselineRead,
    DriftEventList,
    DriftEventRead,
    DriftNotificationAcknowledge,
    DriftNotificationRemediation,
    DriftNotificationRevisionRead,
    DriftNotificationThread,
    DriftNotificationThreadWithHistory,
    DriftNotificationVerify,
    DriftRunList,
    DriftRunRead,
    DriftRunRequest,
    DriftScanStatus,
)
from app.services import drift as drift_service
from app.services import drift_notifications as notifications

# Authentication sits on the router, not on the handlers, so no future route can
# be added without it. Handlers additionally declare the user they need.
router = APIRouter(
    prefix="/drift",
    tags=["Drift"],
    dependencies=[Depends(get_current_user)],
)

# A thread key is a full 64-hex digest. Nothing shorter is accepted: a truncated
# digest accepts collisions whose failure mode is acting on the wrong finding.
THREAD_KEY_PATTERN = r"^[0-9a-f]{64}$"

SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
VERSION_PATTERN = r"^v[0-9]+(\.[0-9]+){0,3}$"
CONTROL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$"


class DriftNotificationThreadList(BaseModel):
    """One page of derived threads.

    Declared here rather than in ``app/schemas/drift.py`` because a thread is
    not a stored row: it is the projection this router computes from the newest
    revision. The envelope is the same {items, limit, offset, returned} shape as
    every other list in this API, and it carries no total.
    """

    items: list[DriftNotificationThread]
    limit: int
    offset: int
    returned: int


def _fail(error: drift_service.DriftError) -> HTTPException:
    """Map a typed drift failure onto its HTTP status with a stable code."""
    return HTTPException(status_code=error.status_code, detail=error.as_detail())


async def _guarded(db: AsyncSession, awaitable: Any) -> Any:
    """Await one service call, turning every database fault into a typed body.

    The ``IntegrityError`` and ``DBAPIError`` arms mirror
    ``manual_evidence.py``: a constraint or a driver-level rejection must still
    be an answer with a clean session, never a 500.
    """
    try:
        return await awaitable
    except drift_service.DriftError as error:
        await db.rollback()
        raise _fail(error) from None
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "drift_conflict",
                "message": drift_service.ERROR_MESSAGES["drift_conflict"],
            },
        ) from None
    except DBAPIError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "drift_not_storable",
                "message": drift_service.ERROR_MESSAGES["drift_not_storable"],
            },
        ) from None


def _request_id(request: Request) -> Optional[str]:
    return notifications.safe_request_id(getattr(request.state, "request_id", None))


def _page(items: list[Any], limit: int, offset: int) -> dict[str, Any]:
    """The house list envelope. Deliberately no total: this API issues no COUNT."""
    return {
        "items": items,
        "limit": limit,
        "offset": offset,
        "returned": len(items),
    }


# ---------------------------------------------------------------------------
# Baselines.
# ---------------------------------------------------------------------------


@router.post(
    "/baselines",
    response_model=DriftBaselineRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_baseline(
    payload: DriftBaselineCreate,
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> DriftBaselineRead:
    """Pin one completed, fact-bearing scan as the comparison point.

    Establishing a baseline records what was observed; it asserts nothing about
    whether the tenant is compliant.
    """
    scan = await _guarded(
        db, drift_service.owned_scan(db, payload.scan_id, current_user.id)
    )
    baseline = await _guarded(
        db,
        drift_service.establish_baseline(
            db, scan=scan, actor_user_id=current_user.id, note=payload.note
        ),
    )
    return DriftBaselineRead.model_validate(baseline)


@router.get("/baselines", response_model=DriftBaselineList)
async def list_baselines(
    framework: Optional[str] = Query(default=None, pattern=SLUG_PATTERN),
    benchmark: Optional[str] = Query(default=None, pattern=SLUG_PATTERN),
    version: Optional[str] = Query(default=None, pattern=VERSION_PATTERN),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftBaselineList:
    """One page of the caller's baselines. Never another account's."""
    rows = await _guarded(
        db,
        drift_service.list_baselines(
            db,
            user_id=current_user.id,
            framework=framework,
            benchmark=benchmark,
            version=version,
            status=status_filter,
            limit=limit,
            offset=offset,
        ),
    )
    items = [DriftBaselineRead.model_validate(row) for row in rows]
    return DriftBaselineList(**_page(items, limit, offset))


@router.get("/baselines/{baseline_id}", response_model=DriftBaselineRead)
async def read_baseline(
    baseline_id: int = Path(ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftBaselineRead:
    """Read one baseline."""
    baseline = await _guarded(
        db, drift_service.get_baseline(db, baseline_id, current_user.id)
    )
    return DriftBaselineRead.model_validate(baseline)


@router.post("/baselines/{baseline_id}/revoke", response_model=DriftBaselineRead)
async def revoke_baseline(
    baseline_id: int = Path(ge=1),
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> DriftBaselineRead:
    """Retire one active baseline. No run and no event is rewritten."""
    baseline = await _guarded(
        db,
        drift_service.revoke_baseline(
            db, baseline_id=baseline_id, user_id=current_user.id
        ),
    )
    return DriftBaselineRead.model_validate(baseline)


# ---------------------------------------------------------------------------
# Runs and events.
# ---------------------------------------------------------------------------


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
async def request_run(
    payload: DriftRunRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> dict[str, Any]:
    """Ask the worker to compare one scan against one baseline.

    This writes nothing. The comparison is computed once, in the worker, and its
    UNIQUE (baseline_id, current_scan_id) makes a duplicate delivery a no-op.
    """
    baseline = await _guarded(
        db, drift_service.get_baseline(db, payload.baseline_id, current_user.id)
    )
    await _guarded(db, drift_service.owned_scan(db, payload.scan_id, current_user.id))
    existing = await _guarded(
        db,
        drift_service.list_runs(
            db,
            user_id=current_user.id,
            baseline_id=baseline.id,
            scan_id=payload.scan_id,
            limit=1,
        ),
    )
    if existing:
        raise _fail(drift_service.DriftError(409, "drift_run_exists"))
    try:
        drift_service.queue_drift_run(baseline.id, payload.scan_id)
    except drift_service.DriftError as error:
        raise _fail(error) from None
    return {
        "code": "drift_evaluation_queued",
        "baseline_id": baseline.id,
        "scan_id": payload.scan_id,
    }


@router.get("/runs", response_model=DriftRunList)
async def list_runs(
    baseline_id: Optional[int] = Query(default=None, ge=1),
    scan_id: Optional[int] = Query(default=None, ge=1),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftRunList:
    """One page of the caller's runs."""
    rows = await _guarded(
        db,
        drift_service.list_runs(
            db,
            user_id=current_user.id,
            baseline_id=baseline_id,
            scan_id=scan_id,
            status=status_filter,
            limit=limit,
            offset=offset,
        ),
    )
    items = [DriftRunRead.model_validate(row) for row in rows]
    return DriftRunList(**_page(items, limit, offset))


@router.get("/runs/{run_id}", response_model=DriftRunRead)
async def read_run(
    run_id: int = Path(ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftRunRead:
    """Read one run. Its events are never inlined; they are paged separately."""
    run = await _guarded(db, drift_service.get_run(db, run_id, current_user.id))
    return DriftRunRead.model_validate(run)


@router.get("/runs/{run_id}/events", response_model=DriftEventList)
async def list_run_events(
    run_id: int = Path(ge=1),
    event_class: Optional[str] = Query(default=None),
    change_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    control_id: Optional[str] = Query(default=None, pattern=CONTROL_ID_PATTERN),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftEventList:
    """One page of one run's events, with the run's own status alongside.

    ``run_status`` matters here: an empty page means one thing on a completed
    run and something entirely different on a run that could not compare at all.
    """
    run = await _guarded(db, drift_service.get_run(db, run_id, current_user.id))
    rows = await _guarded(
        db,
        drift_service.list_events(
            db,
            run=run,
            event_class=event_class,
            change_type=change_type,
            severity=severity,
            control_id=control_id,
            limit=limit,
            offset=offset,
        ),
    )
    items = [DriftEventRead.model_validate(row) for row in rows]
    return DriftEventList(**_page(items, limit, offset), run_status=run.status)


@router.get("/scans/{scan_id}", response_model=DriftScanStatus)
async def read_scan_drift(
    scan_id: int = Path(ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftScanStatus:
    """Where one scan stands with respect to drift.

    "No baseline" and "facts unavailable" are explicit answers, never an empty
    list: "nothing to show" and "nothing changed" are not the same claim.
    """
    payload = await _guarded(
        db, drift_service.scan_drift_status(db, scan_id, current_user.id)
    )
    run = payload.pop("run", None)
    return DriftScanStatus(
        **payload, run=None if run is None else DriftRunRead.model_validate(run)
    )


# ---------------------------------------------------------------------------
# Notification threads. State is derived from the newest revision; nothing here
# rewrites history.
# ---------------------------------------------------------------------------


@router.get("/notifications", response_model=DriftNotificationThreadList)
async def list_notifications(
    state: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftNotificationThreadList:
    """One page of the caller's notification threads, newest activity first."""
    threads = await _guarded(
        db,
        notifications.latest_revisions(
            db,
            user_id=current_user.id,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        ),
    )
    items = [DriftNotificationThread(**thread) for thread in threads]
    return DriftNotificationThreadList(**_page(items, limit, offset))


@router.get(
    "/notifications/{thread_key}",
    response_model=DriftNotificationThreadWithHistory,
)
async def read_notification(
    thread_key: str = Path(pattern=THREAD_KEY_PATTERN),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftNotificationThreadWithHistory:
    """One thread with its complete append-only history."""
    thread = await _guarded(
        db, notifications.get_thread(db, thread_key, current_user.id)
    )
    revisions = await _guarded(
        db, notifications.thread_history(db, thread_key, current_user.id)
    )
    return DriftNotificationThreadWithHistory(
        **thread,
        revisions=[
            DriftNotificationRevisionRead.model_validate(revision)
            for revision in revisions
        ],
    )


@router.post(
    "/notifications/{thread_key}/acknowledge",
    response_model=DriftNotificationThread,
)
async def acknowledge_notification(
    request: Request,
    payload: Optional[DriftNotificationAcknowledge] = None,
    thread_key: str = Path(pattern=THREAD_KEY_PATTERN),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftNotificationThread:
    """Acknowledge a thread. Acknowledging is not a claim that anything is fixed."""
    thread = await _guarded(
        db,
        notifications.append_revision(
            db,
            thread_key=thread_key,
            action="acknowledged",
            actor_user_id=current_user.id,
            note=payload.note if payload else None,
            request_id=_request_id(request),
            user_id=current_user.id,
        ),
    )
    return DriftNotificationThread(**thread)


@router.post(
    "/notifications/{thread_key}/remediation",
    response_model=DriftNotificationThread,
)
async def record_remediation(
    payload: DriftNotificationRemediation,
    request: Request,
    thread_key: str = Path(pattern=THREAD_KEY_PATTERN),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftNotificationThread:
    """Plan remediation, or accept the risk. Either way a reason is recorded."""
    thread = await _guarded(
        db,
        notifications.append_revision(
            db,
            thread_key=thread_key,
            action=payload.state,
            actor_user_id=current_user.id,
            note=payload.note,
            request_id=_request_id(request),
            user_id=current_user.id,
        ),
    )
    return DriftNotificationThread(**thread)


@router.post(
    "/notifications/{thread_key}/verify",
    response_model=DriftNotificationThread,
)
async def verify_remediation(
    payload: DriftNotificationVerify,
    request: Request,
    thread_key: str = Path(pattern=THREAD_KEY_PATTERN),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> DriftNotificationThread:
    """Claim a remediation, and prove it.

    The proof is a later completed run against the same baseline in which the
    finding does not recur. Without one this is 422, not a recorded fix.
    """
    thread = await _guarded(
        db,
        notifications.verify_remediation(
            db,
            thread_key=thread_key,
            scan_id=payload.scan_id,
            user_id=current_user.id,
            actor_user_id=current_user.id,
            request_id=_request_id(request),
        ),
    )
    return DriftNotificationThread(**thread)
