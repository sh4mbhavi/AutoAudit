"""Authenticated, ownership-checked, bounded evidence object API.

This router replaces the Phase 6 evidence endpoints and closes three findings.

**AUTH-01** — ``GET /v1/evidence/reports/{filename}`` bound the current user and
then never used it, so any authenticated caller could download any other
tenant's report from a guessable ``{user_id}-{strategy}-{stem}-{unix}`` name.
Authorization is now never by filename: every read resolves one row by
``(object_id, user_id)`` and a miss is a 404, so the endpoint is not an
existence oracle for other tenants.

**AUTH-02** — ``/strategies``, ``/health``, ``/scan-mem``, ``/scan-mem-log``,
``/recent-scans`` and ``/scan-log`` had no authentication at all. The four
cross-tenant and debug routes are gone. ``/strategies`` and ``/health`` remain
but require a session, and ``/health`` answers with a boolean instead of
absolute container paths and an OCR version probe. The dependency sits on the
router itself, so a route added later cannot regress to anonymous access.

**EVI-01** — uploads are streamed to tenant-scoped random storage keys under a
hard byte ceiling, typed from magic bytes rather than the client's extension,
and extracted exactly once inside a worker thread under page, pixel, archive,
character and time bounds. Every bound fails closed with a stable code. The
multipart body is parsed by these routes rather than declared as an
``UploadFile`` parameter, because FastAPI parses a declared body *before* it
solves dependencies: an unbounded file would otherwise be spooled to disk
before either the ceiling or the session check ran.

Report *generation* is deliberately still synchronous, but it no longer runs the
legacy template/``docx2pdf`` path: that flow shells out to ``soffice`` with no
timeout, and a subprocess cannot be reclaimed when the request deadline passes.
The report produced here is a bounded plain-text summary built in process, with
no converter, no template and no unbounded write. Moving generation to the
Celery worker remains the correct end state and is recorded in the handoff.
"""

from __future__ import annotations

import hashlib
import inspect
import logging
import re
import sys
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from importlib import import_module
from pathlib import Path
from urllib.parse import quote

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi import Path as PathParam
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import FormData, UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from app.core.auth import get_current_user
from app.core.config import Settings, get_settings
from app.db.session import get_async_session
from app.models.compliance import Scan
from app.models.evidence_artifact import EvidenceArtifact
from app.models.evidence_audit_event import EvidenceAuditEvent
from app.models.evidence_validation import EvidenceValidation
from app.models.scan_result import ScanResult
from app.models.user import User
from pydantic import ValidationError

from app.core.permissions import require_auditor_or_above
from app.schemas.evidence_artifact import (
    EvidenceArtifactList,
    EvidenceArtifactRead,
    EvidenceAuditEventList,
    EvidenceReadiness,
    EvidenceScanResponse,
    EvidenceUploadAccepted,
    LegalHoldRequest,
)
from app.services import evidence_audit, evidence_processing, evidence_storage
from app.services.encryption import encrypt
from app.services.evidence_processing import EvidenceRejected
from app.services.evidence_storage import (
    EvidenceStorage,
    EvidenceStorageError,
    EvidenceTooLargeError,
)
from app.services.evidence_validator import validate_text

logger = logging.getLogger("api")

# Authentication is a router-level dependency so no future route can be added
# without it. Each handler also declares the user it needs (AUTH-02).
router = APIRouter(
    prefix="/evidence",
    tags=["evidence"],
    dependencies=[Depends(get_current_user)],
)


def object_id_param():
    """A fresh path parameter per route; ids are opaque, never filenames."""
    return PathParam(
        ...,
        pattern=r"^[A-Za-z0-9_-]{43}$",
        description="Opaque evidence object id. Never a filename.",
    )


_CONTROL_ID_PATTERN = re.compile(r"\A[A-Za-z0-9._:-]{1,50}\Z")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_ASCII_FILENAME = re.compile(r"[^A-Za-z0-9._-]")

_MAX_FILENAME_LENGTH = 255
_MAX_ENCRYPTED_EXCERPT_CHARS = 20000
_MAX_REPORT_BYTES = 256 * 1024
_MAX_REPORT_FINDINGS = 200
# Room for the multipart envelope around the file: boundaries, part headers and
# the handful of small text fields these routes accept.
_MULTIPART_OVERHEAD_BYTES = 64 * 1024
_MAX_FIELD_BYTES = 4096
# Legacy strategies can return server-side locations in a finding. They are the
# scanner's own filesystem, never the caller's evidence, so they are stripped.
_SERVER_PATH_KEYS = frozenset({"absolute_path", "full_path", "path", "evidence_dir"})

STATUS_PENDING = "pending"
STATUS_PROCESSING = "processing"
STATUS_AVAILABLE = "available"
STATUS_FAILED = "failed"
STATUS_DELETED = "deleted"

KIND_UPLOAD = "upload"
KIND_REPORT = "report"

# HTTP status for each redacted failure code. Everything defaults to 422 so a
# parser fault can never surface as a 500 with a traceback.
_FAILURE_STATUS: dict[str, int] = {
    evidence_processing.FAILURE_TOO_LARGE: status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    evidence_processing.FAILURE_UNSUPPORTED_TYPE: status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    evidence_processing.FAILURE_TYPE_MISMATCH: status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    evidence_processing.FAILURE_TIMEOUT: status.HTTP_504_GATEWAY_TIMEOUT,
    evidence_processing.FAILURE_ENGINE_UNAVAILABLE: status.HTTP_503_SERVICE_UNAVAILABLE,
    evidence_processing.FAILURE_OCR_UNAVAILABLE: status.HTTP_503_SERVICE_UNAVAILABLE,
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _now() -> datetime:
    """Naive UTC, matching the ``timestamp without time zone`` columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _rejection(code: str, limit: int | None = None) -> HTTPException:
    detail: dict[str, object] = {"code": code}
    if limit is not None:
        detail["limit"] = limit
    return HTTPException(
        status_code=_FAILURE_STATUS.get(code, status.HTTP_422_UNPROCESSABLE_ENTITY),
        detail=detail,
    )


def _not_found() -> HTTPException:
    """A miss and a foreign object answer identically, by design."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "evidence_not_found"},
    )


def _safe_display_filename(raw: str | None) -> str:
    """Display only. This value never locates or authorizes anything."""
    candidate = Path(raw or "").name
    candidate = _CONTROL_CHARACTERS.sub("", candidate).strip()
    candidate = candidate.replace("\\", "").strip()
    if not candidate or candidate in {".", ".."}:
        return "evidence"
    return candidate[:_MAX_FILENAME_LENGTH]


def _content_disposition(display_filename: str, object_id: str) -> str:
    """Attachment only, with an ASCII fallback and an RFC 5987 form."""
    ascii_name = _ASCII_FILENAME.sub("_", display_filename)[:_MAX_FILENAME_LENGTH]
    if not ascii_name.strip("_"):
        ascii_name = object_id
    encoded = quote(display_filename, safe="")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"


def _download_headers(artifact: EvidenceArtifact) -> dict[str, str]:
    """Never serve stored bytes as an executable type in the app origin."""
    return {
        "Content-Disposition": _content_disposition(
            artifact.display_filename, artifact.object_id
        ),
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "no-store",
        "Content-Length": str(artifact.byte_size),
    }


LEGACY_UI_MODULE = "security.evidence_ui.app"
LEGACY_STRATEGY_MODULE = "security.strategies"


def _legacy(module_name: str, attribute: str):
    """Import one pure helper from the legacy package, lazily and closed.

    ``security/evidence_ui/app.py`` is being hardened concurrently, so nothing
    from ``security`` is imported at module import time: a signature change over
    there must not be able to break API startup. Only the two pure helpers this
    router genuinely needs are ever imported, each one inside the request that
    uses it, and any failure fails closed with a 503 rather than a traceback.
    """
    try:
        root = Path(__file__).resolve().parents[4]
        if (root / "security").is_dir() and str(root) not in sys.path:
            sys.path.insert(0, str(root))
        module = import_module(module_name)
        helper = getattr(module, attribute)
    except Exception as error:  # noqa: BLE001 - legacy import must fail closed
        logger.warning("Legacy evidence helper unavailable: %s", attribute)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": evidence_processing.FAILURE_ENGINE_UNAVAILABLE},
        ) from error
    if not callable(helper):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": evidence_processing.FAILURE_ENGINE_UNAVAILABLE},
        )
    return helper


def _storage(settings: Settings) -> EvidenceStorage:
    try:
        return evidence_storage.get_storage(settings)
    except EvidenceStorageError as error:
        logger.error("Evidence storage backend is not usable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "evidence_storage_unavailable"},
        ) from error


async def _single_chunk(payload: bytes) -> AsyncIterator[bytes]:
    yield payload


# ---------------------------------------------------------------------------
# bounded ingress
# ---------------------------------------------------------------------------
class _BoundedMultiPartParser(MultiPartParser):
    """Starlette's parser with a ceiling on the file part as well as the fields.

    Starlette caps non-file parts with ``max_part_size`` but streams a file part
    into a spooled temporary file with no limit at all. Declaring the upload as
    ``UploadFile = File(...)`` would therefore let any caller spool an arbitrary
    number of gigabytes to disk *before* the route, its byte ceiling or even the
    authentication dependency ran, because FastAPI parses the body first. The
    routes below take a bare ``Request`` and parse it through this class, so the
    ceiling and the session check both come first.
    """

    def __init__(self, *arguments, max_file_size: int, **keywords) -> None:
        super().__init__(*arguments, **keywords)
        self._max_file_size = max_file_size
        self._file_bytes = 0

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        if self._current_part.file is not None:
            self._file_bytes += end - start
            if self._file_bytes > self._max_file_size:
                raise MultiPartException("evidence part exceeds the byte ceiling")
        super().on_part_data(data, start, end)


async def _bounded_form(request: Request, settings: Settings) -> FormData:
    """Read one small multipart body under an explicit ceiling."""
    declared = request.headers.get("content-length")
    ceiling = settings.EVIDENCE_MAX_UPLOAD_BYTES
    if declared is not None and declared.isdigit():
        # Cheapest possible refusal: never start reading a body that has
        # already announced it will not fit.
        if int(declared) > ceiling + _MULTIPART_OVERHEAD_BYTES:
            raise EvidenceRejected(evidence_processing.FAILURE_TOO_LARGE, limit=ceiling)
    if "multipart/form-data" not in (request.headers.get("content-type") or ""):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={"code": "evidence_expects_multipart"},
        )
    parser = _BoundedMultiPartParser(
        request.headers,
        request.stream(),
        max_files=1,
        max_fields=8,
        max_part_size=_MAX_FIELD_BYTES,
        max_file_size=ceiling,
    )
    try:
        return await parser.parse()
    except MultiPartException as error:
        # A body without a truthful Content-Length is stopped here instead,
        # still before the whole part has been spooled.
        raise EvidenceRejected(
            evidence_processing.FAILURE_TOO_LARGE, limit=ceiling
        ) from error


def _form_file(form: FormData, field: str) -> UploadFile:
    value = form.get(field)
    if not isinstance(value, UploadFile):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "evidence_file_required"},
        )
    return value


def _form_text(form: FormData, field: str) -> str | None:
    value = form.get(field)
    if value is None or isinstance(value, UploadFile):
        return None
    text = str(value).strip()
    return text or None


def _form_int(form: FormData, field: str) -> int | None:
    text = _form_text(form, field)
    if text is None:
        return None
    if not text.isdigit() or len(text) > 18:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "invalid_" + field},
        )
    return int(text)


async def _read_form(
    request: Request,
    db: AsyncSession,
    settings: Settings,
    storage: EvidenceStorage,
    user: User,
    object_id: str,
) -> FormData:
    """Parse the body under the ceiling, auditing a refusal at the door.

    A body refused here never became an artifact, so the audit event carries the
    object id this request would have used and no artifact row. That keeps the
    refusal in the append-only trail instead of only in the request log.
    """
    try:
        return await _bounded_form(request, settings)
    except EvidenceRejected as rejected:
        await _record_rejected_upload(
            db,
            storage=storage,
            settings=settings,
            user=user,
            object_id=object_id,
            stored=None,
            display_filename="evidence",
            code=rejected.code,
            limit=rejected.limit,
            request_id=_request_id(request),
        )
        raise _rejection(rejected.code, rejected.limit) from None


async def _close_form(form: FormData) -> None:
    try:
        await form.close()
    except Exception:  # noqa: BLE001 - spool cleanup is never caller visible
        logger.warning("Evidence upload spool could not be closed")


# ---------------------------------------------------------------------------
# ownership resolution
# ---------------------------------------------------------------------------
async def _resolve_parent(
    db: AsyncSession,
    user: User,
    *,
    scan_id: int | None,
    scan_result_id: int | None,
    control_id: str | None,
) -> tuple[int | None, int | None, str | None]:
    """Resolve optional linkage through the authenticated user first.

    A parent that is not the caller's answers 404, not 403, so the endpoint
    cannot be used to probe which scan ids exist in other tenants.
    """
    if control_id is not None and not _CONTROL_ID_PATTERN.match(control_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "invalid_control_id"},
        )

    resolved_scan_id = scan_id
    if scan_result_id is not None:
        result = await db.execute(
            select(ScanResult)
            .join(Scan, Scan.id == ScanResult.scan_id)
            .where(ScanResult.id == scan_result_id, Scan.user_id == user.id)
        )
        scan_result = result.scalar_one_or_none()
        if scan_result is None:
            raise _not_found()
        if scan_id is not None and scan_id != scan_result.scan_id:
            raise _not_found()
        resolved_scan_id = scan_result.scan_id
    elif scan_id is not None:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
        )
        if result.scalar_one_or_none() is None:
            raise _not_found()

    return resolved_scan_id, scan_result_id, control_id


async def _owned_artifact(
    db: AsyncSession, user: User, object_id: str
) -> EvidenceArtifact | None:
    """One query, both predicates. Ownership is part of the lookup itself."""
    result = await db.execute(
        select(EvidenceArtifact).where(
            EvidenceArtifact.object_id == object_id,
            EvidenceArtifact.user_id == user.id,
        )
    )
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# storage of an incoming body
# ---------------------------------------------------------------------------
async def _store_upload(
    upload: UploadFile,
    storage: EvidenceStorage,
    settings: Settings,
    *,
    object_id: str,
    user_id: int,
) -> evidence_storage.StoredObject:
    """Stream the body to storage, stopping at the configured ceiling."""
    key = evidence_storage.build_storage_key(user_id, object_id)
    chunk_size = settings.EVIDENCE_READ_CHUNK_BYTES

    async def chunks() -> AsyncIterator[bytes]:
        while True:
            chunk = await upload.read(chunk_size)
            if not chunk:
                return
            yield chunk

    try:
        return await storage.put(
            key, chunks(), max_bytes=settings.EVIDENCE_MAX_UPLOAD_BYTES
        )
    except EvidenceTooLargeError as error:
        raise EvidenceRejected(
            evidence_processing.FAILURE_TOO_LARGE,
            limit=settings.EVIDENCE_MAX_UPLOAD_BYTES,
        ) from error
    except EvidenceStorageError as error:
        logger.warning("Evidence object could not be stored")
        raise EvidenceRejected(evidence_processing.FAILURE_UNREADABLE) from error


def _build_artifact(
    *,
    object_id: str,
    user: User,
    kind: str,
    stored: evidence_storage.StoredObject,
    display_filename: str,
    media_type: str,
    declared: str | None,
    settings: Settings,
    storage: EvidenceStorage,
    artifact_status: str,
    failure_code: str | None = None,
    scan_id: int | None = None,
    scan_result_id: int | None = None,
    control_id: str | None = None,
    provenance: dict | None = None,
) -> EvidenceArtifact:
    return EvidenceArtifact(
        object_id=object_id,
        user_id=user.id,
        kind=kind,
        scan_id=scan_id,
        scan_result_id=scan_result_id,
        control_id=control_id,
        display_filename=display_filename,
        media_type=media_type,
        declared_media_type=declared,
        byte_size=stored.byte_size,
        content_sha256=stored.content_sha256,
        storage_backend=storage.backend_name,
        storage_key=stored.key,
        status=artifact_status,
        failure_code=failure_code,
        retention_policy_version=settings.EVIDENCE_RETENTION_POLICY_VERSION,
        retention_expires_at=_now() + timedelta(days=settings.EVIDENCE_RETENTION_DAYS),
        legal_hold=False,
        provenance=provenance,
    )


async def _record_rejected_upload(
    db: AsyncSession,
    *,
    storage: EvidenceStorage,
    settings: Settings,
    user: User,
    object_id: str,
    stored: evidence_storage.StoredObject | None,
    display_filename: str,
    code: str,
    limit: int | None,
    request_id: str | None,
    sniffed: str | None = None,
    declared: str | None = None,
) -> None:
    """Persist the refusal, then drop the bytes.

    A rejection is recorded rather than silently coerced: the artifact row keeps
    the digest, the size and the redacted failure code, and the append-only
    audit trail keeps the decision. The stored bytes are removed because content
    we refuse to interpret is content we must not retain.
    """
    detail: dict[str, object] = {"code": code}
    if limit is not None:
        detail["limit"] = limit
    if sniffed:
        detail["media_type"] = sniffed
    if declared:
        detail["declared_media_type"] = declared

    if stored is not None:
        detail["byte_size"] = stored.byte_size
        artifact = _build_artifact(
            object_id=object_id,
            user=user,
            kind=KIND_UPLOAD,
            stored=stored,
            display_filename=display_filename,
            media_type=sniffed or "application/octet-stream",
            declared=declared,
            settings=settings,
            storage=storage,
            artifact_status=STATUS_FAILED,
            failure_code=code,
        )
        db.add(artifact)
        await db.flush()
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_ERROR,
            request_id=request_id,
            detail=detail,
        )
        await _discard_bytes(storage, stored.key)
    else:
        await evidence_audit.record_event(
            db,
            artifact=object_id,
            actor=user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_ERROR,
            request_id=request_id,
            detail=detail,
        )
    await db.commit()


async def _discard_bytes(storage: EvidenceStorage, key: str) -> None:
    try:
        await storage.delete(key)
    except EvidenceStorageError:
        logger.warning("Rejected evidence bytes could not be discarded")


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@router.get("/strategies")
async def strategies(current_user: User = Depends(get_current_user)) -> list[dict]:
    """List evidence strategies for the frontend dropdown. Authenticated."""
    helper = _legacy(LEGACY_UI_MODULE, "api_strategies")
    try:
        listed = await evidence_processing.run_bounded_callable(helper)
    except EvidenceRejected as rejected:
        raise _rejection(rejected.code, rejected.limit) from None
    except Exception as error:  # noqa: BLE001 - legacy loader must fail closed
        logger.warning("Evidence strategies could not be listed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": evidence_processing.FAILURE_ENGINE_UNAVAILABLE},
        ) from error
    return list(listed) if isinstance(listed, list) else []


@router.get("/health", response_model=EvidenceReadiness)
async def readiness(
    current_user: User = Depends(get_current_user),
) -> EvidenceReadiness:
    """Boolean readiness only. No paths, no versions, no probes (AUTH-02)."""
    settings = get_settings()
    try:
        evidence_storage.get_storage(settings)
    except EvidenceStorageError:
        return EvidenceReadiness(ready=False)
    return EvidenceReadiness(ready=True)


UPLOAD_REQUEST_BODY = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["evidence"],
                    "properties": {
                        "evidence": {"type": "string", "format": "binary"},
                        "scan_id": {"type": "integer"},
                        "scan_result_id": {"type": "integer"},
                        "control_id": {"type": "string"},
                    },
                }
            }
        },
    }
}


@router.post(
    "/uploads",
    response_model=EvidenceUploadAccepted,
    status_code=status.HTTP_201_CREATED,
    openapi_extra=UPLOAD_REQUEST_BODY,
)
async def create_upload(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> EvidenceUploadAccepted:
    """Store one evidence object under the caller's ownership.

    The body is parsed by this route rather than declared as ``UploadFile``, so
    the session check and the byte ceiling both run before anything is spooled.
    The optional parent linkage is resolved through the authenticated user
    before a single byte is accepted, and a parent that is not the caller's
    answers 404 rather than 403.

    The object is created ``pending`` and then processed inline through the same
    bounded, time-limited path ``/scan`` uses, so the page, pixel, archive and
    timeout guards run for every stored object. Once item 15.1.9 moves
    processing to the worker, the row simply stays ``pending`` until the worker
    finishes it; nothing else about this route changes.
    """
    settings = get_settings()
    storage = _storage(settings)
    request_id = _request_id(request)

    object_id = evidence_storage.new_object_id()
    form = await _read_form(request, db, settings, storage, current_user, object_id)
    try:
        upload = _form_file(form, "evidence")
        resolved_scan_id, resolved_result_id, resolved_control = await _resolve_parent(
            db,
            current_user,
            scan_id=_form_int(form, "scan_id"),
            scan_result_id=_form_int(form, "scan_result_id"),
            control_id=_form_text(form, "control_id"),
        )
        display_filename = _safe_display_filename(upload.filename)
        stored: evidence_storage.StoredObject | None = None

        try:
            stored = await _store_upload(
                upload,
                storage,
                settings,
                object_id=object_id,
                user_id=current_user.id,
            )
            if stored.byte_size == 0:
                raise EvidenceRejected(evidence_processing.FAILURE_EMPTY)
            data = await evidence_processing.load_bounded_bytes(
                storage, stored.key, settings=settings
            )
            detection = await evidence_processing.detect_media_type(
                data, display_filename=display_filename, settings=settings
            )
        except EvidenceRejected as rejected:
            await _record_rejected_upload(
                db,
                storage=storage,
                settings=settings,
                user=current_user,
                object_id=object_id,
                stored=stored,
                display_filename=display_filename,
                code=rejected.code,
                limit=rejected.limit,
                request_id=request_id,
                declared=evidence_processing.declared_media_type(display_filename)
                or None,
            )
            raise _rejection(rejected.code, rejected.limit) from None
    finally:
        await _close_form(form)

    artifact = _build_artifact(
        object_id=object_id,
        user=current_user,
        kind=KIND_UPLOAD,
        stored=stored,
        display_filename=display_filename,
        media_type=detection.media_type,
        declared=detection.declared_media_type,
        settings=settings,
        storage=storage,
        artifact_status=STATUS_PENDING,
        scan_id=resolved_scan_id,
        scan_result_id=resolved_result_id,
        control_id=resolved_control,
        provenance={"request_id": request_id} if request_id else None,
    )
    await _persist_new_artifact(
        db,
        storage=storage,
        artifact=artifact,
        actor=current_user,
        request_id=request_id,
        detail={
            "kind": KIND_UPLOAD,
            "media_type": detection.media_type,
            "byte_size": stored.byte_size,
        },
    )

    extraction = await _process_artifact(
        db,
        artifact=artifact,
        data=data,
        media_type=detection.media_type,
        actor=current_user,
        request_id=request_id,
        settings=settings,
    )

    return EvidenceUploadAccepted(
        object_id=object_id,
        status=artifact.status,
        kind=KIND_UPLOAD,
        media_type=detection.media_type,
        byte_size=stored.byte_size,
        content_sha256=stored.content_sha256,
        extracted_chars=extraction.char_count,
    )


async def _persist_new_artifact(
    db: AsyncSession,
    *,
    storage: EvidenceStorage,
    artifact: EvidenceArtifact,
    actor: User,
    request_id: str | None,
    detail: dict,
) -> None:
    """Commit the row and its creation event, or drop the stored bytes.

    Storing bytes and then failing to record them would leave an untracked file
    with no owner, no retention date and no audit trail, which is precisely the
    state Phase 7 exists to make impossible.
    """
    try:
        db.add(artifact)
        await db.flush()
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=actor,
            action=evidence_audit.ACTION_CREATED,
            outcome=evidence_audit.OUTCOME_ALLOWED,
            request_id=request_id,
            detail=detail,
        )
        await db.commit()
    except Exception as error:  # noqa: BLE001 - the bytes must not outlive the row
        await _rollback(db)
        await _discard_bytes(storage, artifact.storage_key)
        logger.error("Evidence artifact could not be recorded; stored bytes discarded")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "evidence_not_recorded"},
        ) from error


async def _rollback(db: AsyncSession) -> None:
    try:
        await db.rollback()
    except Exception:  # noqa: BLE001 - rollback failure is not caller visible
        logger.warning("Evidence transaction rollback failed")


async def _process_artifact(
    db: AsyncSession,
    *,
    artifact: EvidenceArtifact,
    data: bytes,
    media_type: str,
    actor: User,
    request_id: str | None,
    settings: Settings,
) -> evidence_processing.Extraction:
    """Run the one bounded extraction for this artifact and record the outcome.

    Exactly one extraction happens per stored object: this is the only call site
    for it, and the caller reuses the returned text.

    A failure here keeps the stored bytes and marks the row ``failed`` with the
    redacted code. That is deliberate and differs from a detection failure: the
    content was identified as a type we accept, so it stays the caller's own
    evidence under the recorded retention policy, and only content we could not
    identify at all is dropped immediately.
    """
    artifact.status = STATUS_PROCESSING
    await evidence_audit.record_event(
        db,
        artifact=artifact,
        actor=actor,
        action=evidence_audit.ACTION_PROCESSING_STARTED,
        outcome=evidence_audit.OUTCOME_ALLOWED,
        request_id=request_id,
        detail={"media_type": media_type},
    )
    await db.commit()

    try:
        extraction = await evidence_processing.extract_text_bounded(
            data, media_type=media_type, settings=settings
        )
    except EvidenceRejected as rejected:
        artifact.status = STATUS_FAILED
        artifact.failure_code = rejected.code
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=actor,
            action=evidence_audit.ACTION_PROCESSING_FAILED,
            outcome=evidence_audit.OUTCOME_ERROR,
            request_id=request_id,
            detail={"code": rejected.code, "limit": rejected.limit},
        )
        await db.commit()
        raise _rejection(rejected.code, rejected.limit) from None

    artifact.status = STATUS_AVAILABLE
    provenance = dict(artifact.provenance or {})
    provenance["extracted_chars"] = extraction.char_count
    artifact.provenance = provenance
    await evidence_audit.record_event(
        db,
        artifact=artifact,
        actor=actor,
        action=evidence_audit.ACTION_PROCESSED,
        outcome=evidence_audit.OUTCOME_ALLOWED,
        request_id=request_id,
        detail={
            "media_type": media_type,
            "extracted_chars": extraction.char_count,
            "page_count": extraction.page_count,
        },
    )
    await db.commit()
    return extraction


@router.get("/artifacts", response_model=EvidenceArtifactList)
async def list_artifacts(
    kind: str | None = Query(default=None, pattern=r"^(upload|report)$"),
    include_deleted: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> EvidenceArtifactList:
    """The caller's own artifacts, paginated. Never another tenant's."""
    query = select(EvidenceArtifact).where(EvidenceArtifact.user_id == current_user.id)
    if kind is not None:
        query = query.where(EvidenceArtifact.kind == kind)
    if not include_deleted:
        query = query.where(EvidenceArtifact.status != STATUS_DELETED)
    query = query.order_by(EvidenceArtifact.id.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    rows = list(result.scalars().all())
    return EvidenceArtifactList(
        items=[EvidenceArtifactRead.model_validate(row) for row in rows],
        limit=limit,
        offset=offset,
        returned=len(rows),
    )


@router.get("/artifacts/{object_id}", response_model=EvidenceArtifactRead)
async def get_artifact(
    request: Request,
    object_id: str = object_id_param(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> EvidenceArtifactRead:
    """Metadata for one owned artifact. A foreign object is a 404."""
    artifact = await _owned_artifact(db, current_user, object_id)
    if artifact is None:
        await evidence_audit.record_event(
            db,
            artifact=object_id,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_DENIED,
            request_id=_request_id(request),
            detail={"code": "evidence_not_found", "operation": "metadata"},
        )
        await db.commit()
        raise _not_found()
    return EvidenceArtifactRead.model_validate(artifact)


@router.get("/artifacts/{object_id}/content")
async def download_artifact(
    request: Request,
    object_id: str = object_id_param(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> Response:
    """Stream owned bytes. Both the allow and the deny are audited."""
    return await _download(request, object_id, current_user, db, kind=None)


@router.get("/reports/{object_id}")
async def download_report(
    request: Request,
    object_id: str = object_id_param(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> Response:
    """Compatibility download for generated reports (AUTH-01 closed).

    The path segment is an opaque object id, not a filename, and the row is
    resolved by ``(object_id, user_id)``. The legacy filename-addressed handler
    in ``security/evidence_ui/app.py`` is never called.
    """
    return await _download(request, object_id, current_user, db, kind=KIND_REPORT)


async def _download(
    request: Request,
    object_id: str,
    current_user: User,
    db: AsyncSession,
    *,
    kind: str | None,
) -> Response:
    settings = get_settings()
    storage = _storage(settings)
    request_id = _request_id(request)

    artifact = await _owned_artifact(db, current_user, object_id)
    denied_code: str | None = None
    if artifact is None or (kind is not None and artifact.kind != kind):
        denied_code = "evidence_not_found"
    elif artifact.status != STATUS_AVAILABLE:
        denied_code = "evidence_not_available"

    if denied_code is not None:
        await evidence_audit.record_event(
            db,
            artifact=artifact if artifact is not None else object_id,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_DENIED,
            request_id=request_id,
            detail={"code": denied_code, "operation": "download"},
        )
        await db.commit()
        raise _not_found()

    # Open before the response starts. An exception raised inside a
    # StreamingResponse body would tear a 200 that has already begun, and a
    # concurrent retention delete between an existence probe and the first read
    # would do exactly that. Once the descriptor exists the bytes stay readable.
    try:
        handle = await storage.open_reader(artifact.storage_key)
    except EvidenceStorageError:
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_ERROR,
            request_id=request_id,
            detail={"code": "evidence_object_missing", "operation": "download"},
        )
        await db.commit()
        raise _not_found() from None

    # The decision is committed before a byte leaves, so an aborted transfer
    # still leaves the access recorded.
    try:
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=current_user,
            action=evidence_audit.ACTION_DOWNLOADED,
            outcome=evidence_audit.OUTCOME_ALLOWED,
            request_id=request_id,
            detail={
                "kind": artifact.kind,
                "byte_size": artifact.byte_size,
                "media_type": artifact.media_type,
            },
        )
        await db.commit()
    except Exception:
        handle.close()
        raise

    return StreamingResponse(
        storage.iter_handle(handle, chunk_size=settings.EVIDENCE_READ_CHUNK_BYTES),
        # Deliberately opaque: a stored HTML or SVG payload must never be
        # rendered as active content in the application origin.
        media_type="application/octet-stream",
        headers=_download_headers(artifact),
    )


@router.delete("/artifacts/{object_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_artifact(
    request: Request,
    object_id: str = object_id_param(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> Response:
    """Soft-delete: the row survives as a tombstone, the bytes do not."""
    settings = get_settings()
    storage = _storage(settings)
    request_id = _request_id(request)

    artifact = await _owned_artifact(db, current_user, object_id)
    if artifact is None:
        await evidence_audit.record_event(
            db,
            artifact=object_id,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_DENIED,
            request_id=request_id,
            detail={"code": "evidence_not_found", "operation": "delete"},
        )
        await db.commit()
        raise _not_found()

    if artifact.legal_hold:
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_DENIED,
            request_id=request_id,
            detail={"code": "evidence_legal_hold", "operation": "delete"},
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "evidence_legal_hold"},
        )

    if artifact.status == STATUS_DELETED:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # Remove the bytes first and prove they are gone. Recording a completed
    # deletion the filesystem refused would be a retention claim the store
    # cannot honour, so a failed removal leaves the row untouched and retryable.
    try:
        await storage.delete(artifact.storage_key)
        still_present = await storage.exists(artifact.storage_key)
    except EvidenceStorageError:
        still_present = True
    if still_present:
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_ERROR,
            request_id=request_id,
            detail={"code": "evidence_delete_failed", "operation": "delete"},
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "evidence_delete_failed"},
        )

    # The CHECK constraint couples these two: status 'deleted' exists if and
    # only if deleted_at is set.
    artifact.status = STATUS_DELETED
    artifact.deleted_at = _now()
    await evidence_audit.record_event(
        db,
        artifact=artifact,
        actor=current_user,
        action=evidence_audit.ACTION_DELETED,
        outcome=evidence_audit.OUTCOME_ALLOWED,
        request_id=request_id,
        detail={"kind": artifact.kind, "byte_size": artifact.byte_size},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# legacy scan flow, reimplemented on the bounded path
# ---------------------------------------------------------------------------
def _resolve_strategy(strategy_name: str):
    """Find the registered strategy, or refuse. Never trusts free text."""
    loader = _legacy(LEGACY_STRATEGY_MODULE, "load_strategies")
    try:
        available = loader() or []
    except Exception as error:  # noqa: BLE001 - legacy loader must fail closed
        logger.warning("Evidence strategies could not be loaded")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": evidence_processing.FAILURE_ENGINE_UNAVAILABLE},
        ) from error
    for candidate in available:
        if getattr(candidate, "name", None) == strategy_name:
            return candidate
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"code": "unknown_strategy"},
    )


def _accepts_source_file(strategy) -> bool:
    try:
        return "source_file" in inspect.signature(strategy.emit_hits).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic legacy callables
        return False


def _strip_server_paths(value, depth: int = 0):
    """Remove the scanner's own filesystem locations from a legacy finding."""
    if depth > 4:
        return None
    if isinstance(value, dict):
        return {
            key: _strip_server_paths(item, depth + 1)
            for key, item in value.items()
            if key not in _SERVER_PATH_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_strip_server_paths(item, depth + 1) for item in value[:200]]
    return value


def _match_findings(strategy, text: str, source_file: str) -> list[dict]:
    """Run the legacy matcher on this upload only. Thread-only; blocking.

    ``source_file`` must be non-empty. Several registered strategies treat an
    empty ``source_file`` as a signal to switch into *folder mode* and scan a
    server-side evidence directory instead of the caller's upload, which would
    return another tenant's data — and the scanner's absolute paths — to whoever
    posted the file. Passing the caller's own display name keeps them in
    single-file mode, and the sanitiser below drops any server location a
    strategy still reports.
    """
    if hasattr(strategy, "emit_hits"):
        if _accepts_source_file(strategy):
            findings = strategy.emit_hits(text, source_file=source_file) or []
        else:
            findings = strategy.emit_hits(text) or []
    else:
        hits = strategy.match(text) or []
        findings = (
            [
                {
                    "test_id": "",
                    "sub_strategy": "",
                    "detected_level": "",
                    "pass_fail": "",
                    "priority": "",
                    "recommendation": "",
                    "evidence": hits,
                }
            ]
            if hits
            else []
        )
    return [
        _strip_server_paths(finding)
        for finding in findings
        if isinstance(finding, dict)
    ]


def _render_report(strategy_name: str, findings: list[dict]) -> bytes:
    """Build a bounded plain-text report in process.

    No template, no ``docx2pdf`` and no ``soffice``: a subprocess cannot be
    reclaimed at the request deadline, which is exactly the EVI-01 defect.

    The bounds here refuse rather than truncate. A report that silently dropped
    findings while its header still counted them would be a report an auditor
    could not rely on, so an oversized one is not produced at all.
    """
    if len(findings) > _MAX_REPORT_FINDINGS:
        raise EvidenceRejected(
            evidence_processing.FAILURE_EXTRACT_LIMIT, limit=_MAX_REPORT_FINDINGS
        )
    lines = [
        "AutoAudit evidence scan report",
        f"Strategy: {strategy_name}",
        f"Findings: {len(findings)}",
        "",
    ]
    for index, finding in enumerate(findings, start=1):
        lines.append(f"[{index}] test_id={str(finding.get('test_id', ''))[:120]}")
        for field in ("sub_strategy", "detected_level", "pass_fail", "priority"):
            lines.append(f"    {field}: {str(finding.get(field, ''))[:200]}")
        recommendation = str(finding.get("recommendation", ""))[:1000]
        if recommendation:
            lines.append(f"    recommendation: {recommendation}")
        lines.append("")
    payload = "\n".join(lines).encode("utf-8", errors="replace")
    if len(payload) > _MAX_REPORT_BYTES:
        raise EvidenceRejected(
            evidence_processing.FAILURE_EXTRACT_LIMIT, limit=_MAX_REPORT_BYTES
        )
    return payload


SCAN_REQUEST_BODY = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["evidence", "strategy_name"],
                    "properties": {
                        "evidence": {"type": "string", "format": "binary"},
                        "strategy_name": {"type": "string"},
                    },
                }
            }
        },
    }
}


@router.post(
    "/scan",
    response_model=EvidenceScanResponse,
    openapi_extra=SCAN_REQUEST_BODY,
)
async def scan(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session),
) -> EvidenceScanResponse:
    """Run one bounded evidence scan and keep the legacy response shape.

    The whole path is bounded and time limited: the body is parsed under the
    byte ceiling before anything is spooled, the type comes from magic bytes,
    extraction happens exactly once inside a worker thread under the processing
    timeout, matching and validation also run off the event loop, and the report
    is rendered in process with no converter subprocess.
    """
    settings = get_settings()
    storage = _storage(settings)
    request_id = _request_id(request)

    object_id = evidence_storage.new_object_id()
    form = await _read_form(request, db, settings, storage, current_user, object_id)
    try:
        upload = _form_file(form, "evidence")
        strategy_name = _form_text(form, "strategy_name")
        if not strategy_name or len(strategy_name) > 255:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "strategy_name_required"},
            )
        # Loading the legacy strategy package imports modules and touches the
        # filesystem, so it does not belong on the event loop either.
        strategy = await evidence_processing.run_bounded_callable(
            _resolve_strategy, strategy_name, settings=settings
        )
        resolved_name = str(getattr(strategy, "name", "") or "unknown")[:255]

        display_filename = _safe_display_filename(upload.filename)
        stored: evidence_storage.StoredObject | None = None

        try:
            stored = await _store_upload(
                upload,
                storage,
                settings,
                object_id=object_id,
                user_id=current_user.id,
            )
            if stored.byte_size == 0:
                raise EvidenceRejected(evidence_processing.FAILURE_EMPTY)
            data = await evidence_processing.load_bounded_bytes(
                storage, stored.key, settings=settings
            )
            detection = await evidence_processing.detect_media_type(
                data, display_filename=display_filename, settings=settings
            )
        except EvidenceRejected as rejected:
            await _record_rejected_upload(
                db,
                storage=storage,
                settings=settings,
                user=current_user,
                object_id=object_id,
                stored=stored,
                display_filename=display_filename,
                code=rejected.code,
                limit=rejected.limit,
                request_id=request_id,
                declared=evidence_processing.declared_media_type(display_filename)
                or None,
            )
            raise _rejection(rejected.code, rejected.limit) from None
    finally:
        await _close_form(form)

    artifact = _build_artifact(
        object_id=object_id,
        user=current_user,
        kind=KIND_UPLOAD,
        stored=stored,
        display_filename=display_filename,
        media_type=detection.media_type,
        declared=detection.declared_media_type,
        settings=settings,
        storage=storage,
        artifact_status=STATUS_PENDING,
        provenance={"request_id": request_id, "strategy": resolved_name}
        if request_id
        else {"strategy": resolved_name},
    )
    await _persist_new_artifact(
        db,
        storage=storage,
        artifact=artifact,
        actor=current_user,
        request_id=request_id,
        detail={
            "kind": KIND_UPLOAD,
            "media_type": detection.media_type,
            "byte_size": stored.byte_size,
        },
    )

    # ---- exactly one extraction for this upload -------------------------
    extraction = await _process_artifact(
        db,
        artifact=artifact,
        data=data,
        media_type=detection.media_type,
        actor=current_user,
        request_id=request_id,
        settings=settings,
    )
    text = extraction.text

    # ---- legacy matching and validation, both off the event loop ---------
    try:
        findings = await evidence_processing.run_bounded_callable(
            _match_findings, strategy, text, display_filename, settings=settings
        )
        validator_payload = await evidence_processing.run_bounded_callable(
            validate_text, resolved_name, text, settings=settings
        )
    except EvidenceRejected as rejected:
        await _fail_artifact(
            db,
            artifact=artifact,
            actor=current_user,
            request_id=request_id,
            code=rejected.code,
            limit=rejected.limit,
        )
        raise _rejection(rejected.code, rejected.limit) from None
    except Exception as error:  # noqa: BLE001 - legacy matcher, redacted
        logger.warning("Evidence strategy matching failed")
        await _fail_artifact(
            db,
            artifact=artifact,
            actor=current_user,
            request_id=request_id,
            code=evidence_processing.FAILURE_UNREADABLE,
            limit=None,
        )
        raise _rejection(evidence_processing.FAILURE_UNREADABLE) from error

    # ---- validator record, linked to the artifact ------------------------
    validation = EvidenceValidation(
        user_id=current_user.id,
        strategy_name=resolved_name,
        source_filename=display_filename,
        text_hash=hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        if text
        else None,
        extracted_text_encrypted=_encrypt_excerpt(text),
        matches_json=validator_payload,
        status="success",
    )
    db.add(validation)
    await db.flush()

    provenance = dict(artifact.provenance or {})
    provenance["evidence_validation_id"] = getattr(validation, "id", None)
    artifact.provenance = provenance

    # ---- bounded report artifact ----------------------------------------
    report_ids: list[str] = []
    note = ""
    if findings:
        report_id, report_note = await _store_report(
            db,
            storage=storage,
            settings=settings,
            user=current_user,
            strategy_name=resolved_name,
            findings=findings,
            request_id=request_id,
        )
        note = report_note
        if report_id is not None:
            report_ids.append(report_id)
    elif not text.strip():
        note = "No readable text found in evidence."

    await evidence_audit.record_event(
        db,
        artifact=artifact,
        actor=current_user,
        action=evidence_audit.ACTION_PROCESSED,
        outcome=evidence_audit.OUTCOME_ALLOWED,
        request_id=request_id,
        detail={
            "media_type": detection.media_type,
            "extracted_chars": extraction.char_count,
            "findings": len(findings),
            "reports": len(report_ids),
        },
    )
    await db.commit()

    return EvidenceScanResponse(
        ok=True,
        findings=findings,
        reports=report_ids,
        note=note,
        object_id=object_id,
        validator=validator_payload,
    )


async def _fail_artifact(
    db: AsyncSession,
    *,
    artifact: EvidenceArtifact,
    actor: User,
    request_id: str | None,
    code: str,
    limit: int | None,
) -> None:
    """Record a redacted processing failure against an already stored object."""
    artifact.status = STATUS_FAILED
    artifact.failure_code = code
    await evidence_audit.record_event(
        db,
        artifact=artifact,
        actor=actor,
        action=evidence_audit.ACTION_PROCESSING_FAILED,
        outcome=evidence_audit.OUTCOME_ERROR,
        request_id=request_id,
        detail={"code": code, "limit": limit},
    )
    await db.commit()


def _encrypt_excerpt(text: str) -> str | None:
    """Encrypt a capped excerpt; a missing key must not fail the scan."""
    if not text:
        return None
    try:
        return encrypt(text[:_MAX_ENCRYPTED_EXCERPT_CHARS])
    except Exception:  # noqa: BLE001 - key configuration is not caller visible
        logger.warning("Extracted text excerpt could not be encrypted")
        return None


async def _store_report(
    db: AsyncSession,
    *,
    storage: EvidenceStorage,
    settings: Settings,
    user: User,
    strategy_name: str,
    findings: list[dict],
    request_id: str | None,
) -> tuple[str | None, str]:
    """Persist the generated report as an owned, addressable artifact.

    Returns the object id and a note. A report that cannot be produced within
    its bounds is not produced at all, and the note says so rather than handing
    back a silently shortened document.
    """
    try:
        payload = _render_report(strategy_name, findings)
    except EvidenceRejected:
        logger.warning("Evidence report exceeds its configured bounds")
        return None, (
            "The findings exceed the report size limit, so no report was "
            "generated. The scan result itself is complete."
        )

    object_id = evidence_storage.new_object_id()
    key = evidence_storage.build_storage_key(user.id, object_id)
    try:
        stored = await storage.put(
            key, _single_chunk(payload), max_bytes=settings.EVIDENCE_MAX_UPLOAD_BYTES
        )
    except EvidenceStorageError:
        logger.warning("Evidence report could not be stored")
        return None, "Report generation is unavailable; the scan result is unaffected."

    artifact = _build_artifact(
        object_id=object_id,
        user=user,
        kind=KIND_REPORT,
        stored=stored,
        display_filename=f"autoaudit-report-{object_id[:8]}.txt",
        media_type=evidence_processing.MEDIA_TEXT,
        declared=evidence_processing.MEDIA_TEXT,
        settings=settings,
        storage=storage,
        artifact_status=STATUS_AVAILABLE,
        provenance={"strategy": strategy_name, "findings": len(findings)},
    )
    try:
        db.add(artifact)
        await db.flush()
        await evidence_audit.record_event(
            db,
            artifact=artifact,
            actor=user,
            action=evidence_audit.ACTION_CREATED,
            outcome=evidence_audit.OUTCOME_ALLOWED,
            request_id=request_id,
            detail={"kind": KIND_REPORT, "byte_size": stored.byte_size},
        )
    except Exception:  # noqa: BLE001 - the bytes must not outlive the row
        await _discard_bytes(storage, key)
        raise
    return object_id, ""


# ---------------------------------------------------------------------------
# Phase 10: legal hold and the access log.
#
# Phase 7 built the enforcement and the vocabulary -- `legal_hold` blocks a
# delete, and `legal_hold_applied` / `legal_hold_released` are declared audit
# actions. Nothing could set the flag and nothing emitted those actions, so the
# only way to place a hold was a DBA running raw SQL against production: itself
# an unaudited privileged action, on the control whose entire purpose is
# accountability.
#
# Similarly the audit trail was write-only. It records every allowed and denied
# access, including the denials, and no endpoint could read it -- so "who
# downloaded this evidence" needed database access to answer.
# ---------------------------------------------------------------------------


async def _bounded_json(request: Request, model, *, max_bytes: int = 4096):
    """Read and validate a small JSON body without letting FastAPI declare it.

    Every route on this router must declare no body field --
    ``test_no_route_lets_fastapi_parse_the_body_before_authentication`` asserts
    it for the whole router, because FastAPI parses a declared body *before* it
    solves dependencies, so an upload route would spool a file to disk before
    the session check could refuse it.

    A two-field administrative payload is not that risk, but the invariant is
    stated over the router rather than over the upload routes, and weakening a
    security assertion to admit a convenience is the wrong trade. So this reads
    the stream itself under an explicit ceiling, in the same shape as
    ``_bounded_form`` above.
    """
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={"code": "request_too_large"},
            )
    try:
        return model.model_validate_json(body)
    except ValidationError:
        # Never echo the body back: this router's error paths are deliberately
        # detail-free, and a validation error would quote whatever was sent.
        raise HTTPException(status_code=422, detail="Invalid request") from None


@router.post(
    "/artifacts/{object_id}/legal-hold",
    response_model=EvidenceArtifactRead,
    # The body is read by _bounded_json rather than declared as a parameter, so
    # that the Phase 7 invariant (no route on this router declares a body field)
    # still holds. FastAPI therefore publishes no requestBody, which would leave
    # /docs and every generated client showing a POST that takes nothing while
    # the handler 422s without one. Declaring it here keeps the invariant and
    # the published contract both true.
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["hold", "reason"],
                        "properties": {
                            "hold": {"type": "boolean"},
                            "reason": {
                                "type": "string",
                                "minLength": 3,
                                "maxLength": 120,
                            },
                        },
                    }
                }
            },
        }
    },
)
async def set_legal_hold(
    request: Request,
    object_id: str = object_id_param(),
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> EvidenceArtifact:
    """Place or release a legal hold on one artifact.

    **Auditor or admin, not the owner.** A hold has to survive the data owner's
    wish to delete -- that is what distinguishes it from ordinary retention -- so
    the owner cannot lift their own. The lookup is therefore deliberately not
    ownership-scoped, and every outcome is recorded either way.

    Scope is per artifact, which is the granularity the column has. Holding a
    whole scan, control or tenant is not expressible today; that is recorded as
    a gap rather than approximated by a loop over artifacts.
    """
    payload = await _bounded_json(request, LegalHoldRequest)
    request_id = _request_id(request)
    artifact = await db.scalar(
        select(EvidenceArtifact)
        .where(
            EvidenceArtifact.object_id == object_id,
            # A tombstoned row has no bytes left to hold.
            EvidenceArtifact.status != STATUS_DELETED,
        )
        # Serialises against a concurrent delete. Without it, applying a hold
        # and deleting the object are a check-then-act pair: the delete reads
        # legal_hold=false, the hold commits, and the bytes are removed anyway.
        # sessions.py:rotate uses the same lock for the same reason.
        .with_for_update()
    )
    if artifact is None:
        await evidence_audit.record_event(
            db,
            artifact=object_id,
            actor=current_user,
            action=evidence_audit.ACTION_REJECTED,
            outcome=evidence_audit.OUTCOME_DENIED,
            request_id=request_id,
            detail={"code": "evidence_not_found", "operation": "legal_hold"},
        )
        await db.commit()
        raise _not_found()

    already = artifact.legal_hold
    artifact.legal_hold = payload.hold
    await evidence_audit.record_event(
        db,
        artifact=artifact,
        actor=current_user,
        action=(
            evidence_audit.ACTION_LEGAL_HOLD_APPLIED
            if payload.hold
            else evidence_audit.ACTION_LEGAL_HOLD_RELEASED
        ),
        outcome=evidence_audit.OUTCOME_ALLOWED,
        request_id=request_id,
        # `reason` is redacted and length-bounded by the audit writer.
        detail={"reason": payload.reason, "was_held": already},
    )
    await db.commit()
    await db.refresh(artifact)
    return artifact


@router.get(
    "/artifacts/{object_id}/audit-events", response_model=EvidenceAuditEventList
)
async def read_audit_events(
    request: Request,
    object_id: str = object_id_param(),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_auditor_or_above),
    db: AsyncSession = Depends(get_async_session),
) -> EvidenceAuditEventList:
    """Read one artifact's access log.

    **Auditor or admin only, deliberately.** The trail carries `actor_user_id`
    for every reader, so an owner-scoped version of this endpoint would tell one
    customer which *other* accounts touched an object -- turning an access log
    into a disclosure. Answering "who read my evidence" for a data subject is a
    different question with a different answer shape, and it needs D05 to say
    what may leave the system.

    Reading the trail is itself an access decision, so it is recorded in the
    trail. That is intended, and it is why the query excludes nothing: an
    auditor must be able to see that another auditor looked.
    """
    request_id = _request_id(request)

    # Existence first. Recording an event for an object id that has never
    # existed would let any caller append arbitrary rows to a table the Phase 7
    # trigger forbids UPDATE and DELETE on -- unbounded, permanent growth driven
    # from outside. A denial is still recorded, but only against a real object.
    exists = await db.scalar(
        select(EvidenceArtifact.id).where(EvidenceArtifact.object_id == object_id)
    )
    if exists is None:
        raise _not_found()

    await evidence_audit.record_event(
        db,
        artifact=object_id,
        actor=current_user,
        # Its own action, not ACTION_DOWNLOADED: reading the log is not
        # downloading the evidence, and conflating them would make every
        # "who downloaded this" query wrong.
        action=evidence_audit.ACTION_AUDIT_READ,
        outcome=evidence_audit.OUTCOME_ALLOWED,
        request_id=request_id,
    )
    await db.commit()

    rows = (
        await db.scalars(
            select(EvidenceAuditEvent)
            .where(EvidenceAuditEvent.artifact_object_id == object_id)
            .order_by(
                EvidenceAuditEvent.occurred_at.desc(), EvidenceAuditEvent.id.desc()
            )
            .offset(offset)
            .limit(limit)
        )
    ).all()
    return EvidenceAuditEventList(
        items=list(rows), limit=limit, offset=offset, returned=len(rows)
    )
