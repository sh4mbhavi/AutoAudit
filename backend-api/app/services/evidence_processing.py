"""Bounded, fail-closed content detection and text extraction for evidence.

EVI-01: the legacy path dispatched on the client-supplied filename extension,
applied no size, page, pixel, archive or timeout bound, ran OCR, PDF
rasterisation and a ``soffice`` subprocess on the API event loop, and extracted
text twice per upload. Everything here exists to make each of those impossible.

Three rules govern this module.

1. **Content decides the type, not the name.** ``detect_media_type`` sniffs
   magic bytes and, for the zip-based ``.docx`` container, checks the real
   ``[Content_Types].xml`` entry. A declared extension that disagrees with the
   sniffed content is a rejection recorded against the artifact, never a silent
   coercion.
2. **Every limit fails closed.** Exceeding a page, pixel, archive, character or
   time bound rejects the artifact with a stable machine-readable code.
   Truncating and reporting success would let partial evidence read as complete
   evidence, which is the exact failure this phase exists to prevent.
3. **Nothing runs on the event loop, and nothing a timeout abandons can write.**
   Extraction happens in a worker thread under ``anyio``; the request stops
   waiting at the deadline and answers ``evidence_timeout``. Be precise about
   what that buys: a Python thread cannot be killed, so an abandoned thread may
   still finish the page or archive entry it is inside before the deadline it
   re-checks stops it. What it can never do is leave a trace — it opens no
   output file, writes no preview, spawns no converter and touches no database,
   so its result is simply discarded. Reclaiming CPU from a hostile document
   needs a separate process, which is why item 15.1.9 moves this to the worker.
"""

from __future__ import annotations

import io
import logging
import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

import anyio

from app.core.config import Settings, get_settings
from app.services.evidence_storage import (
    EvidenceStorage,
    EvidenceStorageError,
    EvidenceTooLargeError,
)

logger = logging.getLogger("api")

# ---------------------------------------------------------------------------
# Stable, redacted failure codes. These are the only content-processing values
# that ever reach a caller, a log line or EvidenceArtifact.failure_code.
# ---------------------------------------------------------------------------
FAILURE_TOO_LARGE = "evidence_too_large"
FAILURE_EMPTY = "evidence_empty"
FAILURE_UNSUPPORTED_TYPE = "evidence_unsupported_type"
FAILURE_TYPE_MISMATCH = "evidence_type_mismatch"
FAILURE_PAGE_LIMIT = "evidence_page_limit"
FAILURE_PIXEL_LIMIT = "evidence_pixel_limit"
FAILURE_ARCHIVE_BOMB = "evidence_archive_bomb"
FAILURE_EXTRACT_LIMIT = "evidence_extract_limit"
FAILURE_TIMEOUT = "evidence_timeout"
FAILURE_UNREADABLE = "evidence_unreadable"
FAILURE_ENGINE_UNAVAILABLE = "evidence_engine_unavailable"
FAILURE_OCR_UNAVAILABLE = "evidence_ocr_unavailable"

FAILURE_CODES = frozenset(
    {
        FAILURE_TOO_LARGE,
        FAILURE_EMPTY,
        FAILURE_UNSUPPORTED_TYPE,
        FAILURE_TYPE_MISMATCH,
        FAILURE_PAGE_LIMIT,
        FAILURE_PIXEL_LIMIT,
        FAILURE_ARCHIVE_BOMB,
        FAILURE_EXTRACT_LIMIT,
        FAILURE_TIMEOUT,
        FAILURE_UNREADABLE,
        FAILURE_ENGINE_UNAVAILABLE,
        FAILURE_OCR_UNAVAILABLE,
    }
)

MEDIA_PNG = "image/png"
MEDIA_JPEG = "image/jpeg"
MEDIA_TIFF = "image/tiff"
MEDIA_BMP = "image/bmp"
MEDIA_WEBP = "image/webp"
MEDIA_PDF = "application/pdf"
MEDIA_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
MEDIA_TEXT = "text/plain"

IMAGE_MEDIA_TYPES = frozenset(
    {MEDIA_PNG, MEDIA_JPEG, MEDIA_TIFF, MEDIA_BMP, MEDIA_WEBP}
)

#: The only media types this service will store, extract or serve back.
ALLOWED_MEDIA_TYPES = frozenset(IMAGE_MEDIA_TYPES | {MEDIA_PDF, MEDIA_DOCX, MEDIA_TEXT})

#: What a declared extension claims. A claim that contradicts the sniffed bytes
#: is rejected; an unknown extension is also a rejection, because accepting it
#: would mean serving back a type we never agreed to handle.
EXTENSION_MEDIA_TYPES: dict[str, str] = {
    ".png": MEDIA_PNG,
    ".jpg": MEDIA_JPEG,
    ".jpeg": MEDIA_JPEG,
    ".jpe": MEDIA_JPEG,
    ".tif": MEDIA_TIFF,
    ".tiff": MEDIA_TIFF,
    ".bmp": MEDIA_BMP,
    ".webp": MEDIA_WEBP,
    ".pdf": MEDIA_PDF,
    ".docx": MEDIA_DOCX,
    ".txt": MEDIA_TEXT,
    ".log": MEDIA_TEXT,
    ".csv": MEDIA_TEXT,
    ".json": MEDIA_TEXT,
    ".xml": MEDIA_TEXT,
    ".ini": MEDIA_TEXT,
    ".reg": MEDIA_TEXT,
    ".md": MEDIA_TEXT,
}

# Enough bytes for every signature this module understands.
_SNIFF_BYTES = 4096

_DOCX_CONTENT_TYPES_ENTRY = "[Content_Types].xml"
_DOCX_DOCUMENT_ENTRY = "word/document.xml"


class EvidenceRejected(Exception):
    """A bound was exceeded or the content was not acceptable.

    Carries only a stable code. No parser message, path or byte of content is
    ever attached, so the code can be logged, audited and returned as-is.
    """

    def __init__(self, code: str, *, limit: int | None = None) -> None:
        if code not in FAILURE_CODES:
            code = FAILURE_UNREADABLE
        super().__init__(code)
        self.code = code
        self.limit = limit


@dataclass(frozen=True)
class Detection:
    """What the bytes actually are, and what the filename claimed."""

    media_type: str
    declared_media_type: str | None


@dataclass(frozen=True)
class Extraction:
    """The single extraction performed for one artifact."""

    media_type: str
    text: str
    char_count: int
    page_count: int | None
    engine: str


def declared_media_type(display_filename: str | None) -> str | None:
    """The media type the filename claims, or None when it claims nothing."""
    suffix = Path(display_filename or "").suffix.lower()
    if not suffix:
        return None
    return EXTENSION_MEDIA_TYPES.get(suffix, "")


# ---------------------------------------------------------------------------
# magic-byte sniffing
# ---------------------------------------------------------------------------
def _looks_like_bmp(head: bytes) -> bool:
    """Two-byte 'BM' alone would misread text, so check the real header."""
    if len(head) < 14 or not head.startswith(b"BM"):
        return False
    return head[6:10] == b"\x00\x00\x00\x00"


#: Control characters that do not appear in real evidence text. Tab, newline,
#: carriage return and form feed are the only ones allowed through.
_BINARY_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")


def _looks_like_utf8_text(data: bytes) -> bool:
    """UTF-8 decodable *and* free of the control bytes binaries carry.

    Decodability alone is not enough: an ELF header decodes cleanly as UTF-8,
    and accepting it would let an executable in through the text fallback.
    """
    if b"\x00" in data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return _BINARY_CONTROL_CHARACTERS.search(text) is None


def _sniff_zip_container(data: bytes, settings: Settings) -> str:
    """Only a structurally real .docx is accepted from a zip container."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > settings.EVIDENCE_MAX_ARCHIVE_ENTRIES:
                raise EvidenceRejected(
                    FAILURE_ARCHIVE_BOMB, limit=settings.EVIDENCE_MAX_ARCHIVE_ENTRIES
                )
            names = {entry.filename for entry in entries}
    except EvidenceRejected:
        raise
    except (zipfile.BadZipFile, OSError, ValueError) as error:
        raise EvidenceRejected(FAILURE_UNREADABLE) from error
    if _DOCX_CONTENT_TYPES_ENTRY not in names or _DOCX_DOCUMENT_ENTRY not in names:
        raise EvidenceRejected(FAILURE_UNSUPPORTED_TYPE)
    return MEDIA_DOCX


def sniff_media_type(data: bytes, settings: Settings | None = None) -> str:
    """Identify content from its bytes. Raises for anything unsupported."""
    active = settings or get_settings()
    if not data:
        raise EvidenceRejected(FAILURE_EMPTY)
    head = data[:_SNIFF_BYTES]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return MEDIA_PNG
    if head.startswith(b"\xff\xd8\xff"):
        return MEDIA_JPEG
    if head.startswith(b"II*\x00") or head.startswith(b"MM\x00*"):
        return MEDIA_TIFF
    if _looks_like_bmp(head):
        return MEDIA_BMP
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return MEDIA_WEBP
    if head.startswith(b"%PDF-"):
        return MEDIA_PDF
    if head.startswith(b"PK\x03\x04"):
        return _sniff_zip_container(data, active)
    if _looks_like_utf8_text(data):
        return MEDIA_TEXT
    raise EvidenceRejected(FAILURE_UNSUPPORTED_TYPE)


def detect_media_type_sync(
    data: bytes, display_filename: str | None, settings: Settings
) -> Detection:
    """Sniff, then refuse a filename whose extension contradicts the bytes."""
    sniffed = sniff_media_type(data, settings)
    if sniffed not in ALLOWED_MEDIA_TYPES:
        raise EvidenceRejected(FAILURE_UNSUPPORTED_TYPE)
    claimed = declared_media_type(display_filename)
    if claimed is not None and claimed != sniffed:
        # Includes the unknown-extension case (claimed == ""): a name that
        # claims something we do not handle is rejected, never coerced.
        raise EvidenceRejected(FAILURE_TYPE_MISMATCH)
    return Detection(media_type=sniffed, declared_media_type=claimed or None)


# ---------------------------------------------------------------------------
# bounded extraction (runs only inside a worker thread)
# ---------------------------------------------------------------------------
def _check_deadline(deadline: float) -> None:
    """Cooperative stop so an abandoned thread does not keep burning CPU."""
    if time.monotonic() >= deadline:
        raise EvidenceRejected(FAILURE_TIMEOUT)


def _bound_text(parts: list[str], limit: int) -> str:
    text = "".join(parts)
    if len(text) > limit:
        raise EvidenceRejected(FAILURE_EXTRACT_LIMIT, limit=limit)
    return text


def _extract_image(
    data: bytes, media_type: str, settings: Settings, deadline: float
) -> Extraction:
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as error:
        raise EvidenceRejected(FAILURE_ENGINE_UNAVAILABLE) from error

    limit = settings.EVIDENCE_MAX_IMAGE_PIXELS
    # Set the decompression-bomb guard explicitly rather than inheriting a
    # library default that has nothing to do with our configured ceiling.
    previous = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = limit
    try:
        with Image.open(io.BytesIO(data)) as image:
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > limit:
                raise EvidenceRejected(FAILURE_PIXEL_LIMIT, limit=limit)
            # A multi-frame TIFF or animation carries evidence this service
            # does not read. Reading frame zero and reporting success would
            # score unexamined pages as examined, so it is refused instead.
            if int(getattr(image, "n_frames", 1) or 1) > 1:
                raise EvidenceRejected(FAILURE_PAGE_LIMIT, limit=1)
            _check_deadline(deadline)
            text = _ocr_image(image, deadline)
    except EvidenceRejected:
        raise
    except Image.DecompressionBombError as error:
        raise EvidenceRejected(FAILURE_PIXEL_LIMIT, limit=limit) from error
    except (
        Image.DecompressionBombWarning
    ) as error:  # pragma: no cover - policy dependent
        raise EvidenceRejected(FAILURE_PIXEL_LIMIT, limit=limit) from error
    except (UnidentifiedImageError, OSError, ValueError) as error:
        raise EvidenceRejected(FAILURE_UNREADABLE) from error
    finally:
        Image.MAX_IMAGE_PIXELS = previous

    return Extraction(
        media_type=media_type,
        text=_bound_text([text], settings.EVIDENCE_MAX_EXTRACTED_CHARS),
        char_count=len(text),
        page_count=1,
        engine="ocr",
    )


def _ocr_image(image, deadline: float) -> str:
    """OCR under a hard timeout; a missing engine is a failure, not a pass."""
    try:
        import pytesseract
        from pytesseract import TesseractNotFoundError
    except ImportError as error:
        raise EvidenceRejected(FAILURE_ENGINE_UNAVAILABLE) from error

    remaining = max(1, int(deadline - time.monotonic()))
    try:
        return pytesseract.image_to_string(image, timeout=remaining) or ""
    except TesseractNotFoundError as error:
        # Unreadable evidence must never be reported as readable-and-empty:
        # empty text would score as "no signals found", which reads as a
        # tenant finding rather than as a broken collection.
        raise EvidenceRejected(FAILURE_OCR_UNAVAILABLE) from error
    except RuntimeError as error:
        raise EvidenceRejected(FAILURE_TIMEOUT) from error
    except (OSError, ValueError) as error:
        raise EvidenceRejected(FAILURE_UNREADABLE) from error


def _extract_pdf(data: bytes, settings: Settings, deadline: float) -> Extraction:
    try:
        import fitz
    except ImportError as error:
        raise EvidenceRejected(FAILURE_ENGINE_UNAVAILABLE) from error

    max_pages = settings.EVIDENCE_MAX_PDF_PAGES
    max_chars = settings.EVIDENCE_MAX_EXTRACTED_CHARS
    document = None
    try:
        document = fitz.open(stream=data, filetype="pdf")
        page_count = document.page_count
        if page_count > max_pages:
            raise EvidenceRejected(FAILURE_PAGE_LIMIT, limit=max_pages)
        parts: list[str] = []
        length = 0
        for index in range(page_count):
            _check_deadline(deadline)
            page_text = document.load_page(index).get_text() or ""
            length += len(page_text)
            if length > max_chars:
                raise EvidenceRejected(FAILURE_EXTRACT_LIMIT, limit=max_chars)
            parts.append(page_text)
    except EvidenceRejected:
        raise
    except Exception as error:  # noqa: BLE001 - third-party parser, redacted below
        raise EvidenceRejected(FAILURE_UNREADABLE) from error
    finally:
        if document is not None:
            try:
                document.close()
            except Exception:  # noqa: BLE001 - close failures are not caller visible
                logger.warning("PDF handle could not be closed cleanly")

    # No rasterisation and no preview file: the legacy preview write was an
    # unbounded disk side effect on caller-supplied bytes.
    text = _bound_text(parts, max_chars)
    return Extraction(
        media_type=MEDIA_PDF,
        text=text,
        char_count=len(text),
        page_count=page_count,
        engine="pdf",
    )


def _guard_archive(data: bytes, settings: Settings, deadline: float) -> None:
    """Inspect the central directory before a single entry is decompressed.

    Three independent ceilings apply, because a ratio alone is not a memory
    bound: at the shipped defaults a 25 MB upload with an acceptable ratio still
    expands to about 3 GB, which would end the API process rather than the
    request. ``EVIDENCE_PROCESSING_MEMORY_MB`` is the absolute ceiling.
    """
    max_entries = settings.EVIDENCE_MAX_ARCHIVE_ENTRIES
    max_ratio = settings.EVIDENCE_MAX_ARCHIVE_RATIO
    max_expanded = settings.EVIDENCE_PROCESSING_MEMORY_MB * 1024 * 1024
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > max_entries:
                raise EvidenceRejected(FAILURE_ARCHIVE_BOMB, limit=max_entries)
            uncompressed = 0
            compressed = 0
            for entry in entries:
                _check_deadline(deadline)
                if entry.file_size < 0 or entry.compress_size < 0:
                    raise EvidenceRejected(FAILURE_ARCHIVE_BOMB)
                uncompressed += entry.file_size
                compressed += entry.compress_size
                if uncompressed > max_expanded:
                    raise EvidenceRejected(FAILURE_ARCHIVE_BOMB, limit=max_expanded)
    except EvidenceRejected:
        raise
    except (zipfile.BadZipFile, OSError, ValueError) as error:
        raise EvidenceRejected(FAILURE_UNREADABLE) from error

    if uncompressed > max_ratio * max(compressed, 1):
        raise EvidenceRejected(FAILURE_ARCHIVE_BOMB, limit=max_ratio)
    if uncompressed > max_ratio * len(data):
        raise EvidenceRejected(FAILURE_ARCHIVE_BOMB, limit=max_ratio)


def _extract_docx(data: bytes, settings: Settings, deadline: float) -> Extraction:
    _guard_archive(data, settings, deadline)
    try:
        from docx import Document as DocxDocument
    except ImportError as error:
        raise EvidenceRejected(FAILURE_ENGINE_UNAVAILABLE) from error

    max_chars = settings.EVIDENCE_MAX_EXTRACTED_CHARS
    parts: list[str] = []
    length = 0
    try:
        document = DocxDocument(io.BytesIO(data))
        for paragraph in document.paragraphs:
            _check_deadline(deadline)
            if not paragraph.text:
                continue
            length += len(paragraph.text) + 1
            if length > max_chars:
                raise EvidenceRejected(FAILURE_EXTRACT_LIMIT, limit=max_chars)
            parts.append(paragraph.text)
            parts.append("\n")
        for table in document.tables:
            for row in table.rows:
                _check_deadline(deadline)
                for cell in row.cells:
                    if not cell.text:
                        continue
                    length += len(cell.text) + 1
                    if length > max_chars:
                        raise EvidenceRejected(FAILURE_EXTRACT_LIMIT, limit=max_chars)
                    parts.append(cell.text)
                    parts.append("\n")
    except EvidenceRejected:
        raise
    except Exception as error:  # noqa: BLE001 - third-party parser, redacted below
        raise EvidenceRejected(FAILURE_UNREADABLE) from error

    text = _bound_text(parts, max_chars)
    return Extraction(
        media_type=MEDIA_DOCX,
        text=text,
        char_count=len(text),
        page_count=None,
        engine="docx",
    )


def _extract_text(data: bytes, settings: Settings, deadline: float) -> Extraction:
    _check_deadline(deadline)
    max_chars = settings.EVIDENCE_MAX_EXTRACTED_CHARS
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceRejected(FAILURE_UNREADABLE) from error
    if len(text) > max_chars:
        raise EvidenceRejected(FAILURE_EXTRACT_LIMIT, limit=max_chars)
    return Extraction(
        media_type=MEDIA_TEXT,
        text=text,
        char_count=len(text),
        page_count=None,
        engine="text",
    )


def extract_sync(
    data: bytes, media_type: str, settings: Settings, deadline: float
) -> Extraction:
    """The one and only extraction entry point. Blocking, thread-only."""
    _check_deadline(deadline)
    if media_type in IMAGE_MEDIA_TYPES:
        return _extract_image(data, media_type, settings, deadline)
    if media_type == MEDIA_PDF:
        return _extract_pdf(data, settings, deadline)
    if media_type == MEDIA_DOCX:
        return _extract_docx(data, settings, deadline)
    if media_type == MEDIA_TEXT:
        return _extract_text(data, settings, deadline)
    raise EvidenceRejected(FAILURE_UNSUPPORTED_TYPE)


# ---------------------------------------------------------------------------
# async wrappers: everything below keeps the event loop free
# ---------------------------------------------------------------------------
async def _run_bounded(function, *arguments, timeout: float):
    """Run blocking work off the loop and stop waiting at the deadline.

    ``abandon_on_cancel`` lets the request fail immediately at the timeout. The
    abandoned thread holds bytes in memory only and re-checks the same deadline,
    so it stops shortly afterwards; its result is discarded either way and it
    never writes a file, a preview or a row.
    """
    result: list = []

    def call() -> None:
        result.append(function(*arguments))

    with anyio.move_on_after(timeout) as scope:
        await anyio.to_thread.run_sync(call, abandon_on_cancel=True)
    if scope.cancelled_caught or not result:
        raise EvidenceRejected(FAILURE_TIMEOUT, limit=int(timeout))
    return result[0]


async def load_bounded_bytes(
    storage: EvidenceStorage, key: str, *, settings: Settings | None = None
) -> bytes:
    """Read a stored object back inside the configured byte ceiling."""
    active = settings or get_settings()
    try:
        return await storage.read_bounded(
            key, max_bytes=active.EVIDENCE_MAX_UPLOAD_BYTES
        )
    except EvidenceTooLargeError as error:
        raise EvidenceRejected(
            FAILURE_TOO_LARGE, limit=active.EVIDENCE_MAX_UPLOAD_BYTES
        ) from error
    except EvidenceStorageError as error:
        raise EvidenceRejected(FAILURE_UNREADABLE) from error


async def detect_media_type(
    data: bytes,
    *,
    display_filename: str | None,
    settings: Settings | None = None,
) -> Detection:
    """Sniff and cross-check the declared extension, off the event loop."""
    active = settings or get_settings()
    try:
        return await _run_bounded(
            detect_media_type_sync,
            data,
            display_filename,
            active,
            timeout=active.EVIDENCE_PROCESSING_TIMEOUT_SECONDS,
        )
    except EvidenceRejected:
        raise
    except Exception as error:  # noqa: BLE001 - no sniffer fault may escape raw
        logger.warning("Evidence content type could not be determined")
        raise EvidenceRejected(FAILURE_UNREADABLE) from error


async def extract_text_bounded(
    data: bytes,
    *,
    media_type: str,
    settings: Settings | None = None,
) -> Extraction:
    """Extract exactly once, under every configured bound."""
    active = settings or get_settings()
    timeout = float(active.EVIDENCE_PROCESSING_TIMEOUT_SECONDS)
    deadline = time.monotonic() + timeout
    try:
        return await _run_bounded(
            extract_sync, data, media_type, active, deadline, timeout=timeout
        )
    except EvidenceRejected:
        raise
    except Exception as error:  # noqa: BLE001 - no parser fault may escape raw
        # A third-party parser must never surface as a 500 with a traceback.
        logger.warning("Evidence extraction failed for %s", media_type)
        raise EvidenceRejected(FAILURE_UNREADABLE) from error


async def run_bounded_callable(function, *arguments, settings: Settings | None = None):
    """Run untrusted legacy matching code off the loop, under the timeout."""
    active = settings or get_settings()
    return await _run_bounded(
        function, *arguments, timeout=active.EVIDENCE_PROCESSING_TIMEOUT_SECONDS
    )
