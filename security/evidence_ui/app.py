"""Evidence extraction helpers plus an opt-in, non-production development server.

Importing this module is side-effect free by design (AUTH-02): it builds no
FastAPI application, installs no CORS middleware, mounts no directories, probes
no OCR binary and writes no files. The authenticated backend router
(`backend-api/app/api/v1/evidence.py`) imports the helpers below; the standalone
legacy server exists only if `create_app()` is called explicitly, and that
factory refuses to build unless a developer opts in on a non-production machine.
"""

from __future__ import annotations

import html
import inspect
import io
import os
import re
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytesseract
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from PIL import Image, UnidentifiedImageError
from pytesseract import TesseractNotFoundError

try:
    import fitz  # PyMuPDF for PDFs
except Exception:
    fitz = None

try:
    from docx import Document as DocxDocument  # python-docx
except Exception:
    DocxDocument = None

# -------------------- Import modules --------------------

# NOTE: When imported from the FastAPI backend, the project root (`/app`) is on
# `sys.path`, so `security.*` imports resolve. `reports.*` does not, because
# `reports/` lives under `security/`.
from security.reports.report_service import generate_pdf
from security.strategies import load_strategies

# -------------------- paths --------------------
# Paths relative to security/. `resolve()` reads the filesystem to normalise
# symlinks, but nothing here creates, writes or opens a file at import time.
ROOT = Path(__file__).resolve().parents[1]  # .../security
RESULTS = ROOT / "results"  # security/results/...
TEMPLATES = RESULTS  # report_template.docx lives here
OUT_DIR = RESULTS / "reports"  # PDF (or DOCX/TXT) outputs
PREVIEWS = RESULTS / "previews"  # preview images for evidence
UI_DIR = Path(__file__).resolve().parent  # bundled single-page UI assets
INDEX_HTML = UI_DIR / "ui.html"  # the ONE html file the dev server may serve
LOGO_PNG = UI_DIR / "AutoAudit.png"  # the ONE image the dev server may serve


# -------------------- development-server gate --------------------
# The legacy standalone app has no authentication on any route. It must never be
# reachable from a deployed environment, so serving it requires two deliberate
# signals: an explicit opt-in variable AND a non-production APP_ENV.
DEV_SERVER_ENV_VAR = "AUTOAUDIT_EVIDENCE_UI_DEV_SERVER"
NON_PRODUCTION_ENVIRONMENTS = frozenset({"dev", "development", "local", "test"})
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _app_env() -> str:
    """The environment name exactly as configured — never defaulted.

    Defaulting an unset `APP_ENV` would turn the second signal into no signal at
    all: a deployed process that inherited the opt-in variable but no `APP_ENV`
    would silently look like a development box.
    """
    return (os.environ.get("APP_ENV") or "").strip().lower()


def dev_server_enabled() -> bool:
    """True only when a developer has explicitly opted into the legacy server."""
    return (os.environ.get(DEV_SERVER_ENV_VAR) or "").strip().lower() in _TRUTHY


def _require_dev_server_opt_in() -> None:
    """Raise unless this process is explicitly allowed to serve the legacy app."""
    if not dev_server_enabled():
        raise RuntimeError(
            "The standalone evidence UI is disabled because it has no "
            "authentication on any route. Set "
            f"{DEV_SERVER_ENV_VAR}=1 on a local development machine to build it; "
            "deployed traffic must use the authenticated backend router at "
            "/v1/evidence."
        )
    environment = _app_env()
    if environment not in NON_PRODUCTION_ENVIRONMENTS:
        raise RuntimeError(
            "The standalone evidence UI refuses to start with "
            f"APP_ENV={environment!r}. The unauthenticated legacy app is only "
            f"permitted when APP_ENV is explicitly set to one of "
            f"{sorted(NON_PRODUCTION_ENVIRONMENTS)}; an unset APP_ENV is refused "
            "so that an inherited opt-in cannot serve it by accident."
        )


# -------------------- environment checks --------------------
_TESSERACT_PROBE: tuple[bool, str] | None = None


def _tesseract_status() -> tuple[bool, str]:
    """Probe Tesseract lazily and cache it.

    Importing this module must not spawn a subprocess, so the version lookup is
    deferred until something actually asks (i.e. `health()`).
    """
    global _TESSERACT_PROBE
    if _TESSERACT_PROBE is None:
        try:
            _TESSERACT_PROBE = (True, str(pytesseract.get_tesseract_version()))
        except Exception:
            _TESSERACT_PROBE = (False, "")
    return _TESSERACT_PROBE


# -------------------- utility --------------------
def _safe_uid(s: str) -> str:
    """Make a filesystem-safe id (no spaces/odd chars)."""
    s = re.sub(r"\s+", "_", s.strip())
    return re.sub(r"[^A-Za-z0-9._-]", "-", s)


# -------------------- extraction helpers --------------------
def _ocr_image_bytes(data: bytes) -> str:
    """OCR bytes of an image; if Tesseract is missing, return empty text instead of 500."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            try:
                return pytesseract.image_to_string(img)
            except TesseractNotFoundError:
                return ""  # no OCR available → behave gracefully
    except (UnidentifiedImageError, OSError):
        return ""


def _extract_pdf_bytes(
    data: bytes, previews_dir: Path, stem: str
) -> tuple[str, Path | None]:
    if not fitz:
        return "", None
    try:
        doc = fitz.open(stream=data, filetype="pdf")
        text = "".join((page.get_text() or "") for page in doc)
        preview_path: Path | None = None
        if len(doc) > 0:
            pix = doc[0].get_pixmap()
            previews_dir.mkdir(parents=True, exist_ok=True)
            preview_path = previews_dir / f"{stem}_page1.png"
            pix.save(str(preview_path))
        doc.close()
        return text, preview_path
    except Exception:
        return "", None


def _extract_docx_bytes(data: bytes) -> str:
    if not DocxDocument:
        return ""
    try:
        doc = DocxDocument(io.BytesIO(data))
        parts: list[str] = []
        for p in doc.paragraphs:
            if p.text:
                parts.append(p.text)
        for tbl in doc.tables:
            for row in tbl.rows:
                for cell in row.cells:
                    if cell.text:
                        parts.append(cell.text)
        return "\n".join(parts)
    except Exception:
        return ""


def extract_text_and_preview_bytes(
    filename: str, data: bytes, previews_dir: Path
) -> tuple[str, Path | None]:
    """Extract text and (for images/PDFs) write a preview into `previews_dir`.

    NOTE for the backend owner (EVI-01): this helper has a disk side effect — it
    writes caller-supplied bytes under `previews_dir` — and applies no size,
    page, pixel or timeout bound. Those limits and the OCR offload belong to the
    backend/worker layer, not here.
    """
    ext = Path(filename).suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}:
        text = _ocr_image_bytes(data)
        previews_dir.mkdir(parents=True, exist_ok=True)
        preview_path = previews_dir / _safe_uid(filename)
        with open(preview_path, "wb") as f:
            f.write(data)
        return text, preview_path
    if ext == ".pdf":
        return _extract_pdf_bytes(data, previews_dir, Path(_safe_uid(filename)).stem)
    if ext == ".docx":
        return _extract_docx_bytes(data), None
    if ext in {
        ".txt",
        ".log",
        ".reg",
        ".csv",
        ".ini",
        ".json",
        ".xml",
        ".htm",
        ".html",
    }:
        return data.decode("utf-8", errors="ignore"), None
    return "", None


# -------------------- recent scans: in-memory log --------------------
SCAN_MEM: deque[dict[str, str]] = deque(maxlen=50)

_LOG_VALUE_MAX = 120
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_LOG_STATUSES = frozenset({"success", "error"})


def _scrub_log_value(value: object) -> str:
    """Bound and de-control free text before it is remembered.

    Rendering escapes these values too; this only stops the in-memory log from
    becoming an unbounded store of caller-supplied text and keeps control
    characters out of any log line that quotes it.
    """
    return _CONTROL_CHARS.sub(" ", str(value))[:_LOG_VALUE_MAX]


def _push_mem_log(user: str, strategy: str, status: str) -> None:
    """Remember one scan outcome. status: 'success' | 'error'."""
    SCAN_MEM.appendleft(
        {
            "ts": datetime.now().astimezone().isoformat(),
            "user": _scrub_log_value(user),
            "strategy": _scrub_log_value(strategy),
            "status": status if status in _LOG_STATUSES else "error",
        }
    )


def index():
    """Serve the single bundled UI file — never a directory."""
    if INDEX_HTML.is_file():
        return INDEX_HTML.read_text(encoding="utf-8", errors="ignore")
    return "<h3>AutoAudit Evidence Scanner</h3>"


def api_strategies():
    out = []
    for s in load_strategies():
        try:
            desc = s.description()
        except Exception:
            desc = ""
        meta = getattr(s, "meta", None)
        out.append(
            {
                "name": getattr(s, "name", ""),
                "description": desc,
                "category": getattr(meta, "category", "") if meta else "",
                "severity": getattr(meta, "severity", "") if meta else "",
                "evidence_types": list(getattr(meta, "evidence_types", []) or [])
                if meta
                else [],
            }
        )
    return out


def health():
    """Quick status to debug issues without crashing the UI."""
    has_tesseract, version = _tesseract_status()
    return {
        "ok": True,
        "has_tesseract": has_tesseract,
        "tesseract_version": version,
        "template_exists": (TEMPLATES / "report_template.docx").exists(),
        "previews_dir": str(PREVIEWS),
        "out_dir": str(OUT_DIR),
    }


def api_get_scan_mem_log():
    return JSONResponse(list(SCAN_MEM))


def _cell(value: object) -> str:
    """Escape one table cell. Every interpolated value goes through here."""
    return html.escape(str(value), quote=True)


def scan_mem_page():
    """Render the recent-scan log.

    Every interpolated value is HTML-escaped: entries may carry caller-supplied
    text, so this is the sink that must never emit raw markup (AUTH-02).
    """
    rows = (
        "".join(
            f"<tr><td>{_cell(r.get('ts', ''))}</td>"
            f"<td>{_cell(r.get('user', ''))}</td>"
            f"<td>{_cell(r.get('strategy', ''))}</td>"
            f"<td>{_cell(r.get('status', ''))}</td></tr>"
            for r in SCAN_MEM
        )
        or "<tr><td colspan='4'>No runs yet</td></tr>"
    )
    return HTMLResponse(
        f"""<!doctype html>
<meta charset="utf-8">
<title>Recent Scans — AutoAudit</title>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#fff;color:#111;margin:24px}}
  a{{color:#0d6efd;text-decoration:none}}
  table{{border-collapse:collapse;width:100%;max-width:1040px;margin-top:12px}}
  th,td{{border:1px solid #e5e7eb;padding:10px;font-size:14px}}
  th{{background:#f9fafb;text-align:left}}
  .ok{{color:#047857;font-weight:700}}
  .bad{{color:#b00020;font-weight:700}}
</style>
<h1 style="margin:0 0 8px 0;">Recent Scans</h1>
<p><a href="/">← Back to scanner</a></p>
<table>
  <tr><th>Time</th><th>User</th><th>Strategy</th><th>Status</th></tr>
  {rows}
</table>"""
    )


def _recent_scans_redirect():
    return RedirectResponse(url="/scan-mem")


def _scan_log_redirect():
    return RedirectResponse(url="/scan-mem")


async def scan(
    evidence: UploadFile = File(...),
    strategy_name: str = Form(...),
    user_id: str = Form("user"),
):
    # Only a strategy name that resolved to a registered strategy is ever
    # remembered, so caller-supplied free text does not reach SCAN_MEM at all.
    # Escaping in `scan_mem_page()` remains the authoritative defence.
    resolved_name = "unknown"
    try:
        # find strategy
        strategy = next((s for s in load_strategies() if s.name == strategy_name), None)
        if not strategy:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown strategy: {_scrub_log_value(strategy_name)}",
            )
        resolved_name = str(getattr(strategy, "name", "") or "unknown")

        # read upload
        content = await evidence.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty upload")

        filename = evidence.filename or "evidence"

        # extract text + preview
        text, preview_path = extract_text_and_preview_bytes(filename, content, PREVIEWS)
        if not text.strip():
            # log a successful run even without readable text
            _push_mem_log(user_id, resolved_name, "success")
            return JSONResponse(
                {
                    "ok": True,
                    "findings": [],
                    "reports": [],
                    "note": "No readable text found in evidence.",
                }
            )

        # run rules
        if hasattr(strategy, "emit_hits"):
            findings = strategy.emit_hits(text, source_file=filename) or []
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

        # generate reports (PDF preferred; fallback DOCX/TXT so we never 500)
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        generated: list[str] = []
        note = ""

        for r in findings:
            base_uid = _safe_uid(f"{user_id}-{strategy.name}-{Path(filename).stem}")
            # make name unique to avoid 'Permission denied' if file is locked from previous run
            uid = f"{base_uid}-{int(time.time())}"

            # payload for the existing template flow
            payload = {
                "UniqueID": uid,
                "UserID": user_id,
                "Evidence": filename,
                "Evidence Preview": str(preview_path) if preview_path else "",
                "Strategy": strategy.name,
                "TestID": r.get("test_id", ""),
                "Sub-Strategy": r.get("sub_strategy", ""),
                "ML Level": r.get("detected_level", ""),
                "Pass/Fail": r.get("pass_fail", ""),
                "Priority": r.get("priority", ""),
                "Recommendation": r.get("recommendation", ""),
                "Evidence Extract": "; ".join(r.get("evidence", [])),
                "Description": r.get("description", ""),
                "Confidence": r.get("confidence", ""),
            }

            try:
                pdf_path = generate_pdf(
                    payload,
                    template_path=str(TEMPLATES / "report_template.docx"),
                    output_dir=str(OUT_DIR),
                    base_dir=str(ROOT),
                )
                generated.append(Path(pdf_path).name)
            except Exception:
                # Fallback: create a simple DOCX (or TXT) so the UI still returns a download
                note = "PDF converter not available or file was locked; generated a DOCX/TXT fallback."
                fallback_name = f"{uid}.docx" if DocxDocument else f"{uid}.txt"
                fallback_path = OUT_DIR / fallback_name

                try:
                    if DocxDocument:
                        doc = DocxDocument()
                        doc.add_heading("AutoAudit – Finding", 0)
                        doc.add_paragraph(f"Strategy: {strategy.name}")
                        doc.add_paragraph(f"Test ID: {payload['TestID']}")
                        doc.add_paragraph(f"Pass/Fail: {payload['Pass/Fail']}")
                        if payload["Recommendation"]:
                            doc.add_paragraph(
                                f"Recommendation: {payload['Recommendation']}"
                            )
                        if payload["Evidence Extract"]:
                            doc.add_paragraph("Evidence:")
                            doc.add_paragraph(payload["Evidence Extract"])
                        doc.save(str(fallback_path))
                    else:
                        with open(fallback_path, "w", encoding="utf-8") as f:
                            f.write(f"Strategy: {strategy.name}\n")
                            f.write(f"Test ID: {payload['TestID']}\n")
                            f.write(f"Pass/Fail: {payload['Pass/Fail']}\n")
                            f.write(f"Recommendation: {payload['Recommendation']}\n")
                            f.write(f"Evidence: {payload['Evidence Extract']}\n")
                    generated.append(fallback_path.name)
                except Exception:
                    # If even the fallback fails, keep going without a report link
                    note = (
                        "Report generation failed; no downloadable report was produced."
                    )

        _push_mem_log(user_id, resolved_name, "success")
        return {"ok": True, "findings": findings, "reports": generated, "note": note}

    except HTTPException:
        _push_mem_log(user_id, resolved_name, "error")
        raise
    except Exception:
        _push_mem_log(user_id, resolved_name, "error")
        raise


# -------------------- report downloads --------------------
# `authorize` receives the resolved report path and must return True only when
# the current principal is allowed to read it.
ReportAuthorizer = Callable[[Path], bool]

# A malformed path must be a 400, never a traceback. Older CPython raises
# RuntimeError (not OSError) when `resolve()` walks a symlink loop.
_PATH_ERRORS = (ValueError, OSError, RuntimeError)

_MEDIA_TYPES = {
    ".pdf": "application/pdf",
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ),
}


def resolve_report_path(filename: str, reports_dir: Path | None = None) -> Path:
    """Resolve a bare report file name to a real file inside `reports_dir`.

    Rejects anything that is not a plain name directly inside the directory:
    traversal segments, path separators, absolute paths, NUL bytes and symlinks
    that resolve outside the directory. Raises `HTTPException` — 400 for a
    malformed name, 404 when the report does not exist.
    """
    name = filename or ""
    if (
        not name
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or name != Path(name).name
    ):
        raise HTTPException(status_code=400, detail="Invalid filename")

    try:
        base = (reports_dir or OUT_DIR).resolve()
        path = (base / name).resolve()
        if path == base or not path.is_relative_to(base):
            raise HTTPException(status_code=400, detail="Invalid filename")
        is_file = path.is_file()
    except _PATH_ERRORS as error:
        # e.g. a symlink loop or a name longer than the platform allows.
        raise HTTPException(status_code=400, detail="Invalid filename") from error
    if not is_file:
        raise HTTPException(status_code=404, detail="Report not found")
    return path


def _report_response(path: Path) -> FileResponse:
    """Build the download response for an already-validated, authorized path.

    RESIDUAL (for the storage owner, plan item 15.1.9): `FileResponse` re-opens
    the path when the response is streamed, so a principal who can write inside
    the reports directory could swap the validated file for a symlink in between.
    Closing that race needs the checked file descriptor to be the one served,
    which belongs with the object-storage work rather than this legacy shim.
    """
    media = _MEDIA_TYPES.get(path.suffix.lower(), "text/plain")
    return FileResponse(str(path), media_type=media, filename=path.name)


def _require_positive_decision(decision: object) -> None:
    """Accept only a literal True. Anything else denies.

    A truthy-but-not-True result is almost always a mistake — an unawaited
    coroutine from an `async def` authorizer is truthy, so `if not authorize(...)`
    would have granted access without ever running the check.
    """
    if inspect.isawaitable(decision):
        close = getattr(decision, "close", None)
        if close is not None:
            close()
        raise TypeError(
            "authorize must be a synchronous callable returning a bool. An "
            "awaitable result is truthy, so the authorization check would be "
            "skipped; await your check before calling download_report()."
        )
    if decision is not True:
        raise HTTPException(status_code=404, detail="Report not found")


def download_report(
    filename: str,
    *,
    authorize: ReportAuthorizer,
    reports_dir: Path | None = None,
) -> FileResponse:
    """Serve a generated report, but only once the caller has authorized it.

    `authorize` is mandatory and keyword-only: there is deliberately no way to
    fetch a report by name alone (AUTH-02). It is called with the resolved path
    and must return exactly `True` for a principal entitled to that report; every
    other value, including a truthy one, denies. An unauthorized request is
    answered 404 so the endpoint does not confirm which report names exist.
    """
    path = resolve_report_path(filename, reports_dir)
    _require_positive_decision(authorize(path))
    return _report_response(path)


def download_authorized_report(
    path: Path, *, reports_dir: Path | None = None
) -> FileResponse:
    """Serve a report the caller has ALREADY resolved and authorized.

    `path` must be absolute and, after symlink resolution, inside `reports_dir`.
    Use this when the backend has looked the object up by owner-scoped id and no
    longer needs a name-based lookup at all. An absolute path is not by itself
    proof of authorization: the caller owns that check.
    """
    try:
        base = (reports_dir or OUT_DIR).resolve()
        candidate = Path(path)
        if not candidate.is_absolute():
            raise HTTPException(status_code=400, detail="Invalid report path")
        resolved = candidate.resolve()
        if resolved == base or not resolved.is_relative_to(base):
            raise HTTPException(status_code=400, detail="Invalid report path")
        is_file = resolved.is_file()
    except _PATH_ERRORS as error:
        # e.g. an embedded NUL byte, a name too long, or a symlink loop.
        raise HTTPException(status_code=400, detail="Invalid report path") from error
    if not is_file:
        raise HTTPException(status_code=404, detail="Report not found")
    return _report_response(resolved)


# -------------------- opt-in development server --------------------
def _dev_serve_ui_logo() -> FileResponse:
    """Serve the one bundled logo file. The package directory is never mounted."""
    if not LOGO_PNG.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(str(LOGO_PNG), media_type="image/png")


def _dev_authorize_every_report(path: Path) -> bool:
    """Development-only authorizer: the local harness has no identity to check.

    This is reachable only from `create_app()`, which refuses to build outside an
    explicitly opted-in, non-production environment. Deployed report access goes
    through the authenticated backend with a real ownership check.
    """
    return True


def _dev_download_report(filename: str) -> FileResponse:
    return download_report(filename, authorize=_dev_authorize_every_report)


def create_app() -> FastAPI:
    """Build the legacy standalone app for local development only.

    Refuses unless `AUTOAUDIT_EVIDENCE_UI_DEV_SERVER` is set truthy AND `APP_ENV`
    is explicitly set to a non-production environment — both signals must be
    present, and an unset `APP_ENV` is a refusal. There is no wildcard CORS and no
    static directory mount: exactly two asset files are reachable, each by its own
    route. Run it with:

        AUTOAUDIT_EVIDENCE_UI_DEV_SERVER=1 APP_ENV=dev uvicorn \\
            security.evidence_ui.app:create_app --factory --host 127.0.0.1
    """
    _require_dev_server_opt_in()

    app = FastAPI(
        title="AutoAudit Evidence Scanner (local development only)",
        description=(
            "Unauthenticated local harness for the legacy evidence scanner. "
            "Never expose this on a network; deployed traffic uses the "
            "authenticated backend router at /v1/evidence."
        ),
    )

    app.get("/", response_class=HTMLResponse)(index)
    app.get("/strategies")(api_strategies)
    app.get("/health")(health)
    app.get("/api/scan-mem-log")(api_get_scan_mem_log)
    app.get("/scan-mem", response_class=HTMLResponse)(scan_mem_page)
    app.get("/recent-scans", include_in_schema=False)(_recent_scans_redirect)
    app.get("/scan-log", include_in_schema=False)(_scan_log_redirect)
    app.get("/frontend/AutoAudit.png", include_in_schema=False)(_dev_serve_ui_logo)
    app.post("/scan")(scan)
    app.get("/reports/{filename}")(_dev_download_report)
    return app
