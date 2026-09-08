"""AUTH-02: importing the legacy evidence module serves nothing and leaks nothing."""

import builtins
import importlib
import io
import os
import subprocess  # nosec B404 # only the fixed-argv audit probe below
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

evidence_ui = importlib.import_module("security.evidence_ui.app")

XSS_PAYLOAD = "<script>alert(1)</script>"
ESCAPED_PAYLOAD = "&lt;script&gt;alert(1)&lt;/script&gt;"


@pytest.fixture
def scan_mem():
    """Isolate the shared in-memory log so tests never observe each other."""
    evidence_ui.SCAN_MEM.clear()
    yield evidence_ui.SCAN_MEM
    evidence_ui.SCAN_MEM.clear()


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    directory = tmp_path / "reports"
    directory.mkdir()
    monkeypatch.setattr(evidence_ui, "OUT_DIR", directory)
    return directory


# -------------------- import is inert --------------------


@pytest.mark.parametrize("attribute", ["app", "UI_DIR_MOUNT", "StaticFiles"])
def test_import_exposes_no_application_or_mount(attribute):
    assert not hasattr(evidence_ui, attribute)


def test_module_never_imports_cors_or_staticfiles():
    source = Path(evidence_ui.__file__).read_text(encoding="utf-8")
    assert "CORSMiddleware" not in source
    assert "StaticFiles" not in source
    assert "allow_origins" not in source
    assert ".mount(" not in source


def test_reimport_writes_nothing_and_spawns_no_process(monkeypatch):
    """Re-execute the module body with the write and subprocess paths trapped."""
    writes: list[object] = []
    spawns: list[object] = []
    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            writes.append(("open", file))
        return real_open(file, mode, *args, **kwargs)

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
            writes.append(("os.open", path))
        return real_os_open(path, flags, *args, **kwargs)

    def record_write(target, *args, **kwargs):
        writes.append(("write", target))

    def guarded_spawn(*args, **kwargs):
        spawns.append(args)
        raise AssertionError("import must not spawn a subprocess")

    real_os_open = os.open
    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    monkeypatch.setattr(os, "mkdir", record_write)
    monkeypatch.setattr(os, "makedirs", record_write)
    monkeypatch.setattr(Path, "mkdir", record_write)
    monkeypatch.setattr(Path, "open", record_write)
    monkeypatch.setattr(Path, "write_bytes", record_write)
    monkeypatch.setattr(Path, "write_text", record_write)
    monkeypatch.setattr(subprocess, "Popen", guarded_spawn)
    monkeypatch.setattr(subprocess, "run", guarded_spawn)
    monkeypatch.setattr(subprocess, "check_output", guarded_spawn)
    monkeypatch.setattr(os, "system", guarded_spawn)

    importlib.reload(evidence_ui)

    assert writes == []
    assert spawns == []


# The audit-hook probe below is stronger than monkeypatching: hooks fire inside
# CPython, so a write or spawn cannot dodge them by holding an alias. Only
# third-party dependencies are pre-imported; every first-party `security.*`
# import happens under the hook, so a side effect anywhere in our own package is
# still caught.
_AUDIT_PROBE = """
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, {root!r})

import PIL.Image
import fastapi
import fastapi.responses
import pytesseract

for _optional in ("fitz", "docx", "fpdf"):
    try:
        __import__(_optional)
    except Exception:
        pass

WRITE_FLAGS = 0
import os

for name in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"):
    WRITE_FLAGS |= getattr(os, name, 0)

SPAWNS = (
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.fork",
    "socket.bind",
)
violations = []


def hook(event, args):
    if event == "open":
        mode, flags = args[1], args[2]
        if mode and any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            violations.append((event, str(args[0])))
        elif mode is None and isinstance(flags, int) and flags & WRITE_FLAGS:
            violations.append((event, str(args[0])))
    elif event.startswith(SPAWNS) or event in {{
        "os.mkdir",
        "os.rename",
        "os.remove",
        "os.rmdir",
        "os.symlink",
        "os.link",
        "os.truncate",
    }}:
        violations.append((event, str(args[0]) if args else ""))


sys.addaudithook(hook)

assert "security.evidence_ui.app" not in sys.modules
import security.evidence_ui.app  # noqa: F401

assert "security.evidence_ui.app" in sys.modules
print(violations)
"""


def test_cold_import_under_an_audit_hook_writes_nothing_and_spawns_nothing():
    """Import the module in a fresh interpreter with CPython audit hooks watching."""
    completed = subprocess.run(  # nosec B603 # fixed argv, no shell, our own probe
        [sys.executable, "-B", "-c", _AUDIT_PROBE.format(root=str(ROOT))],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        cwd=str(ROOT),
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "[]", completed.stdout


def test_helpers_the_backend_router_imports_stay_available():
    for name in (
        "api_strategies",
        "health",
        "scan_mem_page",
        "api_get_scan_mem_log",
        "extract_text_and_preview_bytes",
        "scan",
        "download_report",
        "PREVIEWS",
        "OUT_DIR",
        "ROOT",
    ):
        assert hasattr(evidence_ui, name), name


# -------------------- the dev server is opt-in and never production --------------------


@pytest.mark.parametrize("opt_in", [None, "", "0", "false", "no", "off", "maybe"])
def test_create_app_refuses_without_explicit_opt_in(monkeypatch, opt_in):
    monkeypatch.delenv(evidence_ui.DEV_SERVER_ENV_VAR, raising=False)
    monkeypatch.setenv("APP_ENV", "dev")
    if opt_in is not None:
        monkeypatch.setenv(evidence_ui.DEV_SERVER_ENV_VAR, opt_in)
    with pytest.raises(RuntimeError, match="no authentication"):
        evidence_ui.create_app()


@pytest.mark.parametrize(
    "environment",
    ["production", "prod", "staging", "preview", "acceptance", "PROD", "", "   "],
)
def test_create_app_refuses_outside_a_development_environment(monkeypatch, environment):
    monkeypatch.setenv(evidence_ui.DEV_SERVER_ENV_VAR, "1")
    monkeypatch.setenv("APP_ENV", environment)
    with pytest.raises(RuntimeError, match="refuses to start"):
        evidence_ui.create_app()


def test_create_app_refuses_when_app_env_is_not_set_at_all(monkeypatch):
    """An inherited opt-in must not serve the app just because APP_ENV is absent."""
    monkeypatch.setenv(evidence_ui.DEV_SERVER_ENV_VAR, "1")
    monkeypatch.delenv("APP_ENV", raising=False)
    with pytest.raises(RuntimeError, match="refuses to start"):
        evidence_ui.create_app()


@pytest.mark.parametrize("environment", ["dev", "development", "local", "TEST"])
def test_opted_in_dev_app_has_no_cors_no_mount_and_no_log_writer(
    monkeypatch, environment
):
    monkeypatch.setenv(evidence_ui.DEV_SERVER_ENV_VAR, "1")
    monkeypatch.setenv("APP_ENV", environment)
    app = evidence_ui.create_app()

    assert app.user_middleware == []
    assert not any(type(route).__name__ == "Mount" for route in app.router.routes)
    exposed = {
        (route.path, method)
        for route in app.router.routes
        for method in getattr(route, "methods", set())
    }
    assert ("/api/scan-mem-log", "POST") not in exposed
    assert ("/api/scan-mem-log", "GET") in exposed
    assert not any(
        path.startswith("/frontend/") and path.endswith("app.py") for path, _ in exposed
    )


def test_dev_app_serves_one_asset_file_not_the_package_directory(monkeypatch):
    monkeypatch.setenv(evidence_ui.DEV_SERVER_ENV_VAR, "1")
    monkeypatch.setenv("APP_ENV", "dev")
    app = evidence_ui.create_app()
    asset_paths = {
        route.path for route in app.router.routes if route.path.startswith("/frontend")
    }
    assert asset_paths == {"/frontend/AutoAudit.png"}


# -------------------- the recent-scan page escapes what it renders --------------------


def test_scan_mem_page_escapes_a_stored_script_payload(scan_mem):
    evidence_ui._push_mem_log(XSS_PAYLOAD, XSS_PAYLOAD, "error")
    body = evidence_ui.scan_mem_page().body.decode("utf-8")
    assert XSS_PAYLOAD not in body
    assert body.count(ESCAPED_PAYLOAD) == 2


@pytest.mark.parametrize(
    ("payload", "escaped"),
    [
        ('" onmouseover="alert(1)', "&quot; onmouseover=&quot;alert(1)"),
        ("</td><td>injected", "&lt;/td&gt;&lt;td&gt;injected"),
        ("<img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;"),
        ("a&b", "a&amp;b"),
    ],
)
def test_scan_mem_page_escapes_quotes_and_markup(scan_mem, payload, escaped):
    evidence_ui._push_mem_log("user", payload, "success")
    body = evidence_ui.scan_mem_page().body.decode("utf-8")
    assert payload not in body
    assert escaped in body


def test_stored_log_entries_are_bounded_and_control_free(scan_mem):
    evidence_ui._push_mem_log("u\r\nInjected: line", "s" * 500, "not-a-status")
    entry = scan_mem[0]
    assert "\n" not in entry["user"] and "\r" not in entry["user"]
    assert len(entry["strategy"]) == 120
    assert entry["status"] == "error"


@pytest.mark.parametrize("field", ["ts", "user", "strategy", "status"])
def test_scan_mem_page_escapes_every_column_including_ts_and_status(scan_mem, field):
    """Bypass the log helper to prove the sink escapes all four cells, not two."""
    scan_mem.appendleft(
        {
            "ts": "t",
            "user": "u",
            "strategy": "s",
            "status": "success",
            field: XSS_PAYLOAD,
        }
    )
    body = evidence_ui.scan_mem_page().body.decode("utf-8")
    assert XSS_PAYLOAD not in body
    assert ESCAPED_PAYLOAD in body


def test_scan_mem_page_renders_a_placeholder_when_empty(scan_mem):
    body = evidence_ui.scan_mem_page().body.decode("utf-8")
    assert "No runs yet" in body


# -------------------- the unauthenticated write endpoint is gone --------------------


@pytest.mark.parametrize(
    "name", ["api_post_scan_mem_log", "post_scan_mem_log", "api_scan_mem_log_write"]
)
def test_scan_mem_write_handler_no_longer_exists(name):
    assert not hasattr(evidence_ui, name)


def test_module_source_defines_no_scan_mem_write_route():
    source = Path(evidence_ui.__file__).read_text(encoding="utf-8")
    assert 'post("/api/scan-mem-log"' not in source
    assert 'app.post("/api/scan-mem-log")' not in source


# -------------------- report download requires authorization --------------------


def test_download_report_cannot_be_called_with_a_bare_filename(reports_dir):
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")
    with pytest.raises(TypeError):
        evidence_ui.download_report("report.pdf")


def test_download_report_denies_when_the_authorizer_says_no(reports_dir):
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")
    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_report("report.pdf", authorize=lambda path: False)
    assert excinfo.value.status_code == 404


@pytest.mark.parametrize(
    "decision", ["false", "yes", 1, [1], {"allowed": False}, object(), None, 0]
)
def test_only_a_literal_true_authorizes(reports_dir, decision):
    """A truthy-but-not-True result is a mistake, not a grant."""
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")
    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_report("report.pdf", authorize=lambda path: decision)
    assert excinfo.value.status_code == 404


def test_an_async_authorizer_is_rejected_loudly_not_silently_granted(reports_dir):
    """An unawaited coroutine is truthy; it must never pass for authorization."""
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")

    async def authorize(path):  # pragma: no cover - body must never run
        return False

    with pytest.raises(TypeError, match="synchronous"):
        evidence_ui.download_report("report.pdf", authorize=authorize)


def test_download_report_serves_only_after_the_authorizer_agrees(reports_dir):
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")
    seen: list[Path] = []

    def authorize(path):
        seen.append(path)
        return True

    response = evidence_ui.download_report("report.pdf", authorize=authorize)
    assert seen == [(reports_dir / "report.pdf").resolve()]
    assert response.media_type == "application/pdf"


@pytest.mark.parametrize(
    "filename",
    [
        "",
        ".",
        "..",
        "../secret.pdf",
        "../../etc/passwd",
        "sub/report.pdf",
        "..\\..\\secret.pdf",
        "/etc/passwd",
        "/opt/reports/report.pdf",
        "report.pdf\x00.png",
    ],
)
def test_traversal_and_absolute_paths_are_rejected_before_authorization(
    reports_dir, filename
):
    def authorize(path):
        raise AssertionError("authorization must not be consulted for a bad name")

    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_report(filename, authorize=authorize)
    assert excinfo.value.status_code == 400


def test_symlink_escaping_the_reports_directory_is_rejected(reports_dir, tmp_path):
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.4")
    link = reports_dir / "escape.pdf"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not available here")

    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_report("escape.pdf", authorize=lambda path: True)
    assert excinfo.value.status_code == 400


def test_a_symlink_loop_is_a_400_not_an_unhandled_error(reports_dir):
    """`Path.resolve()` raises RuntimeError or OSError on a loop; neither may escape."""
    first = reports_dir / "loop-a.pdf"
    second = reports_dir / "loop-b.pdf"
    try:
        first.symlink_to(second)
        second.symlink_to(first)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not available here")

    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_report("loop-a.pdf", authorize=lambda path: True)
    assert excinfo.value.status_code == 400


def test_missing_report_is_a_404_not_an_authorization_bypass(reports_dir):
    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_report("absent.pdf", authorize=lambda path: True)
    assert excinfo.value.status_code == 404


@pytest.mark.parametrize("relative", ["report.pdf", "./report.pdf"])
def test_pre_authorized_download_requires_an_absolute_path(reports_dir, relative):
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")
    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_authorized_report(Path(relative))
    assert excinfo.value.status_code == 400


def test_pre_authorized_download_rejects_a_path_outside_the_reports_directory(
    reports_dir, tmp_path
):
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.4")
    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_authorized_report(outside)
    assert excinfo.value.status_code == 400


def test_pre_authorized_download_serves_an_absolute_in_directory_path(reports_dir):
    target = reports_dir / "report.docx"
    target.write_bytes(b"PK\x03\x04")
    response = evidence_ui.download_authorized_report(target)
    assert response.media_type.endswith("wordprocessingml.document")


def test_pre_authorized_download_rejects_a_nul_byte_instead_of_raising(reports_dir):
    """A malformed path is a 400, not an uncaught ValueError turning into a 500."""
    with pytest.raises(evidence_ui.HTTPException) as excinfo:
        evidence_ui.download_authorized_report(Path(f"{reports_dir}/rep\x00.pdf"))
    assert excinfo.value.status_code == 400


def test_download_serves_the_bytes_that_were_validated(reports_dir):
    body = b"%PDF-1.4 authorized report body"
    (reports_dir / "report.pdf").write_bytes(body)
    response = evidence_ui.download_report("report.pdf", authorize=lambda path: True)
    assert Path(response.path).read_bytes() == body
