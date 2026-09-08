"""Phase 7 evidence: ownership, bounds and the append-only audit trail.

These tests are written to fail if AUTH-01, AUTH-02 or EVI-01 come back. The
API-level cases run against a disposable PostgreSQL database because the
guarantees under test (the ownership predicate, the status/deleted_at CHECK and
the append-only trigger) live in the database, not in Python.
"""

import asyncio
import io
import json
import os
import struct
import subprocess  # nosec B404 # controlled Alembic subprocess in a disposable database
import sys
import time
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1 import evidence
from app.core.config import Settings
from app.services import evidence_audit, evidence_processing, evidence_storage
from app.services.evidence_processing import EvidenceRejected
from app.services.evidence_storage import (
    LocalFilesystemStorage,
    EvidenceStorageKeyError,
    EvidenceTooLargeError,
    build_storage_key,
    new_object_id,
)

BACKEND = Path(__file__).resolve().parents[1]

OWNER_ID = 7101
INTRUDER_ID = 7102
OWNER_SCAN_ID = 7201
INTRUDER_SCAN_ID = 7202
OWNER_RESULT_ID = 7301
INTRUDER_RESULT_ID = 7302

# Written with literal ids and no interpolation at all. The constants above are
# what the tests assert against; the assertion below keeps the two in step, so
# there is no string building for a scanner (or a reader) to mistake for a
# SQL-injection sink.
SEED_SQL = """
    INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
    VALUES (7101, 'user', 'owner@example.invalid', 'synthetic-not-a-password', true, false, true),
           (7102, 'user', 'intruder@example.invalid', 'synthetic-not-a-password', true, false, true);
    INSERT INTO scan (id, user_id, framework, benchmark, version)
    VALUES (7201, 7101, 'CIS', 'M365', '1.0'),
           (7202, 7102, 'CIS', 'M365', '1.0');
    INSERT INTO scan_result (id, scan_id, control_id, status)
    VALUES (7301, 7201, '1.1.1', 'pending'),
           (7302, 7202, '1.1.1', 'pending');
"""

# Fails loudly if a constant is renumbered without updating the seed script.
for _name, _value in (
    ("OWNER_ID", OWNER_ID),
    ("INTRUDER_ID", INTRUDER_ID),
    ("OWNER_SCAN_ID", OWNER_SCAN_ID),
    ("INTRUDER_SCAN_ID", INTRUDER_SCAN_ID),
    ("OWNER_RESULT_ID", OWNER_RESULT_ID),
    ("INTRUDER_RESULT_ID", INTRUDER_RESULT_ID),
):
    if f"{_value}" not in SEED_SQL:
        raise AssertionError(f"{_name}={_value} is missing from SEED_SQL")

TEXT_EVIDENCE = (
    b"MFA is enforced for all admins. Conditional access blocks legacy "
    b"authentication. Audit log retention is enabled.\n"
)


# ---------------------------------------------------------------------------
# fixtures: a disposable database, built exactly like tests/test_migrations.py
# ---------------------------------------------------------------------------
async def _query(url, sql, *, execute=False, parameters=()):
    connection = await asyncpg.connect(url)
    try:
        await connection.set_type_codec(
            "jsonb",
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )
        if execute:
            return await connection.execute(sql, *parameters)
        return [dict(row) for row in await connection.fetch(sql, *parameters)]
    finally:
        await connection.close()


def _sql(url, sql, *parameters):
    return asyncio.run(_query(url, sql, execute=True, parameters=parameters))


def _rows(url, sql, *parameters):
    return asyncio.run(_query(url, sql, parameters=parameters))


def _alembic(url, *arguments):
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 # fixed interpreter and Alembic arguments from this test
        [sys.executable, "-m", "alembic", *arguments],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture(scope="module")
def database_url():
    """Create, migrate and seed a throwaway database; never touch anything else."""
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    parsed = urlsplit(admin_url)
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "::1"}:
        pytest.fail("MIGRATION_TEST_ADMIN_URL must be a loopback postgresql:// URL")
    name = "autoaudit_phase7_evidence_" + uuid4().hex
    _sql(admin_url, f'CREATE DATABASE "{name}"')
    url = urlunsplit(parsed._replace(path="/" + name))
    try:
        _alembic(url, "upgrade", "head")
        _sql(url, SEED_SQL)
        yield url
    finally:
        _sql(admin_url, f'DROP DATABASE "{name}" WITH (FORCE)')


def _settings(store: Path) -> Settings:
    return Settings(
        _env_file=None,
        APP_ENV="dev",
        EVIDENCE_STORAGE_BACKEND="local",
        EVIDENCE_STORAGE_DIR=str(store),
        EVIDENCE_MAX_UPLOAD_BYTES=1024 * 1024,
        EVIDENCE_READ_CHUNK_BYTES=4096,
        EVIDENCE_MAX_PDF_PAGES=3,
        EVIDENCE_MAX_IMAGE_PIXELS=1_000_000,
        EVIDENCE_MAX_ARCHIVE_ENTRIES=32,
        EVIDENCE_MAX_ARCHIVE_RATIO=100,
        EVIDENCE_MAX_EXTRACTED_CHARS=100_000,
        EVIDENCE_PROCESSING_TIMEOUT_SECONDS=30,
    )


@pytest.fixture
def api(database_url, tmp_path, monkeypatch):
    """A TestClient over the real router, a real session and a real store."""
    _sql(
        database_url,
        "TRUNCATE evidence_audit_event, evidence_artifact, evidence_validation "
        "RESTART IDENTITY CASCADE",
    )
    store = tmp_path / "evidence-store"
    settings = _settings(store)
    monkeypatch.setattr(evidence, "get_settings", lambda: settings)

    engine = create_async_engine(
        database_url.replace("postgresql://", "postgresql+asyncpg://", 1),
        poolclass=NullPool,
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def session():
        async with maker() as opened:
            yield opened

    actor = SimpleNamespace(id=OWNER_ID)
    app = FastAPI()
    app.include_router(evidence.router)
    app.dependency_overrides[evidence.get_current_user] = lambda: actor
    app.dependency_overrides[evidence.get_async_session] = session

    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            actor=actor,
            settings=settings,
            store=store,
            url=database_url,
        )


# ---------------------------------------------------------------------------
# fixture content builders
# ---------------------------------------------------------------------------
def _png(width: int, height: int) -> bytes:
    """A structurally valid PNG whose IHDR declares the given dimensions."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00" * 16))
        + chunk(b"IEND", b"")
    )


def _real_png() -> bytes:
    """A decodable PNG, unlike the header-only fixture used for the pixel cap."""
    image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image.new("L", (8, 8), color=255).save(buffer, format="PNG")
    return buffer.getvalue()


def _pdf(pages: int) -> bytes:
    fitz = pytest.importorskip("fitz")
    document = fitz.open()
    for _ in range(pages):
        document.new_page()
    data = document.tobytes()
    document.close()
    return data


def _docx(text: str) -> bytes:
    docx = pytest.importorskip("docx")
    document = docx.Document()
    document.add_paragraph(text)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def _docx_bomb() -> bytes:
    """A real .docx container whose uncompressed size dwarfs its own bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "A" * (4 * 1024 * 1024))
    return buffer.getvalue()


def _upload(api, content: bytes, filename: str, **form):
    return api.client.post(
        "/evidence/uploads",
        files={"evidence": (filename, content, "application/octet-stream")},
        data={key: str(value) for key, value in form.items()},
    )


def _multipart(payload: bytes, filename: str = "huge.txt") -> bytes:
    """A hand-built multipart body, so the test controls the framing."""
    boundary = b"--phase7boundary"
    return (
        boundary
        + b'\r\nContent-Disposition: form-data; name="evidence"; filename="'
        + filename.encode()
        + b'"\r\nContent-Type: text/plain\r\n\r\n'
        + payload
        + b"\r\n"
        + boundary
        + b"--\r\n"
    )


def _artifacts(url, object_id=None):
    if object_id is None:
        return _rows(url, "SELECT * FROM evidence_artifact ORDER BY id")
    return _rows(url, "SELECT * FROM evidence_artifact WHERE object_id = $1", object_id)


def _events(url, object_id=None):
    if object_id is None:
        return _rows(url, "SELECT * FROM evidence_audit_event ORDER BY id")
    return _rows(
        url,
        "SELECT * FROM evidence_audit_event WHERE artifact_object_id = $1 ORDER BY id",
        object_id,
    )


def _stored_files(store: Path) -> list[Path]:
    if not store.exists():
        return []
    return [path for path in store.rglob("*") if path.is_file()]


# ---------------------------------------------------------------------------
# AUTH-02: no evidence route is reachable without a session
# ---------------------------------------------------------------------------
def _dependency_calls(dependant) -> set:
    calls = set()
    for dependency in dependant.dependencies:
        if dependency.call is not None:
            calls.add(dependency.call)
        calls |= _dependency_calls(dependency)
    return calls


def test_every_route_declares_the_authentication_dependency():
    """Structural, so a route added later cannot regress to anonymous access."""
    routes = [route for route in evidence.router.routes if isinstance(route, APIRoute)]
    assert routes, "the evidence router must expose routes"
    for route in routes:
        assert evidence.get_current_user in _dependency_calls(
            route.dependant
        ), route.path


def test_every_route_answers_401_without_a_session():
    """The runtime half of the same claim, exercised through the router."""
    app = FastAPI()
    app.include_router(evidence.router)
    client = TestClient(app)
    probe = "A" * 43
    checked = 0
    for route in evidence.router.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path.replace("{object_id}", probe)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            response = client.request(method, path)
            assert response.status_code == 401, (method, path, response.status_code)
            checked += 1
    assert checked >= 9


def test_no_route_lets_fastapi_parse_the_body_before_authentication():
    """The ingress ceiling depends on this.

    FastAPI parses a declared body *before* it solves dependencies, so a route
    that declares ``UploadFile = File(...)`` spools the whole file to disk
    before the session check or the byte ceiling can refuse it. These routes
    must therefore declare no body field at all and parse the stream themselves.
    """
    for route in evidence.router.routes:
        if not isinstance(route, APIRoute):
            continue
        assert route.body_field is None, route.path
        assert route.dependant.body_params == [], route.path


@pytest.mark.parametrize(
    "path",
    [
        "/evidence/scan-mem",
        "/evidence/scan-mem-log",
        "/evidence/recent-scans",
        "/evidence/scan-log",
    ],
)
def test_cross_tenant_debug_routes_are_gone(path):
    assert path not in {route.path for route in evidence.router.routes}


def test_health_answers_a_boolean_and_leaks_no_paths(api):
    response = api.client.get("/evidence/health")
    assert response.status_code == 200
    assert response.json() == {"ready": True}


# ---------------------------------------------------------------------------
# AUTH-01: authorization is by owned object id, never by filename
# ---------------------------------------------------------------------------
def test_a_second_user_cannot_read_download_or_delete_another_tenants_artifact(api):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    assert created.status_code == 201, created.text
    object_id = created.json()["object_id"]

    # Same session, different principal: exactly the AUTH-01 scenario.
    api.actor.id = INTRUDER_ID
    for method, path in (
        ("GET", f"/evidence/artifacts/{object_id}"),
        ("GET", f"/evidence/artifacts/{object_id}/content"),
        ("GET", f"/evidence/reports/{object_id}"),
        ("DELETE", f"/evidence/artifacts/{object_id}"),
    ):
        response = api.client.request(method, path)
        # 404, never 403: a 403 would confirm the object exists elsewhere.
        assert response.status_code == 404, (path, response.text)
        assert response.json()["detail"]["code"] == "evidence_not_found"

    api.actor.id = OWNER_ID
    assert api.client.get(f"/evidence/artifacts/{object_id}").status_code == 200
    assert _artifacts(api.url, object_id)[0]["status"] == "available"


def test_denied_download_is_audited_against_the_intruder(api):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    object_id = created.json()["object_id"]

    api.actor.id = INTRUDER_ID
    assert api.client.get(f"/evidence/artifacts/{object_id}/content").status_code == 404

    denied = [
        event
        for event in _events(api.url, object_id)
        if event["outcome"] == "denied" and event["action"] == "rejected"
    ]
    assert len(denied) == 1
    assert denied[0]["actor_user_id"] == INTRUDER_ID


def test_a_foreign_parent_scan_is_404_not_an_existence_oracle(api):
    refused = _upload(api, TEXT_EVIDENCE, "policy.txt", scan_id=INTRUDER_SCAN_ID)
    assert refused.status_code == 404
    assert not _artifacts(api.url)

    refused_result = _upload(
        api, TEXT_EVIDENCE, "policy.txt", scan_result_id=INTRUDER_RESULT_ID
    )
    assert refused_result.status_code == 404

    accepted = _upload(
        api,
        TEXT_EVIDENCE,
        "policy.txt",
        scan_result_id=OWNER_RESULT_ID,
        control_id="1.1.1",
    )
    assert accepted.status_code == 201
    row = _artifacts(api.url, accepted.json()["object_id"])[0]
    assert row["scan_id"] == OWNER_SCAN_ID
    assert row["scan_result_id"] == OWNER_RESULT_ID
    assert row["control_id"] == "1.1.1"


def test_download_is_an_inert_attachment(api):
    created = _upload(api, b"<svg onload=alert(1)></svg>\n", "payload.txt")
    assert created.json()["status"] == "available"
    object_id = created.json()["object_id"]
    response = api.client.get(f"/evidence/artifacts/{object_id}/content")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.content == b"<svg onload=alert(1)></svg>\n"


# ---------------------------------------------------------------------------
# EVI-01: storage keys
# ---------------------------------------------------------------------------
def test_storage_keys_are_unguessable_and_carry_no_filename(api):
    created = _upload(api, TEXT_EVIDENCE, "Q3 quarterly-secret-plan.txt")
    object_id = created.json()["object_id"]
    row = _artifacts(api.url, object_id)[0]

    assert row["storage_key"] == f"{OWNER_ID}/{object_id[:2]}/{object_id}"
    for fragment in ("quarterly", "secret", "plan", ".txt", " "):
        assert fragment not in row["storage_key"]
    assert row["display_filename"] == "Q3 quarterly-secret-plan.txt"
    assert len({new_object_id() for _ in range(200)}) == 200


@pytest.mark.parametrize(
    "key",
    [
        "../etc/passwd",
        "/etc/passwd",
        "7101/ab/../../../etc/passwd",
        "7101//" + "A" * 43,
        "7101\\ab\\" + "A" * 43,
        "C:/store/" + "A" * 43,
        "7101/ab/" + "A" * 43 + "\x00",
        "",
    ],
)
def test_traversal_and_absolute_keys_are_refused(tmp_path, key):
    storage = LocalFilesystemStorage(tmp_path)
    with pytest.raises(EvidenceStorageKeyError):
        storage.resolve(key)


def test_symlinked_directory_cannot_smuggle_a_key_out_of_the_store(tmp_path):
    store = tmp_path / "store"
    outside = tmp_path / "outside"
    (store / str(OWNER_ID)).mkdir(parents=True)
    outside.mkdir()
    (store / str(OWNER_ID) / "ab").symlink_to(outside, target_is_directory=True)

    storage = LocalFilesystemStorage(store)
    with pytest.raises(EvidenceStorageKeyError):
        storage.resolve(f"{OWNER_ID}/ab/" + "A" * 43)


def test_a_key_cannot_be_built_from_anything_but_ownership_and_entropy():
    with pytest.raises(EvidenceStorageKeyError):
        build_storage_key(0, new_object_id())
    with pytest.raises(EvidenceStorageKeyError):
        build_storage_key(OWNER_ID, "../evidence")
    with pytest.raises(EvidenceStorageKeyError):
        build_storage_key(OWNER_ID, "short")


# ---------------------------------------------------------------------------
# EVI-01: the byte ceiling stops the stream instead of buffering it
# ---------------------------------------------------------------------------
def test_the_ceiling_stops_the_stream_before_the_body_is_buffered(tmp_path):
    storage = LocalFilesystemStorage(tmp_path / "store")
    key = build_storage_key(OWNER_ID, new_object_id())
    produced = []

    async def chunks():
        for index in range(1000):
            produced.append(index)
            yield b"x" * 1024

    with pytest.raises(EvidenceTooLargeError):
        asyncio.run(storage.put(key, chunks(), max_bytes=4096))

    # The generator was abandoned at the ceiling rather than drained.
    assert len(produced) <= 6
    assert _stored_files(tmp_path / "store") == []


def test_an_oversized_upload_is_refused_and_leaves_nothing_behind(api):
    api.settings.EVIDENCE_MAX_UPLOAD_BYTES = 1024
    response = _upload(api, b"x" * 200_000, "huge.txt")

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "evidence_too_large"
    assert _artifacts(api.url) == []
    assert _stored_files(api.store) == []
    rejected = _events(api.url)
    assert [event["action"] for event in rejected] == ["rejected"]
    assert rejected[0]["detail"]["code"] == "evidence_too_large"


# ---------------------------------------------------------------------------
# EVI-01: the content decides the type, not the extension
# ---------------------------------------------------------------------------
def test_an_extension_that_lies_about_the_content_is_rejected_and_recorded(api):
    response = _upload(api, _docx("hello"), "screenshot.png")

    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "evidence_type_mismatch"

    rows = _artifacts(api.url)
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert rows[0]["failure_code"] == "evidence_type_mismatch"
    # Recorded, not coerced, and the refused bytes are not retained.
    assert _stored_files(api.store) == []
    assert [event["action"] for event in _events(api.url)] == ["rejected"]


@pytest.mark.parametrize(
    "content,filename,code",
    [
        (b"MZ\x90\x00binary", "tool.exe", "evidence_unsupported_type"),
        (b"\x7fELF\x02\x01\x01", "notes.txt", "evidence_unsupported_type"),
        (b"", "empty.txt", "evidence_empty"),
    ],
)
def test_unsupported_content_is_refused(api, content, filename, code):
    response = _upload(api, content, filename)
    assert response.status_code in {415, 422}
    assert response.json()["detail"]["code"] == code


def test_sniffing_ignores_the_extension_entirely():
    settings = _settings(Path("/nonexistent-store-never-touched"))
    assert (
        evidence_processing.sniff_media_type(_png(4, 4), settings)
        == evidence_processing.MEDIA_PNG
    )
    assert (
        evidence_processing.sniff_media_type(_pdf(1), settings)
        == evidence_processing.MEDIA_PDF
    )
    assert (
        evidence_processing.sniff_media_type(_docx("x"), settings)
        == evidence_processing.MEDIA_DOCX
    )
    assert (
        evidence_processing.sniff_media_type(b"plain text\n", settings)
        == evidence_processing.MEDIA_TEXT
    )
    # A bare zip that is not a real .docx is not silently accepted.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("payload.bin", "x")
    with pytest.raises(EvidenceRejected) as rejected:
        evidence_processing.sniff_media_type(buffer.getvalue(), settings)
    assert rejected.value.code == "evidence_unsupported_type"


# ---------------------------------------------------------------------------
# EVI-01: every extraction bound fails closed with its own code
# ---------------------------------------------------------------------------
def _extract(data: bytes, media_type: str, settings: Settings):
    return evidence_processing.extract_sync(
        data, media_type, settings, time.monotonic() + 30
    )


def test_the_pdf_page_cap_rejects_with_its_own_code(tmp_path):
    settings = _settings(tmp_path)
    assert _extract(_pdf(3), evidence_processing.MEDIA_PDF, settings).page_count == 3
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(_pdf(4), evidence_processing.MEDIA_PDF, settings)
    assert rejected.value.code == "evidence_page_limit"
    assert rejected.value.limit == 3


def test_the_image_pixel_cap_rejects_with_its_own_code(tmp_path):
    settings = _settings(tmp_path)
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(_png(4000, 4000), evidence_processing.MEDIA_PNG, settings)
    assert rejected.value.code == "evidence_pixel_limit"


def test_the_docx_archive_ratio_rejects_with_its_own_code(tmp_path):
    settings = _settings(tmp_path)
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(_docx_bomb(), evidence_processing.MEDIA_DOCX, settings)
    assert rejected.value.code == "evidence_archive_bomb"


def test_the_archive_entry_cap_rejects_before_anything_is_decompressed(tmp_path):
    settings = _settings(tmp_path)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        for index in range(settings.EVIDENCE_MAX_ARCHIVE_ENTRIES + 1):
            archive.writestr(f"word/media/{index}.bin", "x")
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(buffer.getvalue(), evidence_processing.MEDIA_DOCX, settings)
    assert rejected.value.code == "evidence_archive_bomb"


def test_extraction_never_truncates_silently(tmp_path):
    settings = _settings(tmp_path)
    settings.EVIDENCE_MAX_EXTRACTED_CHARS = 1000
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(b"a" * 5000, evidence_processing.MEDIA_TEXT, settings)
    assert rejected.value.code == "evidence_extract_limit"


def test_a_timeout_stops_the_request_promptly_with_a_redacted_code():
    """The request must not wait for a slow parser to finish."""

    def slow():
        time.sleep(5)
        return "never used"

    started = time.monotonic()
    with pytest.raises(EvidenceRejected) as rejected:
        asyncio.run(evidence_processing._run_bounded(slow, timeout=0.05))
    elapsed = time.monotonic() - started

    assert rejected.value.code == "evidence_timeout"
    # Only the code, never a parser message or a traceback.
    assert str(rejected.value) == "evidence_timeout"
    assert elapsed < 2, elapsed


@pytest.mark.parametrize("builder", ["text", "pdf", "docx", "png"])
def test_extraction_writes_nothing_at_all(tmp_path, builder):
    """The claim that an abandoned worker leaves no trace rests on this.

    A Python thread cannot be killed, so the guarantee is not that a timed-out
    extraction stops instantly; it is that extraction never writes, so whatever
    an abandoned thread finishes doing cannot land anywhere.
    """
    store = tmp_path / "store"
    store.mkdir()
    settings = _settings(store)
    payloads = {
        "text": (TEXT_EVIDENCE, evidence_processing.MEDIA_TEXT),
        "pdf": (_pdf(1), evidence_processing.MEDIA_PDF),
        "docx": (_docx("hello"), evidence_processing.MEDIA_DOCX),
        "png": (_real_png(), evidence_processing.MEDIA_PNG),
    }
    data, media_type = payloads[builder]
    try:
        _extract(data, media_type, settings)
    except EvidenceRejected as rejected:
        # An absent OCR engine is a fail-closed code, not a write.
        assert rejected.code in {
            "evidence_ocr_unavailable",
            "evidence_engine_unavailable",
        }, rejected.code
    assert _stored_files(store) == []
    assert list(store.iterdir()) == []


def test_a_parser_fault_becomes_a_code_not_a_traceback(tmp_path, monkeypatch):
    settings = _settings(tmp_path)

    def explode(*_arguments):
        raise MemoryError("internal detail that must not reach a caller")

    monkeypatch.setattr(evidence_processing, "extract_sync", explode)
    with pytest.raises(EvidenceRejected) as rejected:
        asyncio.run(
            evidence_processing.extract_text_bounded(
                b"x", media_type=evidence_processing.MEDIA_TEXT, settings=settings
            )
        )
    assert rejected.value.code == "evidence_unreadable"
    assert "internal detail" not in str(rejected.value)


def test_a_timeout_reaches_the_api_as_a_code_without_a_traceback(api, monkeypatch):
    async def timed_out(*_arguments, **_keywords):
        raise EvidenceRejected(evidence_processing.FAILURE_TIMEOUT, limit=30)

    monkeypatch.setattr(evidence_processing, "extract_text_bounded", timed_out)
    response = api.client.post(
        "/evidence/scan",
        files={"evidence": ("policy.txt", TEXT_EVIDENCE, "text/plain")},
        data={"strategy_name": _strategy_name()},
    )
    assert response.status_code == 504
    assert response.json()["detail"]["code"] == "evidence_timeout"
    assert "Traceback" not in response.text

    row = _artifacts(api.url)[0]
    assert row["status"] == "failed"
    assert row["failure_code"] == "evidence_timeout"
    assert "processing_failed" in {event["action"] for event in _events(api.url)}


# ---------------------------------------------------------------------------
# the scan path: bounded, single extraction, owned report
# ---------------------------------------------------------------------------
def _strategy_name() -> str:
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    strategies = pytest.importorskip("security.strategies").load_strategies()
    for strategy in strategies:
        name = getattr(strategy, "name", None)
        if name:
            return name
    pytest.skip("no evidence strategy is registered in this environment")


def test_the_scan_path_extracts_exactly_once_and_stores_an_owned_report(
    api, monkeypatch
):
    calls = []
    original = evidence_processing.extract_sync

    def counted(*arguments):
        calls.append(arguments[1])
        return original(*arguments)

    monkeypatch.setattr(evidence_processing, "extract_sync", counted)

    response = api.client.post(
        "/evidence/scan",
        files={"evidence": ("policy.txt", TEXT_EVIDENCE, "text/plain")},
        data={"strategy_name": _strategy_name()},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["ok"] is True
    # The legacy double extraction is the defect; exactly one is the fix.
    assert calls == [evidence_processing.MEDIA_TEXT]

    upload_row = _artifacts(api.url, payload["object_id"])[0]
    assert upload_row["status"] == "available"
    assert upload_row["kind"] == "upload"

    validations = _rows(api.url, "SELECT * FROM evidence_validation")
    assert len(validations) == 1
    assert upload_row["provenance"] is not None

    for report_id in payload["reports"]:
        report = _artifacts(api.url, report_id)[0]
        assert report["kind"] == "report"
        assert report["user_id"] == OWNER_ID
        download = api.client.get(f"/evidence/reports/{report_id}")
        assert download.status_code == 200
        api.actor.id = INTRUDER_ID
        assert api.client.get(f"/evidence/reports/{report_id}").status_code == 404
        api.actor.id = OWNER_ID


def test_an_unknown_strategy_is_refused_before_anything_is_stored(api):
    response = api.client.post(
        "/evidence/scan",
        files={"evidence": ("policy.txt", TEXT_EVIDENCE, "text/plain")},
        data={"strategy_name": "not-a-registered-strategy"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unknown_strategy"
    assert _artifacts(api.url) == []
    assert _stored_files(api.store) == []


# ---------------------------------------------------------------------------
# deletion, retention and the append-only trail
# ---------------------------------------------------------------------------
def test_delete_soft_deletes_the_row_removes_the_bytes_and_is_audited(api):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    object_id = created.json()["object_id"]
    assert len(_stored_files(api.store)) == 1

    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204

    row = _artifacts(api.url, object_id)[0]
    assert row["status"] == "deleted"
    assert row["deleted_at"] is not None
    assert _stored_files(api.store) == []
    assert "deleted" in {event["action"] for event in _events(api.url, object_id)}

    # The tombstone is not downloadable, and the refusal is audited too.
    assert api.client.get(f"/evidence/artifacts/{object_id}/content").status_code == 404
    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204


def test_a_legal_hold_refuses_deletion_and_keeps_the_bytes(api):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    object_id = created.json()["object_id"]
    _sql(
        api.url,
        "UPDATE evidence_artifact SET legal_hold=true WHERE object_id=$1",
        object_id,
    )

    response = api.client.delete(f"/evidence/artifacts/{object_id}")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "evidence_legal_hold"
    assert _artifacts(api.url, object_id)[0]["status"] == "available"
    assert len(_stored_files(api.store)) == 1


def test_the_lifecycle_writes_created_downloaded_denied_and_deleted_events(api):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    object_id = created.json()["object_id"]
    assert api.client.get(f"/evidence/artifacts/{object_id}/content").status_code == 200
    api.actor.id = INTRUDER_ID
    assert api.client.get(f"/evidence/artifacts/{object_id}/content").status_code == 404
    api.actor.id = OWNER_ID
    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204

    events = _events(api.url, object_id)
    recorded = [(event["action"], event["outcome"]) for event in events]
    assert ("created", "allowed") in recorded
    assert ("downloaded", "allowed") in recorded
    assert ("rejected", "denied") in recorded
    assert ("deleted", "allowed") in recorded
    for event in events:
        assert "policy.txt" not in str(event["detail"])


def test_audit_rows_reject_update_and_delete(api):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    object_id = created.json()["object_id"]
    event = _events(api.url, object_id)[0]

    with pytest.raises(asyncpg.PostgresError):
        _sql(
            api.url,
            "UPDATE evidence_audit_event SET outcome='allowed' WHERE id=$1",
            event["id"],
        )
    with pytest.raises(asyncpg.PostgresError):
        _sql(api.url, "DELETE FROM evidence_audit_event WHERE id=$1", event["id"])
    assert _events(api.url, object_id)[0] == event


def test_listing_returns_only_the_callers_own_artifacts(api):
    mine = _upload(api, TEXT_EVIDENCE, "mine.txt").json()["object_id"]
    api.actor.id = INTRUDER_ID
    theirs = _upload(api, TEXT_EVIDENCE, "theirs.txt").json()["object_id"]

    api.actor.id = OWNER_ID
    listed = api.client.get("/evidence/artifacts").json()
    ids = {item["object_id"] for item in listed["items"]}
    assert mine in ids
    assert theirs not in ids
    assert all("storage_key" not in item for item in listed["items"])


# ---------------------------------------------------------------------------
# the audit detail is redacted before it is ever written
# ---------------------------------------------------------------------------
def test_audit_detail_keeps_only_redacted_scalars():
    detail = evidence_audit.redact_detail(
        {
            "code": "evidence_too_large",
            "byte_size": 42,
            "nested": {
                "secret": "value"  # pragma: allowlist secret - synthetic redaction fixture
            },
            "Bad-Key": "dropped",
            "control": "line\nbreak",
            "items": ["a", {"b": 1}, 2],
            "ratio": float("inf"),
        }
    )
    assert detail == {
        "code": "evidence_too_large",
        "byte_size": 42,
        "control": "line break",
        "items": ["a", 2],
    }


def test_audit_events_require_a_known_action_and_a_real_object_id():
    with pytest.raises(ValueError):
        evidence_audit.build_event(
            artifact=new_object_id(),
            actor=None,
            action="exfiltrate",
            outcome="allowed",
        )
    with pytest.raises(ValueError):
        evidence_audit.build_event(
            artifact="../not-an-object-id",
            actor=None,
            action="downloaded",
            outcome="allowed",
        )


# ---------------------------------------------------------------------------
# the matcher must never read the server's own evidence directory
# ---------------------------------------------------------------------------
class _FolderModeStrategy:
    """Mimics the registered strategies that switch mode on ``source_file``.

    ``PatchApplicationsML1`` and ``PatchOperatingSystemsML1`` behave exactly like
    this: an empty ``source_file`` makes them walk a server-side evidence
    directory instead of the upload. They are not always importable, so the
    behaviour is pinned here rather than left to whatever happens to register.
    """

    name = "Fixture Folder Mode"
    EVIDENCE_DIR = "/srv/autoaudit/security/evidence"

    def emit_hits(self, text, source_file="", **_keywords):
        if not source_file:
            return [
                {
                    "test_id": "folder-mode",
                    "evidence": {
                        "source_file": "another-tenant.txt",
                        "absolute_path": "/srv/autoaudit/security/evidence/other.txt",
                    },
                }
            ]
        return [{"test_id": "single-file", "evidence": {"source_file": source_file}}]


def test_the_matcher_stays_in_single_file_mode_and_leaks_no_server_paths():
    """Passing an empty source_file would return another tenant's evidence."""
    findings = evidence._match_findings(
        _FolderModeStrategy(), "winget upgrade output", "policy.txt"
    )
    assert findings == [
        {"test_id": "single-file", "evidence": {"source_file": "policy.txt"}}
    ]


def test_every_registered_strategy_is_driven_from_the_upload_only():
    strategies = pytest.importorskip("security.strategies").load_strategies()
    assert strategies, "no evidence strategy is registered in this environment"
    for strategy in strategies:
        findings = evidence._match_findings(
            strategy, "winget upgrade\nNo installed package found", "policy.txt"
        )
        payload = json.dumps(findings, default=str)
        assert "absolute_path" not in payload
        assert str(BACKEND.parent) not in payload


def test_a_scan_response_never_carries_a_server_path(api):
    response = api.client.post(
        "/evidence/scan",
        files={"evidence": ("policy.txt", TEXT_EVIDENCE, "text/plain")},
        data={"strategy_name": _strategy_name()},
    )
    assert response.status_code == 200, response.text
    body = response.text
    assert str(BACKEND.parent) not in body
    assert "absolute_path" not in body


def test_server_paths_are_stripped_from_a_legacy_finding():
    finding = {
        "test_id": "t1",
        "evidence": {
            "source_file": "policy.txt",
            "absolute_path": "/srv/autoaudit/security/evidence/other-tenant.txt",
            "full_path": "/srv/elsewhere",
            "pending_count": 2,
        },
    }
    cleaned = evidence._strip_server_paths(finding)
    assert cleaned["evidence"] == {"source_file": "policy.txt", "pending_count": 2}


# ---------------------------------------------------------------------------
# bounds the review of the first cut exposed
# ---------------------------------------------------------------------------
def test_a_multi_frame_image_is_refused_rather_than_partly_read(tmp_path):
    """Reading frame zero and reporting success would score unexamined pages."""
    image = pytest.importorskip("PIL.Image")
    settings = _settings(tmp_path)
    buffer = io.BytesIO()
    first = image.new("L", (8, 8), color=1)
    second = image.new("L", (8, 8), color=2)
    first.save(buffer, format="TIFF", save_all=True, append_images=[second])
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(buffer.getvalue(), evidence_processing.MEDIA_TIFF, settings)
    assert rejected.value.code == "evidence_page_limit"


def test_the_archive_guard_has_an_absolute_expansion_ceiling(tmp_path):
    """A ratio alone is not a memory bound: 25 MB at ratio 120 is 3 GB."""
    settings = _settings(tmp_path)
    settings.EVIDENCE_MAX_ARCHIVE_RATIO = 10_000
    settings.EVIDENCE_PROCESSING_MEMORY_MB = 1
    with pytest.raises(EvidenceRejected) as rejected:
        _extract(_docx_bomb(), evidence_processing.MEDIA_DOCX, settings)
    assert rejected.value.code == "evidence_archive_bomb"


def test_a_report_is_refused_rather_than_silently_shortened():
    findings = [{"test_id": str(index)} for index in range(500)]
    with pytest.raises(EvidenceRejected) as rejected:
        evidence._render_report("Fixture", findings)
    assert rejected.value.code == "evidence_extract_limit"

    small = evidence._render_report("Fixture", [{"test_id": "only"}])
    assert b"Findings: 1" in small
    assert b"only" in small


def test_a_refused_byte_removal_never_records_a_completed_deletion(api, monkeypatch):
    created = _upload(api, TEXT_EVIDENCE, "policy.txt")
    object_id = created.json()["object_id"]

    async def refuse(self, key):
        raise evidence_storage.EvidenceStorageError("filesystem refused")

    monkeypatch.setattr(
        evidence_storage.LocalFilesystemStorage, "delete", refuse, raising=True
    )
    response = api.client.delete(f"/evidence/artifacts/{object_id}")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "evidence_delete_failed"

    row = _artifacts(api.url, object_id)[0]
    # No tombstone, so the deletion stays retryable and is not claimed.
    assert row["status"] == "available"
    assert row["deleted_at"] is None
    assert len(_stored_files(api.store)) == 1
    assert "deleted" not in {event["action"] for event in _events(api.url, object_id)}


def test_a_body_that_understates_its_size_is_still_refused(api):
    """The Content-Length probe is a shortcut, not the control.

    This body is small enough to pass the cheap header check and still carries a
    file part far over the ceiling, so the refusal has to come from the parser
    itself, part by part, rather than after the whole file has been spooled.
    """
    api.settings.EVIDENCE_MAX_UPLOAD_BYTES = 1024
    body = _multipart(b"x" * 60_000)
    assert len(body) < 1024 + evidence._MULTIPART_OVERHEAD_BYTES

    response = api.client.post(
        "/evidence/uploads",
        headers={"Content-Type": "multipart/form-data; boundary=phase7boundary"},
        content=body,
    )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "evidence_too_large"
    assert _artifacts(api.url) == []
    assert _stored_files(api.store) == []
    assert [event["action"] for event in _events(api.url)] == ["rejected"]


def test_a_stored_object_is_never_left_behind_when_the_row_fails(api, monkeypatch):
    async def fail(*_arguments, **_keywords):
        raise RuntimeError("synthetic database failure")

    monkeypatch.setattr(evidence.evidence_audit, "record_event", fail)
    response = _upload(api, TEXT_EVIDENCE, "policy.txt")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "evidence_not_recorded"
    assert _artifacts(api.url) == []
    assert _stored_files(api.store) == []


def test_an_unimplemented_storage_backend_fails_loudly(tmp_path):
    settings = _settings(tmp_path)
    settings.EVIDENCE_STORAGE_BACKEND = "s3"
    with pytest.raises(evidence_storage.EvidenceStorageError) as error:
        evidence_storage.get_storage(settings)
    assert "D04" in str(error.value)
