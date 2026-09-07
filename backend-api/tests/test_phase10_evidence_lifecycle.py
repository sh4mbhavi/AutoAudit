"""Legal hold and the access log, exercised as endpoints rather than as columns.

Phase 7 built the ``legal_hold`` column, the delete refusal that reads it, and
the ``legal_hold_applied`` / ``legal_hold_released`` audit vocabulary. Phase 10
added the two endpoints that finally made the column reachable: a POST to place
or release a hold, and a GET that reads one artifact's access trail. Neither had
a test anywhere -- the delete refusal was covered, and the thing that sets the
flag it reads was not.

Two defects were live behind that gap and are covered here:

* **The lock was on the wrong side.** ``set_legal_hold`` took
  ``SELECT ... FOR UPDATE``; the delete path read the same row with a plain
  ``SELECT``, and in PostgreSQL a reader never waits for a row lock. Applying a
  hold and deleting the object were a check-then-act pair: the delete read
  ``legal_hold = false`` while the hold was in flight, the hold committed, and
  the bytes were removed anyway.

* **Separation of duties was documented and not implemented.** The endpoint's
  own docstring says "the owner cannot lift their own", which is what
  distinguishes a hold from ordinary retention. Nothing enforced it: an auditor
  or admin owns their own uploads, and could release a hold on them.

Like the Phase 7 evidence tests, these run against a disposable PostgreSQL
database, because the guarantees under test are row locks and a trigger-backed
append-only trail, neither of which exists in Python.
"""

import asyncio
import json
import os
import subprocess  # nosec B404 # controlled Alembic subprocess in a disposable database
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1 import evidence, scans
from app.core.config import Settings
from app.services import encryption

BACKEND = Path(__file__).resolve().parents[1]

OWNER_ID = 7401  # an auditor who is also the owner of the artifact
AUDITOR_ID = 7402  # an auditor who owns nothing here
VIEWER_ID = 7403  # an ordinary user

SEED_SQL = """
    INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
    VALUES (7401, 'auditor', 'owner-auditor@example.invalid', 'synthetic-not-a-password', true, false, true),
           (7402, 'auditor', 'other-auditor@example.invalid', 'synthetic-not-a-password', true, false, true),
           (7403, 'viewer', 'viewer@example.invalid', 'synthetic-not-a-password', true, false, true);
"""

for _name, _value in (
    ("OWNER_ID", OWNER_ID),
    ("AUDITOR_ID", AUDITOR_ID),
    ("VIEWER_ID", VIEWER_ID),
):
    if f"{_value}" not in SEED_SQL:
        raise AssertionError(f"{_name}={_value} is missing from SEED_SQL")

TEXT_EVIDENCE = b"Conditional access blocks legacy authentication for all users.\n"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
async def _query(url, sql, *, execute=False, parameters=()):
    connection = await asyncpg.connect(url)
    try:
        await connection.set_type_codec(
            "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
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
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    parsed = urlsplit(admin_url)
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "::1"}:
        pytest.fail("MIGRATION_TEST_ADMIN_URL must be a loopback postgresql:// URL")
    name = "autoaudit_phase10_lifecycle_" + uuid4().hex
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
        # A real key, because the excerpt the delete path has to purge only
        # exists if `_encrypt_excerpt` could encrypt it in the first place.
        ENCRYPTION_KEY=Fernet.generate_key().decode(),
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
    """A TestClient over the real router, with a switchable actor."""
    _sql(
        database_url,
        "TRUNCATE evidence_audit_event, evidence_artifact, evidence_validation "
        "RESTART IDENTITY CASCADE",
    )
    store = tmp_path / "evidence-store"
    settings = _settings(store)
    monkeypatch.setattr(evidence, "get_settings", lambda: settings)
    # encryption._load() reads the global settings and caches the key ring in
    # module state, so both have to be redirected for this test's key to be the
    # one the excerpt is encrypted under.
    monkeypatch.setattr(encryption, "get_settings", lambda: settings)
    monkeypatch.setattr(encryption, "_primary", None)
    monkeypatch.setattr(encryption, "_ring", None)

    engine = create_async_engine(
        database_url.replace("postgresql://", "postgresql+asyncpg://", 1),
        poolclass=NullPool,
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def session():
        async with maker() as opened:
            yield opened

    # A mutable holder so a test can change who is calling mid-scenario, which
    # is the whole point of a separation-of-duties check.
    actors = {
        "owner": SimpleNamespace(id=OWNER_ID, role="auditor"),
        "auditor": SimpleNamespace(id=AUDITOR_ID, role="auditor"),
        "viewer": SimpleNamespace(id=VIEWER_ID, role="viewer"),
    }
    current = {"actor": actors["owner"]}

    app = FastAPI()
    app.include_router(evidence.router)
    # Mounted so the scan-delete path can be exercised against the same rows:
    # deleting a scan is what severs evidence from the control it proves.
    app.include_router(scans.router)
    app.dependency_overrides[evidence.get_current_user] = lambda: current["actor"]
    app.dependency_overrides[evidence.get_async_session] = session

    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            actors=actors,
            become=lambda name: current.__setitem__("actor", actors[name]),
            settings=settings,
            store=store,
            url=database_url,
        )


def _upload(api, **linkage) -> str:
    response = api.client.post(
        "/evidence/uploads",
        files={"evidence": ("evidence.txt", TEXT_EVIDENCE, "text/plain")},
        data={key: str(value) for key, value in linkage.items()},
    )
    assert response.status_code == 201, response.text
    return response.json()["object_id"]


def _hold(api, object_id, *, hold: bool, reason: str = "litigation hold 2026-09"):
    return api.client.post(
        f"/evidence/artifacts/{object_id}/legal-hold",
        json={"hold": hold, "reason": reason},
    )


def _actions(api, object_id) -> list[str]:
    rows = _rows(
        api.url,
        "SELECT action, outcome FROM evidence_audit_event "
        "WHERE artifact_object_id = $1 ORDER BY id",
        object_id,
    )
    return [f"{row['action']}/{row['outcome']}" for row in rows]


# ---------------------------------------------------------------------------
# the endpoints do what Phase 7 built the column for
# ---------------------------------------------------------------------------
def test_a_hold_blocks_the_delete_that_reads_it(api):
    object_id = _upload(api)

    api.become("auditor")
    placed = _hold(api, object_id, hold=True)
    assert placed.status_code == 200, placed.text
    assert placed.json()["legal_hold"] is True

    api.become("owner")
    refused = api.client.delete(f"/evidence/artifacts/{object_id}")
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "evidence_legal_hold"

    stored = _rows(
        api.url,
        "SELECT status, legal_hold FROM evidence_artifact WHERE object_id = $1",
        object_id,
    )
    assert stored[0]["status"] != "deleted"
    assert stored[0]["legal_hold"] is True
    assert "legal_hold_applied/allowed" in _actions(api, object_id)
    assert "rejected/denied" in _actions(api, object_id)


def test_releasing_a_hold_restores_the_delete(api):
    object_id = _upload(api)
    api.become("auditor")
    assert _hold(api, object_id, hold=True).status_code == 200
    released = _hold(api, object_id, hold=False, reason="matter closed")
    assert released.status_code == 200
    assert released.json()["legal_hold"] is False

    api.become("owner")
    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204
    assert "legal_hold_released/allowed" in _actions(api, object_id)


def test_the_owner_cannot_release_a_hold_on_their_own_evidence(api):
    """The claim the endpoint's docstring has made since Phase 10.

    `require_auditor_or_above` keeps an ordinary viewer out, but an auditor or
    admin owns their own uploads, so without this the person the hold exists to
    restrain could lift it.
    """
    object_id = _upload(api)
    api.become("auditor")
    assert _hold(api, object_id, hold=True).status_code == 200

    api.become("owner")
    refused = _hold(api, object_id, hold=False, reason="I would like it gone")
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "evidence_legal_hold_self_release"

    still_held = _rows(
        api.url,
        "SELECT legal_hold FROM evidence_artifact WHERE object_id = $1",
        object_id,
    )
    assert still_held[0]["legal_hold"] is True
    assert "rejected/denied" in _actions(api, object_id)

    # And the delete it was protecting against is still refused.
    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 409


def test_the_owner_may_still_place_a_hold_on_their_own_evidence(api):
    """Adding an obligation to yourself is not the act separation of duties forbids."""
    object_id = _upload(api)
    api.become("owner")
    placed = _hold(api, object_id, hold=True)
    assert placed.status_code == 200
    assert placed.json()["legal_hold"] is True


def test_a_viewer_can_neither_hold_nor_read_the_trail(api):
    object_id = _upload(api)
    api.become("viewer")
    assert _hold(api, object_id, hold=True).status_code == 403
    assert (
        api.client.get(f"/evidence/artifacts/{object_id}/audit-events").status_code
        == 403
    )


def test_the_access_log_is_readable_and_records_its_own_reader(api):
    object_id = _upload(api)
    api.become("auditor")
    assert _hold(api, object_id, hold=True).status_code == 200

    response = api.client.get(f"/evidence/artifacts/{object_id}/audit-events")
    assert response.status_code == 200, response.text
    body = response.json()
    actions = [event["action"] for event in body["items"]]
    assert "created" in actions
    assert "legal_hold_applied" in actions

    # Reading the trail is itself an access decision and is recorded in it.
    again = api.client.get(f"/evidence/artifacts/{object_id}/audit-events")
    assert again.status_code == 200
    assert "audit_read" in [event["action"] for event in again.json()["items"]]


def test_the_access_log_refuses_an_object_that_never_existed(api):
    api.become("auditor")
    response = api.client.get("/evidence/artifacts/" + "0" * 43 + "/audit-events")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# the race
# ---------------------------------------------------------------------------
def test_a_delete_waits_for_an_in_flight_hold(api):
    """The check-then-act pair that a lock on only one side cannot close.

    A hold is applied in another transaction and not yet committed. The delete
    must block on that row rather than read the stale `legal_hold = false` and
    destroy the bytes; when the hold commits, the delete must see it and refuse.
    """
    object_id = _upload(api)
    stored = _rows(
        api.url,
        "SELECT storage_key FROM evidence_artifact WHERE object_id = $1",
        object_id,
    )
    storage_key = stored[0]["storage_key"]
    assert (api.store / storage_key).exists()

    holder_ready = threading.Event()
    release_holder = threading.Event()
    holder_error: list[BaseException] = []

    async def hold_the_row():
        connection = await asyncpg.connect(api.url)
        try:
            transaction = connection.transaction()
            await transaction.start()
            await connection.fetchval(
                "SELECT id FROM evidence_artifact WHERE object_id = $1 FOR UPDATE",
                object_id,
            )
            await connection.execute(
                "UPDATE evidence_artifact SET legal_hold = true WHERE object_id = $1",
                object_id,
            )
            holder_ready.set()
            await asyncio.get_running_loop().run_in_executor(
                None, release_holder.wait, 30
            )
            await transaction.commit()
        finally:
            await connection.close()

    def run_holder():
        try:
            asyncio.run(hold_the_row())
        except BaseException as error:  # noqa: BLE001 - surfaced by the assertion below
            holder_error.append(error)
            holder_ready.set()

    holder = threading.Thread(target=run_holder, daemon=True)
    holder.start()
    assert holder_ready.wait(20), "the holding transaction never started"
    assert not holder_error, holder_error

    api.become("owner")
    outcome: list[int] = []

    def run_delete():
        outcome.append(
            api.client.delete(f"/evidence/artifacts/{object_id}").status_code
        )

    deleter = threading.Thread(target=run_delete, daemon=True)
    deleter.start()

    # It must still be waiting. Before the fix it read the uncommitted row's
    # stale value, saw no hold, and had already removed the bytes by now.
    time.sleep(1.5)
    assert deleter.is_alive(), (
        "the delete did not wait for the in-flight hold; it read the row without "
        "a lock"
    )
    assert (api.store / storage_key).exists(), "the bytes were removed while a "
    "hold was being applied"

    release_holder.set()
    holder.join(timeout=30)
    deleter.join(timeout=30)
    assert not holder_error, holder_error
    assert outcome == [409], outcome
    assert (api.store / storage_key).exists()


# ---------------------------------------------------------------------------
# what a delete leaves behind
# ---------------------------------------------------------------------------
def _validations(api):
    return _rows(
        api.url,
        "SELECT id, extracted_text_encrypted, text_hash, matches_json "
        "FROM evidence_validation ORDER BY id",
    )


def test_deleting_an_artifact_purges_its_stored_excerpt(api):
    """The excerpt is the evidence; the validator's findings are the assessment.

    `/evidence/scan` writes an encrypted copy of the extracted text into
    evidence_validation and links it from artifact.provenance. Deleting the
    object used to leave that copy behind -- a decryptable excerpt of evidence
    the tenant was told had been deleted, with nothing pointing at it.
    """
    strategies = api.client.get("/evidence/strategies")
    assert strategies.status_code == 200, strategies.text
    listed = strategies.json()
    entries = listed["strategies"] if isinstance(listed, dict) else listed
    names = [entry["name"] if isinstance(entry, dict) else entry for entry in entries]
    if not names:
        pytest.skip("no evidence strategy is registered in this environment")

    response = api.client.post(
        "/evidence/scan",
        files={"evidence": ("policy.txt", TEXT_EVIDENCE, "text/plain")},
        data={"strategy_name": names[0]},
    )
    assert response.status_code == 200, response.text
    object_id = response.json()["object_id"]

    before = _validations(api)
    assert before, "the scan wrote no validation row"
    assert before[0]["extracted_text_encrypted"] is not None

    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204

    after = _validations(api)
    assert len(after) == len(before), "the validation row itself must survive"
    assert after[0]["extracted_text_encrypted"] is None
    # The finding is the assessment and is retained deliberately.
    assert after[0]["text_hash"] == before[0]["text_hash"]
    assert after[0]["matches_json"] == before[0]["matches_json"]

    events = _rows(
        api.url,
        "SELECT action, detail FROM evidence_audit_event "
        "WHERE artifact_object_id = $1 AND action = 'deleted'",
        object_id,
    )
    assert events and events[0]["detail"]["excerpt_purged"] is True


# ---------------------------------------------------------------------------
# deleting a scan
# ---------------------------------------------------------------------------
def _seed_scan(api, scan_id: int = 7501) -> int:
    _sql(
        api.url,
        "INSERT INTO scan (id, user_id, framework, benchmark, version) "
        "VALUES ($1, $2, 'CIS', 'M365', '1.0')",
        scan_id,
        OWNER_ID,
    )
    return scan_id


def test_deleting_a_scan_is_refused_while_its_evidence_is_bound(api):
    """Two Phase 7 mechanisms disagreed, and callers got a 500.

    `evidence_artifact.scan_id` is ON DELETE SET NULL, so the FK wants to sever
    the link; `phase7_artifact_identity_immutable` freezes `scan_id` on every
    UPDATE, so the severing raises and the delete aborts with an unhandled
    IntegrityError. The trigger is right -- evidence that proved 1.1.1 for a
    scan must not become evidence that proved 1.1.1 for no scan -- so the
    refusal is explicit and says what to do instead.
    """
    scan_id = _seed_scan(api)
    object_id = _upload(api, scan_id=scan_id, control_id="1.1.1")

    api.become("owner")
    refused = api.client.delete(f"/scans/{scan_id}")
    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == "evidence_still_linked"
    assert detail["linked_artifacts"] == 1
    assert detail["held_artifacts"] == 0

    assert _rows(api.url, "SELECT id FROM scan WHERE id = $1", scan_id)
    events = _rows(
        api.url,
        "SELECT action, detail FROM evidence_audit_event "
        "WHERE artifact_object_id = $1 AND action = 'rejected'",
        object_id,
    )
    assert events, "the refusal was not recorded against the evidence"
    assert events[0]["detail"]["operation"] == "delete_scan"

    # Deleting the evidence first is the documented way through.
    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204
    still_bound = api.client.delete(f"/scans/{scan_id}")
    assert (
        still_bound.status_code == 409
    ), "a tombstoned artifact still carries the binding the trigger protects"


def test_deleting_a_scan_with_no_evidence_still_works(api):
    scan_id = _seed_scan(api, 7503)
    api.become("owner")
    assert api.client.delete(f"/scans/{scan_id}").status_code == 204
    assert not _rows(api.url, "SELECT id FROM scan WHERE id = $1", scan_id)


def test_deleting_a_scan_is_refused_while_its_evidence_is_held(api):
    """A hold has to survive the owner deleting the scan, not only the object."""
    scan_id = _seed_scan(api, 7502)
    object_id = _upload(api, scan_id=scan_id, control_id="1.1.1")

    api.become("auditor")
    assert _hold(api, object_id, hold=True).status_code == 200

    api.become("owner")
    refused = api.client.delete(f"/scans/{scan_id}")
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "evidence_legal_hold"
    assert refused.json()["detail"]["held_artifacts"] == 1

    still_there = _rows(api.url, "SELECT id FROM scan WHERE id = $1", scan_id)
    assert still_there, "the scan was deleted despite a hold on its evidence"
    linked = _rows(
        api.url,
        "SELECT scan_id FROM evidence_artifact WHERE object_id = $1",
        object_id,
    )
    assert linked[0]["scan_id"] == scan_id


# ---------------------------------------------------------------------------
# an approved bundle's attachments
# ---------------------------------------------------------------------------
def _approved_record_with(api, object_id: str, *, status: str = "approved") -> int:
    """Seed a manual evidence record and one revision holding this attachment."""
    scan_id = _seed_scan(api, 7601 if status == "approved" else 7605)
    _sql(
        api.url,
        "INSERT INTO scan_result (id, scan_id, control_id, status) "
        "VALUES ($2, $1, '1.1.1', 'pending')",
        scan_id,
        scan_id + 1000,
    )
    _sql(
        api.url,
        "INSERT INTO manual_evidence_record "
        "(id, scan_result_id, scan_id, control_id, user_id, evidence_source, "
        " status, reviewer_user_id, reviewed_at, retention_policy_version, "
        " current_revision_number, created_at, updated_at) "
        "VALUES ($4, $5, $1, '1.1.1', $2, 'manual', $3, $6, $7, 'v1', 1, "
        "        now(), now())",
        scan_id,
        OWNER_ID,
        status,
        scan_id + 2000,
        scan_id + 1000,
        # ck_manual_evidence_record_reviewed_by: an approval needs a reviewer,
        # and ck_manual_evidence_record_independent_reviewer says it cannot be
        # the submitter.
        AUDITOR_ID if status == "approved" else None,
        datetime.now(timezone.utc).replace(tzinfo=None)
        if status == "approved"
        else None,
    )
    _sql(
        api.url,
        "INSERT INTO manual_evidence_revision "
        "(id, record_id, revision_number, action, status_after, actor_user_id, "
        " actor_role, attachment_object_ids) "
        "VALUES ($4, $5, 1, $6, $1, $2, 'auditor', $3::jsonb)",
        status,
        AUDITOR_ID,
        [object_id],
        scan_id + 3000,
        scan_id + 2000,
        "approved" if status == "approved" else "created",
    )
    return scan_id + 2000


def test_an_approved_bundles_attachment_cannot_be_deleted_by_its_submitter(api):
    """The approval binds the submitter; nothing enforced that.

    An approved revision carries `evidence_sha256` over exactly its attachment
    set, so a later reader can prove the approved bundle is the bundle that was
    reviewed. Deleting an attachment makes that digest unverifiable, and the
    submitter -- the only party this route authorises -- is the party the
    approval exists to bind.
    """
    object_id = _upload(api)
    _approved_record_with(api, object_id)

    # Assert the fixture landed as a JSONB *array*. A pre-serialised string
    # stored a JSONB string instead, and every substring assertion still passed
    # while the guard under test matched nothing.
    seeded = _rows(
        api.url,
        "SELECT r.status, v.attachment_object_ids FROM manual_evidence_record r "
        "JOIN manual_evidence_revision v ON v.record_id = r.id",
    )
    assert seeded and seeded[0]["status"] == "approved", seeded
    assert seeded[0]["attachment_object_ids"] == [object_id], seeded

    api.become("owner")
    refused = api.client.delete(f"/evidence/artifacts/{object_id}")
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["code"] == "evidence_attached_to_approved_record"

    stored = _rows(
        api.url,
        "SELECT status FROM evidence_artifact WHERE object_id = $1",
        object_id,
    )
    assert stored[0]["status"] != "deleted"
    events = _rows(
        api.url,
        "SELECT detail FROM evidence_audit_event "
        "WHERE artifact_object_id = $1 AND action = 'rejected'",
        object_id,
    )
    assert events
    assert events[0]["detail"]["code"] == "evidence_attached_to_approved_record"


def test_a_draft_bundles_attachment_may_still_be_deleted(api):
    """Only an approval freezes the set. A draft is still the submitter's."""
    object_id = _upload(api)
    _approved_record_with(api, object_id, status="draft")

    api.become("owner")
    assert api.client.delete(f"/evidence/artifacts/{object_id}").status_code == 204
