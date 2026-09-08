"""The key-rotation pass, exercised against a real PostgreSQL database.

A rotation that is only unit-tested is not evidence of anything: the whole risk
lives in the row lock, the resumability and the "which rows did it not touch"
accounting. These run against a disposable cluster with real rows.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import subprocess  # nosec B404 # controlled Alembic subprocess against a disposable database
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend-api"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(ROOT / "tools"))

PRIMARY = Fernet.generate_key().decode()
RETIRED = Fernet.generate_key().decode()
STRANGER = Fernet.generate_key().decode()


async def _run(url, sql, *, execute=False):
    connection = await asyncpg.connect(url)
    try:
        if execute:
            return await connection.execute(sql)
        return [dict(row) for row in await connection.fetch(sql)]
    finally:
        await connection.close()


@pytest.fixture
def database_url():
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    parsed = urlsplit(admin_url)
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "::1"}:
        pytest.fail("MIGRATION_TEST_ADMIN_URL must be a loopback postgresql:// URL")
    name = "autoaudit_rotation_test_" + uuid4().hex
    asyncio.run(_run(admin_url, f'CREATE DATABASE "{name}"', execute=True))
    url = urlunsplit(parsed._replace(path="/" + name))
    try:
        _alembic(url, "upgrade", "head")
        yield url
    finally:
        asyncio.run(
            _run(admin_url, f'DROP DATABASE "{name}" WITH (FORCE)', execute=True)
        )


def _alembic(url, *arguments):
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": PRIMARY,
    }
    result = subprocess.run(  # nosec B603 # fixed interpreter and Alembic arguments
        [sys.executable, "-m", "alembic", *arguments],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture
def rotate(monkeypatch, database_url):
    """The tool, bound to the disposable database and a chosen key ring."""
    from app.core.config import Settings
    from app.services import encryption

    module = importlib.import_module("ops.rotate_encryption_key")

    def _configure(primary: str, decrypt_only: str = ""):
        settings = Settings(
            APP_ENV="dev",
            DATABASE_URL=database_url.replace(
                "postgresql://", "postgresql+asyncpg://", 1
            ),
            ENCRYPTION_KEY=primary,
            ENCRYPTION_KEY_DECRYPT_ONLY=decrypt_only,
        )
        monkeypatch.setattr(encryption, "get_settings", lambda: settings)
        monkeypatch.setattr(module, "get_settings", lambda: settings)
        encryption.reset_key_ring()
        return module

    yield _configure
    encryption.reset_key_ring()


def _rotate(module, url: str, *, dry_run: bool) -> dict:
    async def _go():
        engine = create_async_engine(module.async_url(url))
        try:
            async with AsyncSession(engine) as session:
                return await module.rotate_connections(session, dry_run=dry_run)
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def _survey(module, url: str) -> dict:
    async def _go():
        engine = create_async_engine(module.async_url(url))
        try:
            async with AsyncSession(engine) as session:
                return await module.survey_evidence_excerpts(session)
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def _seed(url: str, secrets_by_key: list[tuple[str | None, str]]) -> list[int]:
    """Insert one connection per (key, plaintext); a None key stores empty text."""
    rows = []
    statements = [
        'INSERT INTO "user" (id, role, email, hashed_password, is_active,'
        " is_superuser, is_verified) VALUES (900, 'user',"
        " 'rotation@example.invalid', 'synthetic-not-a-password', true, false, true);"
    ]
    for index, (key, plaintext) in enumerate(secrets_by_key, start=1):
        ciphertext = (
            ""
            if key is None
            else Fernet(key.encode()).encrypt(plaintext.encode()).decode()
        )
        connection_id = 900 + index
        rows.append(connection_id)
        statements.append(
            "INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id,"
            f" encrypted_client_secret) VALUES ({connection_id}, 900, 'fixture-{index}',"
            f" 'synthetic-tenant', 'synthetic-client', '{ciphertext}');"
        )
    asyncio.run(_run(url, "\n".join(statements), execute=True))
    return rows


def _secrets(url: str) -> dict[int, str]:
    return {
        row["id"]: row["encrypted_client_secret"]
        for row in asyncio.run(
            _run(url, "SELECT id, encrypted_client_secret FROM m365_connection")
        )
    }


def _plaintext(key: str, ciphertext: str) -> str:
    return Fernet(key.encode()).decrypt(ciphertext.encode()).decode()


def test_a_retired_row_is_rewritten_under_the_primary_key(rotate, database_url):
    ids = _seed(database_url, [(RETIRED, "tenant-secret")])
    module = rotate(PRIMARY, RETIRED)

    report = _rotate(module, database_url, dry_run=False)

    assert report["rewritten"] == 1
    assert report["unreadable"] == 0
    # The plaintext survived, and only the primary key can read it now.
    stored = _secrets(database_url)[ids[0]]
    assert _plaintext(PRIMARY, stored) == "tenant-secret"


def test_a_row_already_under_the_primary_key_is_left_untouched(rotate, database_url):
    ids = _seed(database_url, [(PRIMARY, "already-current")])
    before = _secrets(database_url)[ids[0]]
    module = rotate(PRIMARY, RETIRED)

    report = _rotate(module, database_url, dry_run=False)

    assert report["already_current"] == 1
    assert report["rewritten"] == 0
    # Byte-identical: a no-op row is not re-encrypted, which is what makes the
    # pass resumable rather than merely repeatable.
    assert _secrets(database_url)[ids[0]] == before


def test_an_empty_secret_is_nothing_to_rotate(rotate, database_url):
    """The empty string means 'no secret held', not 'decryption failed'."""
    ids = _seed(database_url, [(None, "")])
    module = rotate(PRIMARY, RETIRED)

    report = _rotate(module, database_url, dry_run=False)

    assert report["empty"] == 1
    assert report["rewritten"] == 0
    assert report["unreadable"] == 0
    assert _secrets(database_url)[ids[0]] == ""


def test_a_row_no_key_can_read_is_reported_and_left_alone(rotate, database_url):
    ids = _seed(database_url, [(STRANGER, "orphaned")])
    before = _secrets(database_url)[ids[0]]
    module = rotate(PRIMARY, RETIRED)

    report = _rotate(module, database_url, dry_run=False)

    assert report["unreadable"] == 1
    assert report["unreadable_ids"] == ids
    # Never destroyed: an unreadable row may still be recoverable by restoring
    # the key that wrote it.
    assert _secrets(database_url)[ids[0]] == before


def test_check_mode_changes_nothing(rotate, database_url):
    ids = _seed(database_url, [(RETIRED, "tenant-secret")])
    before = _secrets(database_url)[ids[0]]
    module = rotate(PRIMARY, RETIRED)

    report = _rotate(module, database_url, dry_run=True)

    assert report["rewritten"] == 1  # would rewrite
    assert _secrets(database_url)[ids[0]] == before  # but did not


def test_a_second_pass_is_a_no_op(rotate, database_url):
    """Resumability: re-running after a completed pass rewrites nothing."""
    _seed(database_url, [(RETIRED, "a"), (RETIRED, "b"), (PRIMARY, "c")])
    module = rotate(PRIMARY, RETIRED)

    first = _rotate(module, database_url, dry_run=False)
    second = _rotate(module, database_url, dry_run=False)

    assert first["rewritten"] == 2 and first["already_current"] == 1
    assert second["rewritten"] == 0 and second["already_current"] == 3


def test_every_plaintext_survives_a_mixed_rotation(rotate, database_url):
    ids = _seed(
        database_url,
        [(RETIRED, "first"), (PRIMARY, "second"), (RETIRED, "third"), (None, "")],
    )
    module = rotate(PRIMARY, RETIRED)

    _rotate(module, database_url, dry_run=False)

    stored = _secrets(database_url)
    assert _plaintext(PRIMARY, stored[ids[0]]) == "first"
    assert _plaintext(PRIMARY, stored[ids[1]]) == "second"
    assert _plaintext(PRIMARY, stored[ids[2]]) == "third"
    assert stored[ids[3]] == ""


def test_the_row_is_locked_while_it_is_rewritten(rotate, database_url):
    """A concurrent tenant edit must not be silently reverted.

    The rotation reads, decrypts and writes; without FOR UPDATE an update
    landing between the read and the write would be overwritten by the value the
    rotation had already decrypted. This asserts the lock is actually taken, by
    observing that a second transaction cannot lock the same row.
    """
    ids = _seed(database_url, [(RETIRED, "tenant-secret")])
    module = rotate(PRIMARY, RETIRED)

    # First, the thing that can actually regress: the tool's own statement. The
    # contention check below is a property of PostgreSQL and would still pass if
    # FOR UPDATE were deleted from rotate_connections, so on its own it could
    # not fail. Found by the review pass.
    source = (ROOT / "tools" / "ops" / "rotate_encryption_key.py").read_text()
    # The statement is split across adjacent string literals in the source, so
    # collapse whitespace and quoting before matching.
    flattened = " ".join(source.replace('"', " ").split())
    assert "FROM m365_connection WHERE id = :id FOR UPDATE" in flattened, (
        "the rotation's SELECT must keep its row lock; without FOR UPDATE a "
        "concurrent tenant edit is silently reverted to the value the pass "
        "decrypted"
    )

    async def _contend():
        engine = create_async_engine(module.async_url(database_url))
        try:
            async with AsyncSession(engine) as holder:
                await holder.execute(
                    text("SELECT id FROM m365_connection WHERE id = :id FOR UPDATE"),
                    {"id": ids[0]},
                )
                async with AsyncSession(engine) as contender:
                    await contender.execute(text("SET LOCAL lock_timeout = '250ms'"))
                    with pytest.raises(Exception) as excinfo:
                        await contender.execute(
                            text(
                                "SELECT id FROM m365_connection WHERE id = :id FOR UPDATE"
                            ),
                            {"id": ids[0]},
                        )
                    assert "lock" in str(excinfo.value).lower()
                await holder.rollback()
        finally:
            await engine.dispose()

    asyncio.run(_contend())


def test_evidence_excerpts_are_surveyed_but_never_rewritten(rotate, database_url):
    """The excerpt column is deliberately out of scope; it must be counted, not touched."""
    _seed(database_url, [(PRIMARY, "unused")])
    legacy = Fernet(RETIRED.encode()).encrypt(b"legacy excerpt").decode()
    current = Fernet(PRIMARY.encode()).encrypt(b"current excerpt").decode()
    asyncio.run(
        _run(
            database_url,
            "INSERT INTO evidence_validation (user_id, strategy_name, source_filename,"
            " extracted_text_encrypted, matches_json) VALUES"
            f" (900, 'fixture', 'a.txt', '{legacy}', '{{}}'),"
            f" (900, 'fixture', 'b.txt', '{current}', '{{}}');",
            execute=True,
        )
    )
    module = rotate(PRIMARY, RETIRED)

    report = _survey(module, database_url)
    _rotate(module, database_url, dry_run=False)

    assert report["rotated"] is False
    assert report["total"] == 2
    # "not under the primary key" rather than "retired": a trial decryption
    # cannot distinguish a row under a retired key from one no key can read.
    assert report["not_under_the_primary_key"] == 1

    stored = {
        row["source_filename"]: row["extracted_text_encrypted"]
        for row in asyncio.run(
            _run(
                database_url,
                "SELECT source_filename, extracted_text_encrypted FROM evidence_validation",
            )
        )
    }
    assert stored["a.txt"] == legacy  # unchanged, not rewritten and not NULLed
    assert stored["b.txt"] == current


def test_check_is_not_blocked_by_unrotatable_evidence_excerpts(
    rotate, database_url, monkeypatch, capsys
):
    """--check must be able to return 0, or the documented procedure is unreachable.

    Found by the independent review pass. The tool's own step 3 is "run --check,
    and only once it reports nothing outstanding, drop the retired key". An
    earlier version also returned 1 whenever an evidence excerpt was still under
    a retired key -- but that column is deliberately never rotated, so the count
    can never reach zero once a single historical evidence row exists, and step 3
    became permanently unreachable.

    The excerpt count is a judgement input for the operator, not a gate.
    """
    _seed(database_url, [(PRIMARY, "already-current")])
    legacy = Fernet(RETIRED.encode()).encrypt(b"legacy excerpt").decode()
    asyncio.run(
        _run(
            database_url,
            "INSERT INTO evidence_validation (user_id, strategy_name, source_filename,"
            f" extracted_text_encrypted, matches_json) VALUES (900, 'f', 'a.txt', '{legacy}', '{{}}');",
            execute=True,
        )
    )
    module = rotate(PRIMARY, RETIRED)

    assert module.main(["--check"]) == 0
    # The count is still reported, so the decision is made with it in view.
    assert (
        "evidence excerpt(s) are written under a retired key" in capsys.readouterr().err
    )


def test_check_still_fails_when_a_connection_needs_rewriting(
    rotate, database_url, capsys
):
    """The gate that must keep biting: a row the rotation CAN clear."""
    _seed(database_url, [(RETIRED, "needs-rotating")])
    module = rotate(PRIMARY, RETIRED)

    assert module.main(["--check"]) == 1
    assert "still need rewriting" in capsys.readouterr().err


def test_check_fails_when_a_row_is_unreadable_by_any_key(rotate, database_url, capsys):
    _seed(database_url, [(STRANGER, "orphaned")])
    module = rotate(PRIMARY, RETIRED)

    assert module.main(["--check"]) == 1
    assert "no key in the ring can read" in capsys.readouterr().err
