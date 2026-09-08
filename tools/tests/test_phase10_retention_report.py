"""The retention report, against a real database and three server timezones.

The timezone parametrisation is the reason this module exists. Every retention
and expiry column in the Phase 7 schema is timezone-NAIVE UTC, and Phase 7's own
handoff records what a naive comparison against ``now()`` did to the dispatcher:
it judged every scan instantly past its deadline. The same mistake in a retention
pass does not merely mis-report -- when the deleting half is eventually approved,
it deletes evidence that has not expired.

CI runs PostgreSQL at UTC, which is exactly why the bug would never have shown up
there.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import subprocess  # nosec B404 # controlled Alembic subprocess against a disposable database
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend-api"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(ROOT / "tools"))

TIMEZONES = ["UTC", "Australia/Melbourne", "America/New_York"]


async def _exec(url, sql):
    connection = await asyncpg.connect(url)
    try:
        return await connection.execute(sql)
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
    name = "autoaudit_retention_test_" + uuid4().hex
    asyncio.run(_exec(admin_url, f'CREATE DATABASE "{name}"'))
    url = urlunsplit(parsed._replace(path="/" + name))
    try:
        _alembic(url)
        yield url
    finally:
        asyncio.run(_exec(admin_url, f'DROP DATABASE "{name}" WITH (FORCE)'))


def _alembic(url: str) -> None:
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 B607 # fixed interpreter and Alembic arguments
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _utc_literal(delta: timedelta) -> str:
    """A naive-UTC timestamp literal, written the way the application writes them.

    Deliberately computed in Python from an aware UTC clock and then rendered
    naive, so the fixture does not depend on the server's TimeZone setting. If
    the report's arithmetic were timezone-sloppy, these rows would be judged
    differently under each session timezone -- which is the whole point.
    """
    moment = datetime.now(timezone.utc).replace(tzinfo=None) + delta
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _seed(url: str) -> None:
    """Six artifacts spanning every combination the report has to separate.

    The near-boundary rows are the ones a timezone error moves: an artifact
    expiring in two hours would be judged expired on any server more than two
    hours off UTC.
    """
    expired = _utc_literal(timedelta(days=-2))
    just_expired = _utc_literal(timedelta(hours=-2))
    not_yet = _utc_literal(timedelta(hours=+2))

    def artifact(n, *, expires, held=False, status="available"):
        # ck_evidence_artifact_deleted_at: a tombstoned row must carry the
        # moment it was tombstoned. The schema enforces it, so the fixture has to
        # honour it rather than work around it.
        deleted_at = (
            f"'{_utc_literal(timedelta(days=-1))}'" if status == "deleted" else "NULL"
        )
        return (
            "INSERT INTO evidence_artifact (object_id, user_id, kind, storage_key,"
            " display_filename, media_type, byte_size, content_sha256,"
            " storage_backend, status, retention_policy_version,"
            " retention_expires_at, legal_hold, deleted_at) VALUES ("
            f"'{'a' * 42}{n}', 600, 'upload', 'key-{n}', 'fixture-{n}.txt',"
            f" 'text/plain', 10, '{'0' * 64}', 'local', '{status}', 'phase7-draft-1',"
            f" {'NULL' if expires is None else chr(39) + expires + chr(39)},"
            f" {str(held).lower()}, {deleted_at})"
        )

    statements = [
        'INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser,'
        " is_verified) VALUES (600, 'user', 'retention@example.invalid',"
        " 'synthetic-not-a-password', true, false, true)",
        # 1: long expired, not held -> eligible
        artifact(1, expires=expired),
        # 2: expired two hours ago, not held -> eligible (the boundary row)
        artifact(2, expires=just_expired),
        # 3: expired but UNDER LEGAL HOLD -> past expiry, NOT eligible
        artifact(3, expires=expired, held=True),
        # 4: expires in two hours -> not expired (the other boundary row)
        artifact(4, expires=not_yet),
        # 5: no expiry recorded at all
        artifact(5, expires=None),
        # 6: already tombstoned -> outside the live population entirely
        artifact(6, expires=expired, status="deleted"),
    ]
    asyncio.run(_exec(url, ";\n".join(statements)))


@pytest.fixture
def report(monkeypatch, database_url):
    from app.core.config import Settings

    module = importlib.import_module("ops.retention_report")

    def _run(timezone_name: str = "UTC"):
        # ALTER DATABASE, not SET TIME ZONE: a session-level setting dies with
        # the connection, and the report opens its own. This is also how a real
        # deployment's timezone is actually configured -- on the server or the
        # database, not per request.
        database = urlsplit(database_url).path.lstrip("/")
        asyncio.run(
            _exec(
                database_url,
                f"ALTER DATABASE \"{database}\" SET TimeZone TO '{timezone_name}'",
            )
        )
        settings = Settings(
            APP_ENV="dev",
            DATABASE_URL=database_url.replace(
                "postgresql://", "postgresql+asyncpg://", 1
            ),
            ENCRYPTION_KEY=Fernet.generate_key().decode(),
        )
        monkeypatch.setattr(module, "get_settings", lambda: settings)
        return asyncio.run(module.gather(settings))

    return _run


def test_the_report_deletes_nothing_and_says_so(report, database_url):
    _seed(database_url)
    result = report()
    assert result["mode"] == "report-only"
    assert result["deletes_anything"] is False
    # D04 must be named, so a reader cannot mistake the configured default for
    # an approved policy.
    assert "D04" in result["why"]
    assert result["configured_policy_version"] == "phase7-draft-1"


def test_counts_separate_expiry_from_legal_hold(report, database_url):
    _seed(database_url)
    counts = report()["evidence_artifacts"]["counts"]

    assert counts["total"] == 6
    assert counts["live"] == 5  # the tombstoned one is excluded
    assert counts["under_legal_hold"] == 1
    assert counts["past_expiry"] == 3  # rows 1, 2 and 3
    # Row 3 is expired but held. A hold outranks expiry, and conflating the two
    # is how a sweep deletes something a court told you to keep.
    assert counts["eligible"] == 2
    assert counts["no_expiry_recorded"] == 1


def test_nothing_is_deleted_by_running_the_report(report, database_url):
    _seed(database_url)
    report()
    remaining = asyncio.run(
        _count(database_url, "SELECT COUNT(*) FROM evidence_artifact")
    )
    assert remaining == 6


@pytest.mark.parametrize("server_timezone", TIMEZONES)
def test_expiry_is_computed_in_utc_whatever_the_server_timezone(
    report, database_url, server_timezone
):
    """The defect this module exists to prevent.

    The fixture puts one artifact two hours past expiry and one two hours short
    of it. On an Australia/Melbourne server a naive `now()` comparison is off by
    ten or eleven hours, so the not-yet-expired row would be judged eligible --
    and the deleting pass would destroy it.
    """
    _seed(database_url)
    result = report(server_timezone)
    counts = result["evidence_artifacts"]["counts"]

    assert result["database_server_timezone"] == server_timezone
    assert counts["past_expiry"] == 3, (server_timezone, counts)
    assert counts["eligible"] == 2, (server_timezone, counts)


async def _count(url, sql):
    connection = await asyncpg.connect(url)
    try:
        return await connection.fetchval(sql)
    finally:
        await connection.close()


def test_the_report_names_the_policy_versions_actually_in_use(report, database_url):
    """A retention claim is meaningless without the version it was made under."""
    _seed(database_url)
    versions = report()["evidence_artifacts"]["policy_versions"]
    assert versions == [{"version": "phase7-draft-1", "count": 6}]
