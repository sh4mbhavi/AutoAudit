"""Migration graph regression and optional disposable PostgreSQL integration tests."""

import asyncio
import json
import os
import subprocess  # nosec B404 # controlled Alembic subprocess in disposable database tests
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from cryptography.fernet import Fernet

BACKEND = Path(__file__).resolve().parents[1]
PRIOR_HEADS = (
    "ccf7645372fc",  # pragma: allowlist secret - revision ID
    "d87c3bb49953",  # pragma: allowlist secret - revision ID
)
MERGED_HEAD = "2899a0e678b6"  # pragma: allowlist secret - revision ID


def test_migration_graph_has_one_head():
    """Normal `alembic upgrade head` must resolve without branch selection."""
    scripts = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini")))
    assert len(scripts.get_heads()) == 1, scripts.get_heads()


async def _query(url, sql, *, execute=False):
    connection = await asyncpg.connect(url)
    try:
        if execute:
            return await connection.execute(sql)
        return [dict(row) for row in await connection.fetch(sql)]
    finally:
        await connection.close()


@pytest.fixture
def database_url():
    """Create a fresh database; never migrate the configured admin database."""
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    parsed = urlsplit(admin_url)
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "::1"}:
        pytest.fail("MIGRATION_TEST_ADMIN_URL must be a loopback postgresql:// URL")
    database_name = "autoaudit_migration_test_" + uuid4().hex
    asyncio.run(_query(admin_url, f'CREATE DATABASE "{database_name}"', execute=True))
    try:
        yield urlunsplit(parsed._replace(path="/" + database_name))
    finally:
        asyncio.run(
            _query(
                admin_url, f'DROP DATABASE "{database_name}" WITH (FORCE)', execute=True
            )
        )


def _alembic(url, *arguments):
    environment = {
        **os.environ,
        "APP_ENV": "test",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 # fixed interpreter and Alembic arguments from these tests
        [sys.executable, "-m", "alembic", *arguments],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _versions(url):
    return {
        row["version_num"]
        for row in asyncio.run(_query(url, "SELECT version_num FROM alembic_version"))
    }


def _seed(url, initial_heads):
    """Synthetic linked account, scan, evidence, settings and branch-specific data."""
    sql = """
        INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
        VALUES (101, 'user', 'migration@example.invalid', 'synthetic-not-a-password', true, false, true);
        INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
        VALUES (201, 101, 'Migration fixture', 'synthetic-tenant', 'synthetic-client', 'synthetic-ciphertext');
        INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version, notes)
        VALUES (301, 101, 201, 'CIS', 'M365', '1.0', 'Preserve scan notes');
        INSERT INTO scan_result (id, scan_id, control_id, status, message, evidence)
        VALUES (401, 301, '1.1.1', 'passed', 'Preserve result', '{"fixture": true, "items": [1, 2]}');
        INSERT INTO oauth_account (id, oauth_name, access_token, refresh_token, account_id, account_email, user_id)
        VALUES (501, 'google', repeat('synthetic-', 200), 'synthetic-refresh', 'fixture-account', 'migration@example.invalid', 101);
        INSERT INTO evidence_validation (user_id, strategy_name, source_filename, extracted_text_encrypted, matches_json)
        VALUES (101, 'fixture', 'fixture.txt', 'synthetic-ciphertext', '{"preserved": true}');
        INSERT INTO user_settings (user_id, confirm_delete_enabled) VALUES (101, false);
        INSERT INTO contact_submissions (id, first_name, last_name, email, subject, message, assigned_to, ip_address)
        VALUES ('00000000-0000-4000-8000-000000000001', 'Migration', 'Fixture', 'migration@example.invalid', 'Support', 'Preserve contact', 101, '127.0.0.1');
        INSERT INTO submission_notes (id, submission_id, admin_user_id, note)
        VALUES ('00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000001', 101, 'Preserve note');
        INSERT INTO submission_history (id, submission_id, admin_user_id, action)
        VALUES ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000001', 101, 'created');
    """
    if PRIOR_HEADS[0] in initial_heads:
        sql += """
            INSERT INTO manual_scan_result_detail (scan_result_id, user_id, comment)
            VALUES (401, 101, 'Preserve manual verification');
        """
    if PRIOR_HEADS[1] in initial_heads:
        sql += """
            UPDATE "user" SET first_name='Migration', last_name='Fixture', organization_name='Fixture Org'
            WHERE id=101;
        """
    asyncio.run(_query(url, sql, execute=True))


async def _snapshot(url):
    connection = await asyncpg.connect(url)
    try:
        tables = await connection.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename != 'alembic_version' ORDER BY tablename"
        )
        data = {}
        for table in tables:
            name = table["tablename"]
            quoted = '"' + name.replace('"', '""') + '"'
            rows = await connection.fetch(
                f"SELECT row_to_json(t)::text AS row FROM {quoted} t ORDER BY id"  # nosec B608 # catalog identifier escaped above
            )
            data[name] = [json.loads(row["row"]) for row in rows]
        return data
    finally:
        await connection.close()


def _assert_preserved(before, after):
    for table, original_rows in before.items():
        assert table in after
        assert len(after[table]) == len(original_rows), table
        for original, current in zip(original_rows, after[table]):
            assert {key: current[key] for key in original} == original, table


@pytest.mark.parametrize("starting_point", ["base", *PRIOR_HEADS, "both"])
def test_upgrade_to_phase1_merge_preserves_existing_data(database_url, starting_point):
    initial_heads = PRIOR_HEADS if starting_point == "both" else (starting_point,)
    before = {}
    if starting_point != "base":
        for revision in initial_heads:
            _alembic(database_url, "upgrade", revision)
        assert _versions(database_url) == set(initial_heads)
        _seed(database_url, initial_heads)
        before = asyncio.run(_snapshot(database_url))

    _alembic(database_url, "upgrade", MERGED_HEAD)
    assert _versions(database_url) == {MERGED_HEAD}
    after = asyncio.run(_snapshot(database_url))
    assert "manual_scan_result_detail" in after
    columns = asyncio.run(
        _query(
            database_url,
            "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='user'",
        )
    )
    assert {"first_name", "last_name", "organization_name"} <= {
        row["column_name"] for row in columns
    }
    _assert_preserved(before, after)
    if starting_point == "both":
        assert before == after

    # Re-running normal startup migrations is idempotent.
    _alembic(database_url, "upgrade", MERGED_HEAD)
    assert _versions(database_url) == {MERGED_HEAD}
    assert asyncio.run(_snapshot(database_url)) == after

    if starting_point == "both":
        # Revert only the no-op merge, leaving both deployed branches intact.
        _alembic(database_url, "downgrade", PRIOR_HEADS[0])
        assert _versions(database_url) == set(PRIOR_HEADS)
        assert asyncio.run(_snapshot(database_url)) == before
        _alembic(database_url, "upgrade", MERGED_HEAD)
        assert _versions(database_url) == {MERGED_HEAD}
        assert asyncio.run(_snapshot(database_url)) == before
