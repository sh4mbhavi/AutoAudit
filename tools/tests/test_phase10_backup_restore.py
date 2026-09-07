"""A real backup and a real restore, against a real PostgreSQL server.

The Phase 10 anti-pattern guard says it plainly: do not conflate backup
existence with a tested restore. So this module does not assert that
``backup.py`` can be imported -- it dumps a populated database, drops it,
restores into a fresh one, and asserts the rows and the evidence bytes came
back.

Everything here runs against a disposable loopback cluster and deletes it
afterwards.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 # controlled Alembic subprocess against a disposable database
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend-api"
sys.path.insert(0, str(ROOT / "tools"))

pytestmark = pytest.mark.skipif(
    shutil.which("pg_dump") is None or shutil.which("pg_restore") is None,
    reason="pg_dump/pg_restore are required",
)


@pytest.fixture
def backup_module():
    from ops import backup

    return backup


def _psql(url: str, sql: str) -> str:
    result = subprocess.run(  # nosec B603 B607 # fixed psql invocation, loopback URL
        ["psql", url, "-tAc", sql],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def admin_url():
    url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    if "@127.0.0.1:" not in url:
        pytest.fail("Only loopback test databases are allowed")
    return url


def _create_database(admin_url: str, name: str) -> str:
    _psql(admin_url, f'CREATE DATABASE "{name}"')
    return urlunsplit(urlsplit(admin_url)._replace(path="/" + name))


def _drop_database(admin_url: str, name: str) -> None:
    _psql(admin_url, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _alembic(url: str) -> None:
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 B607 # fixed uv/Alembic arguments
        ["uv", "run", "--project", str(BACKEND), "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


SEED = """
    INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
    VALUES (800, 'user', 'backup@example.invalid', 'synthetic-not-a-password', true, false, true);
    INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
    VALUES (800, 800, 'backup fixture', 'synthetic-tenant', 'synthetic-client', '');
    INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version, status, notes)
    VALUES (800, 800, 800, 'CIS', 'M365', '6.0.0', 'completed', 'preserve this note');
    INSERT INTO scan_result (id, scan_id, control_id, status, selected, message)
    VALUES (810, 800, '1.1.1', 'passed', true, 'preserve this result'),
           (811, 800, '1.2.1', 'failed', true, 'preserve this failure');
"""


@pytest.fixture
def populated(admin_url, tmp_path):
    """A migrated, populated database plus an evidence store with real bytes."""
    name = "autoaudit_backup_src_" + uuid4().hex
    url = _create_database(admin_url, name)
    try:
        _alembic(url)
        _psql(url, SEED.replace("\n", " "))
        evidence = tmp_path / "evidence-store"
        evidence.mkdir()
        (evidence / "artifact-one.bin").write_bytes(b"synthetic evidence object\n")
        nested = evidence / "reports"
        nested.mkdir()
        (nested / "report.pdf").write_bytes(b"%PDF-1.4 synthetic\n")
        yield url, evidence
    finally:
        _drop_database(admin_url, name)


def test_a_backup_records_a_verifiable_manifest(backup_module, populated, tmp_path):
    url, evidence = populated
    into = tmp_path / "backup"

    manifest = backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at="2026-09-07T00:00:00Z",
    )

    assert manifest["schema"] == "autoaudit.backup-manifest/v1"
    assert manifest["database"][
        "alembic_revision"
    ], "the schema revision must be recorded"
    assert manifest["artifacts"]["database.dump"]["sha256"]
    assert manifest["artifacts"]["evidence.tar"]["sha256"]
    # The manifest must state plainly that the archive is not encrypted, rather
    # than leaving a reader to assume either way.
    assert manifest["encryption"]["at_rest"] is False
    backup_module.verify(into)


def test_verify_detects_a_corrupted_artifact(backup_module, populated, tmp_path):
    """A backup nobody verified is an assumption, so verification must bite."""
    url, evidence = populated
    into = tmp_path / "backup"
    backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )

    dump = into / "database.dump"
    payload = bytearray(dump.read_bytes())
    payload[-1] ^= 0xFF
    dump.write_bytes(bytes(payload))

    with pytest.raises(
        backup_module.BackupError, match="does not match its recorded digest"
    ):
        backup_module.verify(into)


def test_verify_detects_a_missing_artifact(backup_module, populated, tmp_path):
    url, evidence = populated
    into = tmp_path / "backup"
    backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )
    (into / "evidence.tar").unlink()
    with pytest.raises(backup_module.BackupError, match="missing"):
        backup_module.verify(into)


def test_a_restore_returns_the_rows_and_the_evidence_bytes(
    backup_module, populated, admin_url, tmp_path
):
    """The test the whole module exists for: restore, then check the data."""
    url, evidence = populated
    into = tmp_path / "backup"
    backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )

    # Destroy the source, exactly as a real loss would.
    source_name = urlsplit(url).path.lstrip("/")
    _drop_database(admin_url, source_name)

    target_name = "autoaudit_backup_dst_" + uuid4().hex
    target_url = _create_database(admin_url, target_name)
    restored_evidence = tmp_path / "restored-evidence"
    try:
        backup_module.restore(
            source=into, target_url=target_url, evidence_dir=restored_evidence
        )

        assert (
            _psql(target_url, "SELECT notes FROM scan WHERE id=800")
            == "preserve this note"
        )
        assert (
            _psql(target_url, "SELECT count(*) FROM scan_result WHERE scan_id=800")
            == "2"
        )
        assert (
            _psql(target_url, "SELECT message FROM scan_result WHERE id=811")
            == "preserve this failure"
        )
        # The schema came back too, not just the rows.
        assert _psql(target_url, "SELECT count(*) FROM alembic_version") == "1"

        # The evidence bytes, which a database-only backup would have lost.
        #
        # Directly in the target, NOT under a nested evidence-store/. The
        # archive's fixed root is stripped on extraction: the documented
        # --evidence-dir is itself the evidence store, so keeping the root would
        # produce <store>/evidence-store/... and every restored object would be
        # unreachable by the application. Found by the review pass.
        assert (
            restored_evidence / "artifact-one.bin"
        ).read_bytes() == b"synthetic evidence object\n"
        assert (
            restored_evidence / "reports" / "report.pdf"
        ).read_bytes() == b"%PDF-1.4 synthetic\n"
        assert not (restored_evidence / "evidence-store").exists()
    finally:
        _drop_database(admin_url, target_name)


def test_a_cross_major_version_restore_is_refused(
    backup_module, populated, admin_url, tmp_path, monkeypatch
):
    """A custom-format dump is not guaranteed across major versions.

    This matters concretely here: docker-compose.yml ran postgres:17 while CI and
    docker-compose.production.yml ran postgres:16, so a dump taken from a
    developer's volume would not have restored into production. Phase 10 aligns
    the versions, and this refuses the mistake if they diverge again.
    """
    url, evidence = populated
    into = tmp_path / "backup"
    backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )

    manifest = json.loads((into / "manifest.json").read_text())
    manifest["database"]["server_version"] = "14.11"
    (into / "manifest.json").write_text(json.dumps(manifest))
    # The digest of the dump is unchanged, so this is purely the version check.

    target_name = "autoaudit_backup_ver_" + uuid4().hex
    target_url = _create_database(admin_url, target_name)
    try:
        with pytest.raises(backup_module.BackupError, match="major versions"):
            backup_module.restore(source=into, target_url=target_url, evidence_dir=None)
    finally:
        _drop_database(admin_url, target_name)


def test_a_backup_without_an_evidence_store_says_so(backup_module, populated, tmp_path):
    """Silence would restore an audit trail whose objects are all missing."""
    url, _ = populated
    into = tmp_path / "backup"
    manifest = backup_module.create(
        database_url=url,
        evidence_dir=None,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )
    entry = manifest["artifacts"]["evidence.tar"]
    assert entry["sha256"] is None
    assert "skipped" in entry
    backup_module.verify(into)


def test_the_archive_refuses_a_traversing_member(backup_module, tmp_path):
    """A backup archive is exactly the kind of file that moves between hosts."""
    import tarfile

    source = tmp_path / "backup"
    source.mkdir()
    archive = source / "evidence.tar"
    outside = tmp_path / "outside.txt"
    outside.write_text("should not be overwritten")
    with tarfile.open(archive, "w") as bundle:
        bundle.add(outside, arcname="../outside.txt")

    destination = tmp_path / "restored"
    destination.mkdir()
    with tarfile.open(archive, "r") as bundle:
        with pytest.raises(backup_module.BackupError, match="escapes the destination"):
            backup_module._safe_extract(bundle, destination)


def test_a_restore_into_a_populated_database_is_refused(
    backup_module, populated, admin_url, tmp_path
):
    """The most likely wrong --target-url an operator types is the production one.

    pg_restore into a populated database merges two datasets rather than
    replacing one, and by default it continues past errors and exits 0.
    """
    url, evidence = populated
    into = tmp_path / "backup"
    backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )

    # The source is still populated; restoring into it must be refused.
    with pytest.raises(backup_module.BackupError, match="already contains tables"):
        backup_module.restore(source=into, target_url=url, evidence_dir=None)

    # And the refusal happened before anything was written.
    assert _psql(url, "SELECT count(*) FROM scan WHERE id=800") == "1"


def test_an_explicit_override_allows_a_populated_target(
    backup_module, populated, tmp_path
):
    """The guard is a guard, not a wall: it can be overridden deliberately."""
    url, evidence = populated
    into = tmp_path / "backup"
    backup_module.create(
        database_url=url,
        evidence_dir=evidence,
        into=into,
        retention_policy_version="phase10-draft-1",
        taken_at=None,
    )
    # --single-transaction makes this fail cleanly on the duplicate rows rather
    # than half-applying, which is the behaviour being asserted: an error, not a
    # silently merged database.
    with pytest.raises(backup_module.BackupError, match="pg_restore failed"):
        backup_module.restore(
            source=into, target_url=url, evidence_dir=None, allow_nonempty=True
        )
    assert _psql(url, "SELECT count(*) FROM scan WHERE id=800") == "1"


def test_error_messages_do_not_echo_the_connection_string(backup_module):
    """libpq tools echo the URL they were given, and it carries the password."""
    redacted = backup_module._redact(
        'connection to server at "db" failed: '
        "postgresql://autoaudit:hunter2@db.internal:5432/autoaudit"  # pragma: allowlist secret
    )
    assert "hunter2" not in redacted
    assert "<redacted>" in redacted


def test_the_restore_is_atomic(backup_module):
    """pg_restore continues past errors and exits 0 unless told otherwise."""
    source = (ROOT / "tools" / "ops" / "backup.py").read_text()
    assert "--single-transaction" in source
    assert "--exit-on-error" in source


# ---------------------------------------------------------------------------
# The connection password never reaches a command line.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected_argv,expected_password",
    [
        (
            "postgresql+asyncpg://autoaudit:s3cr3t%40pass@db:5432/autoaudit",  # pragma: allowlist secret - synthetic fixture, never used to connect
            "postgresql://autoaudit@db:5432/autoaudit",
            "s3cr3t@pass",
        ),
        (
            "postgresql://autoaudit:pw@db/autoaudit",  # pragma: allowlist secret - synthetic fixture, never used to connect
            "postgresql://autoaudit@db/autoaudit",
            "pw",
        ),
        (
            "postgresql://autoaudit@127.0.0.1:5432/autoaudit",
            "postgresql://autoaudit@127.0.0.1:5432/autoaudit",
            None,
        ),
    ],
)
def test_the_database_password_travels_in_the_environment(
    backup_module, url, expected_argv, expected_password
):
    """A connection URL in argv is readable by every other process on the host.

    `ps` and /proc/<pid>/cmdline expose it for as long as pg_dump runs, which on
    a real database is minutes. The environment of another process is not
    readable that way. Percent-encoding has to survive the move, or a password
    containing an `@` or a `/` would authenticate as something else.
    """
    argv, environment = backup_module.libpq_invocation(url)
    assert argv == expected_argv
    assert expected_password is None or "@" not in argv.split("@")[0]
    if expected_password is None:
        assert "PGPASSWORD" not in environment
    else:
        assert environment["PGPASSWORD"] == expected_password
    assert expected_password is None or expected_password not in argv


def test_a_stale_pgpassword_is_not_inherited(backup_module, monkeypatch):
    """Inheriting someone else's PGPASSWORD authenticates as them."""
    monkeypatch.setenv("PGPASSWORD", "left-over-from-another-command")
    _, environment = backup_module.libpq_invocation(
        "postgresql://autoaudit@127.0.0.1:5432/autoaudit"
    )
    assert "PGPASSWORD" not in environment


def test_no_libpq_invocation_puts_a_password_in_argv():
    """Every psql/pg_dump/pg_restore call site must pass the environment.

    Checked structurally rather than by grep: a call that forgets `env=` is the
    exact way the password goes back into argv, and a comment mentioning psql
    should not be able to satisfy or break this.
    """
    import ast

    source = (ROOT / "tools" / "ops" / "backup.py").read_text()
    tree = ast.parse(source)
    tools = {"psql", "pg_dump", "pg_restore"}
    checked = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "_run"):
            continue
        argv = node.args[0] if node.args else None
        if not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts:
            continue
        first = argv.elts[0]
        if not (isinstance(first, ast.Constant) and first.value in tools):
            continue
        checked.add(first.value)
        assert any(keyword.arg == "env" for keyword in node.keywords), (
            f"backup.py:{node.lineno} runs {first.value} without passing the "
            "environment that carries PGPASSWORD"
        )
    assert checked == tools, f"call sites not found for {sorted(tools - checked)}"
