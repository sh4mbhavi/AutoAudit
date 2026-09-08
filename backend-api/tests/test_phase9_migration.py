"""Phase 9 migration b9d4e17c6a52: the durable unit of work becomes a collection.

Run against a real disposable PostgreSQL, because what the revision adds is a
CHECK constraint and a partial index: neither exists in a SQLAlchemy model and
neither can be verified without a server.
"""

import asyncio
import importlib.util

import asyncpg
import pytest
from tests import test_migrations as migration_helpers
from tests.test_migrations import BACKEND, _alembic, _query, _versions

database_url = migration_helpers.database_url

PHASE9_HEAD = "b9d4e17c6a52"  # pragma: allowlist secret - migration revision
MIGRATION_PATH = (
    BACKEND / "alembic" / "versions" / "b9d4e17c6a52_phase9_collection_dispatch.py"
)

FIXTURE = """
    INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
    VALUES (901, 'user', 'phase9@example.invalid', 'synthetic-not-a-password', true, false, true);
    INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
    VALUES (911, 901, 'Phase 9 fixture', 'synthetic-tenant', 'synthetic-client', 'synthetic-ciphertext');
    INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version, status)
    VALUES (921, 901, 911, 'cis', 'microsoft-365-foundations', 'v6.0.0', 'running');
    INSERT INTO scan_result (id, scan_id, control_id, status, selected)
    VALUES (931, 921, '1.1.1', 'pending', true);
"""


@pytest.fixture
def migrated(database_url):
    _alembic(database_url, "upgrade", "head")
    assert _versions(database_url) == {PHASE9_HEAD}
    asyncio.run(_query(database_url, FIXTURE, execute=True))
    return database_url


def _execute(url, sql):
    return asyncio.run(_query(url, sql, execute=True))


def _rows(url, sql):
    return asyncio.run(_query(url, sql))


def test_the_revision_is_forward_only():
    specification = importlib.util.spec_from_file_location(
        "phase9_migration_module", MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    assert module.revision == PHASE9_HEAD
    assert module.down_revision == "a3f5c1d90b47"  # pragma: allowlist secret - revision
    with pytest.raises(RuntimeError, match="forward-only"):
        module.downgrade()


def test_collector_id_is_nullable_and_has_no_server_default(migrated):
    columns = _rows(
        migrated,
        """SELECT is_nullable, column_default, data_type, character_maximum_length
           FROM information_schema.columns
           WHERE table_name='scan_dispatch' AND column_name='collector_id'""",
    )
    assert len(columns) == 1
    column = columns[0]
    # Existing rows are control rows and must stay control rows.
    assert column["is_nullable"] == "YES"
    assert column["column_default"] is None
    assert column["character_maximum_length"] == 200


def test_a_run_scan_row_names_neither_identifier(migrated):
    _execute(
        migrated,
        "INSERT INTO scan_dispatch (id, scan_id, task_name) "
        "VALUES ('11111111-1111-1111-1111-111111111111', 921, 'worker.tasks.run_scan')",
    )
    row = _rows(
        migrated,
        "SELECT result_id, collector_id FROM scan_dispatch WHERE scan_id=921",
    )[0]
    assert row["result_id"] is None and row["collector_id"] is None


def test_a_collection_row_and_a_control_row_are_both_accepted(migrated):
    _execute(
        migrated,
        """INSERT INTO scan_dispatch (id, scan_id, collector_id, task_name)
           VALUES ('22222222-2222-2222-2222-222222222222', 921,
                   'entra.roles.cloud_only_admins', 'worker.tasks.evaluate_collection');
           INSERT INTO scan_dispatch (id, scan_id, result_id, task_name)
           VALUES ('33333333-3333-3333-3333-333333333333', 921, 931,
                   'worker.tasks.evaluate_control');""",
    )
    rows = _rows(
        migrated,
        "SELECT task_name FROM scan_dispatch WHERE scan_id=921 ORDER BY id",
    )
    # The pre-Phase-9 shape is still publishable, so an outbox row written
    # before this deploy is not stranded.
    assert [row["task_name"] for row in rows] == [
        "worker.tasks.evaluate_collection",
        "worker.tasks.evaluate_control",
    ]


def test_a_row_can_never_name_both_a_collector_and_a_result(migrated):
    with pytest.raises(asyncpg.PostgresError, match="ck_scan_dispatch_single_key"):
        _execute(
            migrated,
            """INSERT INTO scan_dispatch (id, scan_id, result_id, collector_id, task_name)
               VALUES ('44444444-4444-4444-4444-444444444444', 921, 931,
                       'entra.roles.cloud_only_admins', 'worker.tasks.evaluate_collection')""",
        )


def test_a_collection_row_survives_the_deletion_of_one_of_its_results(migrated):
    """A collection is not owned by any one control.

    A control row cascades away with its result; a collection row must not,
    because the other controls in its group may still be pending.
    """
    _execute(
        migrated,
        """INSERT INTO scan_dispatch (id, scan_id, collector_id, task_name)
           VALUES ('55555555-5555-5555-5555-555555555555', 921,
                   'entra.roles.cloud_only_admins', 'worker.tasks.evaluate_collection');
           DELETE FROM scan_result WHERE id=931;""",
    )
    assert _rows(migrated, "SELECT count(*) AS n FROM scan_dispatch")[0]["n"] == 1


def test_deleting_the_scan_still_cascades_every_dispatch_row(migrated):
    _execute(
        migrated,
        """INSERT INTO scan_dispatch (id, scan_id, collector_id, task_name)
           VALUES ('66666666-6666-6666-6666-666666666666', 921,
                   'entra.roles.cloud_only_admins', 'worker.tasks.evaluate_collection');
           DELETE FROM scan_result WHERE scan_id=921;
           DELETE FROM scan WHERE id=921;""",
    )
    assert _rows(migrated, "SELECT count(*) AS n FROM scan_dispatch")[0]["n"] == 0


def test_the_collection_lookup_is_indexed(migrated):
    indexes = _rows(
        migrated,
        "SELECT indexdef FROM pg_indexes WHERE tablename='scan_dispatch' "
        "AND indexname='ix_scan_dispatch_collection'",
    )
    assert len(indexes) == 1
    definition = indexes[0]["indexdef"]
    assert "scan_id" in definition and "collector_id" in definition
    # Partial: control rows and run_scan rows never match the predicate.
    assert "WHERE (collector_id IS NOT NULL)" in definition


def test_the_phase3_immutability_trigger_still_covers_only_scan_inputs(migrated):
    """scan_dispatch is orchestration state and is deliberately outside it."""
    triggers = _rows(
        migrated,
        "SELECT tgname FROM pg_trigger WHERE tgrelid='scan_dispatch'::regclass "
        "AND NOT tgisinternal",
    )
    assert triggers == []
