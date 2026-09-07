"""Real PostgreSQL migration preservation and terminal snapshot integrity."""

import asyncio
import json

import asyncpg
import pytest
from tests import test_migrations as migration_helpers
from tests.test_migrations import (
    MERGED_HEAD,
    PRIOR_HEADS,
    _alembic,
    _assert_preserved,
    _query,
    _seed,
    _snapshot,
    _versions,
)

database_url = migration_helpers.database_url

PHASE3_HEAD = "c4e91a73b620"  # pragma: allowlist secret - migration revision


@pytest.fixture
def migrated(database_url):
    _alembic(database_url, "upgrade", MERGED_HEAD)
    _seed(database_url, PRIOR_HEADS)
    before = asyncio.run(_snapshot(database_url))
    _alembic(database_url, "upgrade", PHASE3_HEAD)
    return database_url, before


def test_phase3_upgrade_preserves_legacy_unknown_attribution(migrated):
    url, before = migrated
    assert _versions(url) == {PHASE3_HEAD}
    after = asyncio.run(_snapshot(url))
    _assert_preserved(before, after)
    scan, result = after["scan"][0], after["scan_result"][0]
    for key in [
        "selected_count",
        "coverage_score",
        "semantics_version",
        "metadata_snapshot",
        "metadata_digest",
        "correlation_id",
    ]:
        assert scan[key] is None
    assert scan["indeterminate_count"] == scan["not_assessable_count"] == 0
    assert (
        result["selected"] is None
        and result["provenance"] is None
        and result["reason_code"] is None
    )
    _alembic(url, "upgrade", PHASE3_HEAD)
    assert asyncio.run(_snapshot(url)) == after


async def verify_terminal_integrity(url):
    connection = await asyncpg.connect(url)
    try:
        columns = {
            row["column_name"]
            for row in await connection.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_name='scan_result'"
            )
        }
        assert {"selected", "reason_code", "provenance"} <= columns
        await connection.execute(
            "UPDATE scan SET semantics_version='phase3-v1' WHERE id=301"
        )
        states = [
            "passed",
            "failed",
            "indeterminate",
            "error",
            "not_assessable",
            "skipped",
        ]
        for index, state in enumerate(states):
            selected = state != "skipped"
            result_id = 500 + index
            await connection.execute(
                "INSERT INTO scan_result (id, scan_id, control_id, status, selected) VALUES ($1, 301, $2, $3, $4)",
                result_id,
                f"1.{index + 20}",
                "pending" if selected else "skipped",
                selected,
            )
            if selected:
                # The worker's guarded first transition succeeds once.
                changed = await connection.execute(
                    "UPDATE scan_result SET status=$1, provenance=$2::jsonb WHERE id=$3 AND status='pending' AND selected IS TRUE",
                    state,
                    json.dumps(
                        {"schema_version": "phase3-v1", "control_id": f"1.{index + 20}"}
                    ),
                    result_id,
                )
                assert changed == "UPDATE 1"
                assert (
                    await connection.execute(
                        "UPDATE scan_result SET status='error' WHERE id=$1 AND status='pending' AND selected IS TRUE",
                        result_id,
                    )
                    == "UPDATE 0"
                )
            mutations = [
                "status='pending'",
                "message='changed'",
                "evidence='{}'",
                "provenance='{}'",
                "reason_code='changed'",
                "control_id='changed'",
                "scan_id=999",
                "selected=NULL",
            ]
            for assignment in mutations:
                with pytest.raises(
                    asyncpg.CheckViolationError, match="terminal.*immutable"
                ):
                    await connection.execute(
                        f"UPDATE scan_result SET {assignment} WHERE id=$1",  # nosec B608 # hardcoded mutation cases only
                        result_id,
                    )
            assert (
                await connection.execute(
                    "DELETE FROM scan_result WHERE id=$1", result_id
                )
                == "DELETE 1"
            )
        # Legacy rows retain their existing editable behavior; migration invents no snapshot.
        assert (
            await connection.execute(
                "UPDATE scan_result SET message='legacy update' WHERE id=401"
            )
            == "UPDATE 1"
        )
    finally:
        await connection.close()


def test_terminal_phase3_results_are_immutable_but_deletable(migrated):
    asyncio.run(verify_terminal_integrity(migrated[0]))


def test_fresh_database_upgrades_to_phase3_head(database_url):
    _alembic(database_url, "upgrade", PHASE3_HEAD)
    assert _versions(database_url) == {PHASE3_HEAD}


async def verify_scan_snapshot_integrity(url):
    connection = await asyncpg.connect(url)
    try:
        await connection.execute(
            "INSERT INTO scan (id, user_id, framework, benchmark, version, semantics_version, selected_count, metadata_snapshot, metadata_digest, correlation_id) VALUES (302, 101, 'cis', 'm365', 'v1', 'phase3-v1', 1, '{}', 'original', 'original')"
        )
        for assignment in [
            "metadata_snapshot='{\"altered\":true}'",
            "metadata_digest='changed'",
            "selected_count=2",
            "correlation_id='changed'",
            "semantics_version=NULL",
            "framework='changed'",
            "benchmark='changed'",
            "version='changed'",
            "total_controls=2",
        ]:
            with pytest.raises(asyncpg.CheckViolationError, match="scan.*immutable"):
                await connection.execute(f"UPDATE scan SET {assignment} WHERE id=302")  # nosec B608 # hardcoded mutation cases only
        assert (
            await connection.execute(
                "UPDATE scan SET status='completed', passed_count=1, compliance_score=100, coverage_score=100 WHERE id=302"
            )
            == "UPDATE 1"
        )
        assert await connection.execute("DELETE FROM scan WHERE id=302") == "DELETE 1"
    finally:
        await connection.close()


def test_phase3_scan_inputs_are_immutable(migrated):
    asyncio.run(verify_scan_snapshot_integrity(migrated[0]))


@pytest.mark.parametrize(
    "assignment",
    [
        "selected=NULL",
        "selected=false",
        "id=999",
        "scan_id=999",
        "control_id='changed'",
        "created_at='2000-01-01'",
    ],
)
def test_pending_result_selection_and_identity_cannot_be_rewritten(
    migrated, assignment
):
    url = migrated[0]
    asyncio.run(
        _query(
            url,
            "INSERT INTO scan_result (id, scan_id, control_id, status, selected) VALUES (600, 301, 'pending-fixture', 'pending', true)",
            execute=True,
        )
    )
    with pytest.raises(asyncpg.CheckViolationError, match="result.*immutable"):
        asyncio.run(
            _query(
                url,
                f"UPDATE scan_result SET {assignment} WHERE id=600",  # nosec B608 # hardcoded mutation cases only
                execute=True,
            )
        )
    # A blocked selection downgrade cannot disable the terminal snapshot guard.
    asyncio.run(
        _query(
            url,
            "UPDATE scan_result SET status='passed' WHERE id=600 AND status='pending' AND selected IS TRUE",
            execute=True,
        )
    )
    with pytest.raises(asyncpg.CheckViolationError, match="terminal.*immutable"):
        asyncio.run(
            _query(
                url,
                "UPDATE scan_result SET status='failed', evidence='{}' WHERE id=600",
                execute=True,
            )
        )


@pytest.mark.parametrize(
    "assignment",
    [
        "id=999",
        "created_at='2000-01-01'",
        "updated_at='2000-01-01'",
    ],
)
def test_terminal_result_identity_and_timestamps_are_immutable(migrated, assignment):
    url = migrated[0]
    asyncio.run(
        _query(
            url,
            "INSERT INTO scan_result (id, scan_id, control_id, status, selected) VALUES (600, 301, 'terminal-fixture', 'passed', true)",
            execute=True,
        )
    )
    with pytest.raises(asyncpg.CheckViolationError, match="terminal.*immutable"):
        asyncio.run(
            _query(
                url,
                f"UPDATE scan_result SET {assignment} WHERE id=600",  # nosec B608 # hardcoded mutation cases only
                execute=True,
            )
        )


@pytest.mark.parametrize(
    "assignment",
    [
        "id=999",
        "user_id=999",
        "m365_connection_id=NULL",
        "azure_connection_id=999",
        "gcp_connection_id=999",
        "aws_connection_id=999",
    ],
)
def test_scan_identity_and_connection_attribution_are_immutable(migrated, assignment):
    url = migrated[0]
    asyncio.run(
        _query(
            url,
            "UPDATE scan SET semantics_version='phase3-v1' WHERE id=301",
            execute=True,
        )
    )
    with pytest.raises(asyncpg.CheckViolationError, match="scan.*immutable"):
        asyncio.run(
            _query(url, f"UPDATE scan SET {assignment} WHERE id=301", execute=True)  # nosec B608 # hardcoded mutation cases only
        )
