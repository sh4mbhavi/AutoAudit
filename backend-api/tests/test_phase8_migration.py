"""Phase 8 migration a3f5c1d90b47: schema shape, guards and forward-only posture.

Every assertion here runs against a real disposable PostgreSQL, because every
protection the revision adds is a CHECK constraint, a referential action or a
trigger. None of them exist in a SQLAlchemy model and none of them can be
verified without a server.
"""

import asyncio
import importlib.util

import asyncpg
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from tests import test_migrations as migration_helpers
from tests.test_migrations import BACKEND, _alembic, _query, _versions

database_url = migration_helpers.database_url

PHASE8_HEAD = "a3f5c1d90b47"  # pragma: allowlist secret - migration revision
MIGRATION_PATH = (
    BACKEND
    / "alembic"
    / "versions"
    / "a3f5c1d90b47_phase8_drift_and_compliance_binding.py"
)

PHASE8_TABLES = (
    "scan_result_factprint",
    "drift_baseline",
    "drift_run",
    "drift_event",
    "drift_notification",
)

# Every Phase 8 datetime column, listed here rather than discovered, so a column
# that quietly loses its timestamptz-ness cannot also quietly leave the list.
EXPECTED_DATETIME_COLUMNS = {
    ("scan_result_factprint", "recorded_at"),
    ("drift_baseline", "established_at"),
    ("drift_baseline", "superseded_at"),
    ("drift_run", "started_at"),
    ("drift_run", "completed_at"),
    ("drift_event", "occurred_at"),
    ("drift_notification", "occurred_at"),
}

# Synthetic tenant-free fixtures. Digests are repeat()ed in SQL so no 64-character
# hexadecimal literal ever appears in a tracked file.
FIXTURES = """
    INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
    VALUES (101, 'user', 'phase8@example.invalid', 'synthetic-not-a-password', true, false, true);
    INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
    VALUES (201, 101, 'Phase 8 fixture', 'synthetic-tenant', 'synthetic-client', 'synthetic-ciphertext');
    INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version)
    VALUES (301, 101, 201, 'cis', 'microsoft-365-foundations', 'v6.0.0'),
           (302, 101, 201, 'cis', 'microsoft-365-foundations', 'v6.0.0'),
           (303, 101, 201, 'cis', 'microsoft-365-foundations', 'v6.0.0');
"""

FACTPRINT = """
    INSERT INTO scan_result_factprint
        (scan_id, control_id, collector_id, projection_id, field_name, field_kind,
         value_digest, observed_value, factprint_schema, key_id,
         retention_policy_version, recorded_at)
    VALUES ({scan_id}, '3.2.2', 'compliance.dlp.policies', 'dlp_teams_v1',
            'teams_policy_enabled', 'bool', repeat('a', 64), 'true'::jsonb,
            'phase8-fact-1', 'k0000000', 'phase8-draft-1', now());
"""

BASELINE = """
    INSERT INTO drift_baseline
        (id, user_id, scan_id, m365_connection_id, framework, benchmark, version,
         metadata_digest, policy_corpus_digest, semantics_version,
         connection_identity_digest, configuration_key, evaluation_key,
         observation_digest, control_count, factprint_field_count, status,
         drift_version, retention_policy_version, established_at)
    VALUES ({baseline_id}, 101, {scan_id}, 201, 'cis', 'microsoft-365-foundations',
            'v6.0.0', repeat('b', 64), repeat('c', 64), 'phase3-v1', repeat('d', 64),
            repeat('{configuration}', 64), repeat('f', 64), repeat('0', 64), 140, 3,
            '{status}', 'phase8-drift-1', 'phase8-draft-1', now());
"""

RUN = """
    INSERT INTO drift_run
        (id, baseline_id, baseline_scan_id, current_scan_id, user_id, framework,
         benchmark, version, status, trigger, configuration_comparable,
         evaluation_comparable, axis_reasons, baseline_configuration_key,
         current_configuration_key, baseline_evaluation_key, current_evaluation_key,
         controls_compared, controls_skipped, event_count, event_counts,
         event_set_digest, drift_version, retention_policy_version,
         started_at, completed_at)
    VALUES ({run_id}, {baseline_id}, {baseline_scan_id}, {current_scan_id}, 101, 'cis',
            'microsoft-365-foundations', 'v6.0.0', 'completed', 'scan_finalised',
            true, true, '{{}}'::jsonb, repeat('e', 64), repeat('e', 64),
            repeat('f', 64), repeat('f', 64), 140, '[]'::jsonb, 1,
            '{{"changed": 1}}'::jsonb, repeat('1', 64), 'phase8-drift-1',
            'phase8-draft-1', now(), now());
"""

EVENT = """
    INSERT INTO drift_event
        (id, drift_run_id, baseline_id, baseline_scan_id, current_scan_id, user_id,
         control_id, collector_id, event_class, change_type, fact_name,
         previous_value, current_value, severity, severity_basis, event_key,
         drift_version, retention_policy_version, occurred_at)
    VALUES ({event_id}, {run_id}, {baseline_id}, 301, 302, 101, '3.2.2',
            'compliance.dlp.policies', '{event_class}', '{change_type}', {fact_name},
            {previous_value}, {current_value}, 'medium', 'benchmark_severity',
            encode(sha256('{event_id}'::bytea), 'hex'), 'phase8-drift-1',
            'phase8-draft-1', now());
"""

NOTIFICATION = """
    INSERT INTO drift_notification
        (id, baseline_id, drift_run_id, user_id, thread_key, scope, channel,
         routing_rule, revision_number, action, state_after, severity, summary_code,
         summary_counts, drift_version, retention_policy_version, occurred_at)
    VALUES ({notification_id}, {baseline_id}, {run_id}, 101, repeat('3', 64), 'run',
            'inapp', 'owner_high_or_above', 1, 'raised', 'open', 'high',
            'drift_run_completed', '{{"changed": 1}}'::jsonb, 'phase8-drift-1',
            'phase8-draft-1', now());
"""


def _execute(url, sql):
    return asyncio.run(_query(url, sql, execute=True))


def _rows(url, sql, *parameters):
    return asyncio.run(_query(url, sql, parameters=parameters))


@pytest.fixture
def migrated(database_url):
    """A database at Phase 8 head carrying one user, one connection, three scans."""
    _alembic(database_url, "upgrade", "head")
    assert _versions(database_url) == {PHASE8_HEAD}
    _execute(database_url, FIXTURES)
    return database_url


@pytest.fixture
def drift_chain(migrated):
    """A baseline on scan 301, a run comparing 301 to 302, an event and a notice."""
    _execute(
        migrated,
        BASELINE.format(
            baseline_id=901, scan_id=301, configuration="e", status="active"
        ),
    )
    _execute(
        migrated,
        RUN.format(
            run_id=911, baseline_id=901, baseline_scan_id=301, current_scan_id=302
        ),
    )
    _execute(
        migrated,
        EVENT.format(
            event_id=921,
            run_id=911,
            baseline_id=901,
            event_class="configuration",
            change_type="changed",
            fact_name="'teams_policy_enabled'",
            previous_value="'false'::jsonb",
            current_value="'true'::jsonb",
        ),
    )
    _execute(
        migrated, NOTIFICATION.format(notification_id=931, baseline_id=901, run_id=911)
    )
    return migrated


def test_single_head():
    """`alembic upgrade head` must still resolve without branch selection."""
    scripts = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini")))
    assert tuple(scripts.get_heads()) == (PHASE8_HEAD,)


def test_downgrade_raises():
    specification = importlib.util.spec_from_file_location(
        "phase8_migration_module", MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    assert module.revision == PHASE8_HEAD
    assert module.down_revision == "f7d2c48b1a03"  # pragma: allowlist secret - revision
    with pytest.raises(RuntimeError, match="forward-only"):
        module.downgrade()


def test_every_phase8_datetime_column_is_timestamptz(migrated):
    """D-P8-10: a naive timestamp is a deployability defect on a non-UTC server."""
    columns = _rows(
        migrated,
        "SELECT table_name, column_name, data_type FROM information_schema.columns"
        " WHERE table_schema = 'public' AND table_name = ANY($1::text[])",
        list(PHASE8_TABLES),
    )
    datetimes = {
        (row["table_name"], row["column_name"]): row["data_type"]
        for row in columns
        if row["column_name"].endswith("_at")
    }
    assert set(datetimes) == EXPECTED_DATETIME_COLUMNS
    assert set(datetimes.values()) == {"timestamp with time zone"}


def test_m365_connection_gains_two_nullable_columns(migrated):
    columns = {
        row["column_name"]: row["is_nullable"]
        for row in _rows(
            migrated,
            "SELECT column_name, is_nullable FROM information_schema.columns"
            " WHERE table_schema = 'public' AND table_name = 'm365_connection'",
        )
    }
    assert columns["compliance_certificate_alias"] == "YES"
    assert columns["compliance_organization"] == "YES"


@pytest.mark.parametrize("literal", ["'{\"a\": 1}'::jsonb", "'[1]'::jsonb"])
def test_drift_event_rejects_object_and_array_values(drift_chain, literal):
    """D-P8-08: a raw tenant record can never be stored, even by a future bug."""
    for column in ("previous_value", "current_value"):
        statement = EVENT.format(
            event_id=922,
            run_id=911,
            baseline_id=901,
            event_class="configuration",
            change_type="changed",
            fact_name="'teams_policy_enabled'",
            previous_value=literal if column == "previous_value" else "NULL",
            current_value=literal if column == "current_value" else "NULL",
        )
        with pytest.raises(asyncpg.CheckViolationError, match="scalar"):
            _execute(drift_chain, statement)


def test_drift_event_rejects_long_value(drift_chain):
    """121 characters of JSON text is one character past the bound."""
    too_long = "to_jsonb(repeat('x', 119))"
    at_the_bound = "to_jsonb(repeat('x', 118))"
    with pytest.raises(asyncpg.CheckViolationError, match="_len"):
        _execute(
            drift_chain,
            EVENT.format(
                event_id=923,
                run_id=911,
                baseline_id=901,
                event_class="configuration",
                change_type="changed",
                fact_name="'teams_policy_enabled'",
                previous_value=too_long,
                current_value="NULL",
            ),
        )
    _execute(
        drift_chain,
        EVENT.format(
            event_id=924,
            run_id=911,
            baseline_id=901,
            event_class="configuration",
            change_type="changed",
            fact_name="'teams_policy_enabled'",
            previous_value=at_the_bound,
            current_value="NULL",
        ),
    )
    stored = _rows(
        drift_chain,
        "SELECT length(previous_value::text) AS width FROM drift_event WHERE id = 924",
    )
    assert stored[0]["width"] == 120


def test_configuration_event_requires_fact_name(drift_chain):
    with pytest.raises(asyncpg.CheckViolationError, match="fact_binding"):
        _execute(
            drift_chain,
            EVENT.format(
                event_id=925,
                run_id=911,
                baseline_id=901,
                event_class="configuration",
                change_type="changed",
                fact_name="NULL",
                previous_value="NULL",
                current_value="NULL",
            ),
        )


def test_evaluation_event_forbids_fact_name(drift_chain):
    with pytest.raises(asyncpg.CheckViolationError, match="fact_binding"):
        _execute(
            drift_chain,
            EVENT.format(
                event_id=926,
                run_id=911,
                baseline_id=901,
                event_class="evaluation",
                change_type="status_changed",
                fact_name="'teams_policy_enabled'",
                previous_value="NULL",
                current_value="NULL",
            ),
        )
    # The same row without a fact name is accepted, so the constraint is the
    # binding and not the event class.
    _execute(
        drift_chain,
        EVENT.format(
            event_id=927,
            run_id=911,
            baseline_id=901,
            event_class="evaluation",
            change_type="coverage_lost",
            fact_name="NULL",
            previous_value="NULL",
            current_value="NULL",
        ),
    )


@pytest.mark.parametrize(
    ("table", "identifier", "mutation"),
    [
        ("drift_run", 911, "status = 'not_comparable'"),
        ("drift_event", 921, "severity = 'low'"),
        ("drift_notification", 931, "state_after = 'acknowledged'"),
        ("scan_result_factprint", None, "value_digest = repeat('9', 64)"),
    ],
)
def test_append_only_tables_reject_update_and_delete(
    drift_chain, table, identifier, mutation
):
    """The generic Phase 7 guard now covers the Phase 8 history tables too.

    Its message names the phase that created the guard, not the table's owner, so
    it reads "Phase 7 drift_event history is append-only".
    """
    if table == "scan_result_factprint":
        _execute(drift_chain, FACTPRINT.format(scan_id=303))
        where = "scan_id = 303"
    else:
        where = f"id = {identifier}"
    with pytest.raises(asyncpg.CheckViolationError, match="append-only"):
        _execute(drift_chain, f"UPDATE {table} SET {mutation} WHERE {where}")  # nosec B608 # fixed table and mutation cases from the parametrisation above
    if table == "scan_result_factprint":
        # Deletion stays possible: the row hangs off the scan by ON DELETE CASCADE
        # and a DELETE guard would make deleting a scan impossible.
        assert _execute(drift_chain, f"DELETE FROM {table} WHERE {where}") == "DELETE 1"  # nosec B608 # fixed table name from the parametrisation above
        return
    with pytest.raises(asyncpg.CheckViolationError, match="append-only"):
        _execute(drift_chain, f"DELETE FROM {table} WHERE {where}")  # nosec B608 # fixed table name from the parametrisation above


def test_scan_delete_cascades_factprint_and_is_restricted_by_baseline(migrated):
    _execute(migrated, FACTPRINT.format(scan_id=302))
    _execute(
        migrated,
        BASELINE.format(
            baseline_id=902, scan_id=301, configuration="e", status="active"
        ),
    )
    assert _execute(migrated, "DELETE FROM scan WHERE id = 302") == "DELETE 1"
    assert _rows(migrated, "SELECT id FROM scan_result_factprint") == []
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        _execute(migrated, "DELETE FROM scan WHERE id = 301")


def test_deleting_a_scan_a_drift_run_references_is_refused(drift_chain):
    """Observed consequence of the append-only guard meeting an ON DELETE SET NULL.

    drift_run.baseline_scan_id and current_scan_id are declared SET NULL, but the
    referential action is an UPDATE and the BEFORE UPDATE guard fires first. A
    scan a drift run has already compared is therefore undeletable, and the
    refusal arrives wearing the append-only message rather than a foreign-key one.
    """
    with pytest.raises(asyncpg.CheckViolationError, match="append-only"):
        _execute(drift_chain, "DELETE FROM scan WHERE id = 302")


def test_baseline_identity_is_frozen_and_status_cannot_rewind(drift_chain):
    for mutation in [
        "scan_id = 303",
        "metadata_digest = repeat('9', 64)",
        "policy_corpus_digest = repeat('9', 64)",
        "configuration_key = repeat('9', 64)",
        "evaluation_key = repeat('9', 64)",
        "observation_digest = repeat('9', 64)",
        "connection_identity_digest = repeat('9', 64)",
        "control_count = 0",
        "factprint_field_count = 0",
        "semantics_version = 'rewritten'",
        "drift_version = 'rewritten'",
        "retention_policy_version = 'rewritten'",
        "established_at = '2000-01-01T00:00:00+00:00'",
        "m365_connection_id = NULL",
        "user_id = NULL",
    ]:
        with pytest.raises(asyncpg.CheckViolationError, match="identity is immutable"):
            _execute(
                drift_chain,
                f"UPDATE drift_baseline SET {mutation} WHERE id = 901",  # nosec B608 # hardcoded mutation cases only
            )

    # Superseding is the one legitimate transition, and it is one-way.
    assert (
        _execute(
            drift_chain,
            "UPDATE drift_baseline SET status = 'superseded', superseded_at = now(),"
            " note = 'replaced by a later scan' WHERE id = 901",
        )
        == "UPDATE 1"
    )
    with pytest.raises(asyncpg.CheckViolationError, match="cannot rewind"):
        _execute(
            drift_chain,
            "UPDATE drift_baseline SET status = 'active', superseded_at = NULL"
            " WHERE id = 901",
        )


def test_single_active_baseline_per_configuration_key(migrated):
    _execute(
        migrated,
        BASELINE.format(
            baseline_id=903, scan_id=301, configuration="e", status="active"
        ),
    )
    with pytest.raises(asyncpg.UniqueViolationError):
        _execute(
            migrated,
            BASELINE.format(
                baseline_id=904, scan_id=302, configuration="e", status="active"
            ),
        )
    # The partial index constrains active rows only: a superseded predecessor on
    # the same comparability tuple is exactly what history looks like.
    _execute(
        migrated,
        "UPDATE drift_baseline SET status = 'superseded', superseded_at = now()"
        " WHERE id = 903",
    )
    _execute(
        migrated,
        BASELINE.format(
            baseline_id=905, scan_id=302, configuration="e", status="active"
        ),
    )
    active = _rows(
        migrated, "SELECT id FROM drift_baseline WHERE status = 'active' ORDER BY id"
    )
    assert [row["id"] for row in active] == [905]
