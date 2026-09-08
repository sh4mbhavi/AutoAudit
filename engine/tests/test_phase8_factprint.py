"""Declared factprint projections: canonicalisation, the key gate, and persistence."""

import asyncio
import base64
import hashlib
import hmac
import itertools
import json
import os
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.orm import Session

from collectors.registry import get_collector
from tests import test_phase3_persistence as persistence_helpers
from tests.test_phase4_collector_contracts import (
    GRAPH_CASES,
    PS_CASES,
    collect_graph,
    powershell_client,
)
from worker import factprint
from worker.config import WorkerSettings
from worker.factprint import (
    FACT_PROJECTIONS,
    FORBIDDEN_SOURCE_KEYS,
    FieldSpec,
    Projection,
    canonical_json,
    canonical_sorted,
    fingerprint_key,
    key_id,
    persist_factprint,
    project_facts,
)

# Every factprint digest is scoped to a tenant; see TENANT_KEY_DOMAIN.
TENANT_ID = "00000000-0000-0000-0000-0000000000aa"

database = persistence_helpers.database

# Synthetic, deterministic key material. Nothing here is a credential: the bytes
# are generated in the test process and never leave it.
KEY_A = base64.urlsafe_b64encode(bytes(range(32))).decode()
KEY_B = base64.urlsafe_b64encode(bytes(range(32, 64))).decode()
KEY_HEX = bytes(range(32)).hex()
KEY_TOO_SHORT = base64.urlsafe_b64encode(bytes(31)).decode()

# No enum or enum_set field ships in v1, so both kinds are exercised against a
# projection that exists only inside this module.
SYNTHETIC_ID = "tests.synthetic.dlp"
SYNTHETIC = Projection(
    f"{SYNTHETIC_ID}/v1",
    (
        FieldSpec("mode", "enum", ("enable",)),
        FieldSpec("teams_locations", "enum_set", ("all", "selected")),
    ),
)

# Values the fixture for a declared field is allowed to take, per declared kind.
_KIND_CHECKS = {
    "bool": lambda value: isinstance(value, bool),
    "int": lambda value: isinstance(value, int) and not isinstance(value, bool),
    "enum": lambda value: isinstance(value, str),
    "enum_set": lambda value: isinstance(value, list),
}


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", KEY_A)
    return fingerprint_key()


@pytest.fixture
def synthetic(monkeypatch, keyed):
    monkeypatch.setitem(factprint.FACT_PROJECTIONS, SYNTHETIC_ID, SYNTHETIC)
    return keyed


def _collect_fixture(collector_id):
    """Run one collector against its own Phase 4 contract fixture."""
    if collector_id in GRAPH_CASES:
        result, _ = collect_graph(collector_id)
        return result
    raw, _ = PS_CASES[collector_id]
    client = powershell_client(return_value=raw)
    return asyncio.run(get_collector(collector_id).collect(client))


def test_canonical_sorted_sorts_lists_at_every_depth():
    """Provider ordering is discarded at every depth, not just the top level."""
    value = {"a": [3, 1, [9, 2], {"b": [5, 4]}]}
    expected = canonical_json(canonical_sorted(value))
    permutations = [
        {"a": list(outer)}
        for outer in itertools.permutations([3, 1, [2, 9], {"b": [4, 5]}])
    ]
    permutations += [
        {"a": list(outer)}
        for outer in itertools.permutations([1, 3, [9, 2], {"b": [5, 4]}])
    ]
    for permutation in permutations:
        assert canonical_json(canonical_sorted(permutation)) == expected
    # provenance.canonical_digest deliberately does NOT do this; the difference is
    # the whole reason this helper exists.
    assert canonical_sorted([[2, 1], [1, 2]]) == [[1, 2], [1, 2]]


def test_shipped_key_default_is_empty():
    assert WorkerSettings.model_fields["DRIFT_FACT_HMAC_KEY"].default == ""


@pytest.mark.parametrize(
    "material",
    [
        WorkerSettings.model_fields["DRIFT_FACT_HMAC_KEY"].default,
        "",
        "   ",
        KEY_TOO_SHORT,
        "not-base64!!",
    ],
)
@pytest.mark.parametrize("collector_id", sorted(FACT_PROJECTIONS))
def test_no_key_writes_nothing(monkeypatch, material, collector_id):
    """The key is the gate: an unusable key produces zero rows, never an unkeyed digest."""
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", material)
    assert fingerprint_key() is None
    projection = FACT_PROJECTIONS[collector_id]
    collected = {spec.name: False for spec in projection.fields}
    assert project_facts(collector_id, collected, TENANT_ID) is None


@pytest.mark.parametrize("material", [KEY_A, KEY_HEX])
def test_usable_key_encodings_are_accepted(monkeypatch, material):
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", material)
    key = fingerprint_key()
    assert key is not None and len(key) >= 32
    assert (
        key_id(key)
        == hashlib.sha256(b"autoaudit.factprint.keyid.v1" + key).hexdigest()[:16]
    )


def test_digests_are_keyed(monkeypatch):
    """Two keys disagree, and no digest is a bare sha256 of any preimage variant."""
    collected = {"public_groups_count": 3}
    digests = []
    identifiers = []
    for material in (KEY_A, KEY_B):
        monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", material)
        entry = project_facts("entra.groups.groups", collected, TENANT_ID)[0]
        digests.append(entry["value_digest"])
        identifiers.append(entry["key_id"])
    assert digests[0] != digests[1]
    assert identifiers[0] != identifiers[1]

    projection_id = "entra.groups.groups/v1"
    unkeyed = {
        canonical_json(3),
        json.dumps(3),
        "3",
        projection_id + "\x1fpublic_groups_count\x1fint\x1f3",
        "autoaudit.factprint.v1\x1f"
        + projection_id
        + "\x1fpublic_groups_count\x1fint\x1f3",
    }
    forbidden = {hashlib.sha256(item.encode()).hexdigest() for item in unkeyed}
    forbidden |= {hashlib.sha256(b"3").hexdigest()}
    assert not forbidden & set(digests)


def test_enum_set_value_digest_preimage_uses_member_digests(synthetic):
    """The member_ref is in the preimage of the opaque value digest, by hand."""
    key = synthetic
    entries = project_facts(
        SYNTHETIC_ID, {"teams_locations": ["Selected", "All"]}, TENANT_ID
    )
    entry = next(e for e in entries if e["field_name"] == "teams_locations")

    # Digests are produced under the per-tenant subkey, not the configured key.
    key = factprint.tenant_key(key, TENANT_ID)
    # Member digests are stored PARALLEL to member_tokens, so this list is in
    # token order. The value digest is taken over the canonically sorted
    # digests, which is what makes it independent of that order.
    expected_members = [
        hmac.new(
            key,
            b"autoaudit.factmember.v1\x1f"
            + SYNTHETIC.projection_id.encode()
            + b"\x1fteams_locations\x1f"
            + canonical_json(token).encode(),
            hashlib.sha256,
        ).hexdigest()
        for token in ("all", "selected")
    ]
    expected_value = hmac.new(
        key,
        b"autoaudit.factprint.v1\x1f"
        + SYNTHETIC.projection_id.encode()
        + b"\x1fteams_locations\x1fenum_set\x1f"
        + canonical_json(sorted(expected_members)).encode(),
        hashlib.sha256,
    ).hexdigest()

    assert entry["member_digests"] == expected_members
    assert entry["value_digest"] == expected_value
    assert entry["member_tokens"] == ["all", "selected"]
    assert entry["observed_value"] is None
    # Input order cannot change the digest.
    reordered = project_facts(
        SYNTHETIC_ID, {"teams_locations": ["All", "Selected"]}, TENANT_ID
    )
    assert reordered == entries


@pytest.mark.parametrize("collector_id", sorted(FACT_PROJECTIONS))
def test_every_declared_field_exists_in_the_phase4_contract_fixture(collector_id):
    """No persisted field name is guessed: each is pinned by a contract fixture."""
    assert collector_id in GRAPH_CASES or collector_id in PS_CASES
    result = _collect_fixture(collector_id)
    assert isinstance(result, dict)
    for spec in FACT_PROJECTIONS[collector_id].fields:
        assert spec.name in result, (collector_id, spec.name)
        value = result[spec.name]
        assert value is None or _KIND_CHECKS[spec.kind](value), (
            collector_id,
            spec.name,
            type(value).__name__,
        )


def test_missing_key_is_absent_not_false(keyed):
    """Absence is never rendered as false and never as an empty set."""
    entries = project_facts(
        "exchange.organization.organization_config", {"oauth_enabled": True}, TENANT_ID
    )
    assert [entry["field_name"] for entry in entries] == ["oauth_enabled"]
    assert entries[0]["observed_value"] is True
    assert (
        project_facts("exchange.organization.organization_config", {}, TENANT_ID) == []
    )


def test_present_null_is_recorded_as_null(keyed):
    entries = project_facts(
        "entra.groups.groups", {"public_groups_count": None}, TENANT_ID
    )
    assert len(entries) == 1
    assert entries[0]["observed_value"] is None
    assert entries[0]["member_digests"] is None
    assert entries[0]["member_tokens"] is None


@pytest.mark.parametrize(
    "collector_id,field_name,value",
    [
        ("entra.applications.apps_and_services_settings", "user_owned_apps_enabled", v)
        for v in ("true", "True", 1.5, 1, 0, {}, [], [True])
    ]
    + [
        ("entra.groups.groups", "public_groups_count", v)
        for v in ("1", 1.5, True, False, -1, {}, [1])
    ],
)
def test_malformed_values_are_dropped_never_coerced(
    keyed, collector_id, field_name, value
):
    assert project_facts(collector_id, {field_name: value}, TENANT_ID) == []


def test_enum_set_drops_the_whole_field_on_one_bad_element(synthetic):
    """Never drop an element silently: a shrunken set would read as tenant drift."""
    entries = project_facts(
        SYNTHETIC_ID, {"mode": "Enable", "teams_locations": ["All", 5]}, TENANT_ID
    )
    assert [entry["field_name"] for entry in entries] == ["mode"]
    assert project_facts(SYNTHETIC_ID, {"teams_locations": None}, TENANT_ID) == []
    assert project_facts(SYNTHETIC_ID, {"teams_locations": "All"}, TENANT_ID) == []


def test_enum_set_larger_than_the_bound_drops_the_field(monkeypatch, synthetic):
    monkeypatch.setattr(factprint.settings, "DRIFT_MAX_SET_MEMBERS", 1)
    assert (
        project_facts(SYNTHETIC_ID, {"teams_locations": ["All", "Selected"]}, TENANT_ID)
        == []
    )
    assert (
        len(project_facts(SYNTHETIC_ID, {"teams_locations": ["All"]}, TENANT_ID)) == 1
    )


def test_unrecognised_token_becomes_the_literal_unrecognised(synthetic):
    """A token the licensed procedure does not name can never look determinate."""
    entries = project_facts(
        SYNTHETIC_ID,
        {"mode": "TestWithoutNotifications", "teams_locations": ["All", "Nope"]},
        TENANT_ID,
    )
    by_name = {entry["field_name"]: entry for entry in entries}
    assert by_name["mode"]["observed_value"] == "unrecognised"
    assert by_name["teams_locations"]["member_tokens"] == ["all", "unrecognised"]


def test_unknown_collector_and_non_object_collection_project_nothing(keyed):
    assert project_facts("entra.roles.no_such_collector", {"x": 1}, TENANT_ID) is None
    assert (
        project_facts("entra.groups.groups", ["public_groups_count"], TENANT_ID) is None
    )
    assert project_facts("entra.groups.groups", None, TENANT_ID) is None


def test_no_projection_names_a_raw_object_key():
    """A whole-top-level-key digest is noise, so declaring one is impossible."""
    assert FORBIDDEN_SOURCE_KEYS == {
        "organization_config",
        "tenant",
        "teams_protection_policy",
        "atp_policy",
        "transport_config",
        "external_in_outlook_settings",
        "safe_links_policies",
        "anti_phish_policies",
    }
    declared = {
        spec.name
        for projection in FACT_PROJECTIONS.values()
        for spec in projection.fields
    }
    assert declared.isdisjoint(FORBIDDEN_SOURCE_KEYS)
    for name in sorted(FORBIDDEN_SOURCE_KEYS):
        with pytest.raises(ValueError, match="raw collector object key"):
            FieldSpec(name, "bool")


@pytest.mark.parametrize(
    "arguments,message",
    [
        (("mode", "scalar"), "field kind"),
        (("Mode", "bool"), "column constraint"),
        (("mode", "bool", ("enable",)), "vocabulary"),
        (("mode", "enum"), "declared vocabulary"),
        (("mode", "enum", ("Enable",)), "lowercase"),
        (("mode", "enum", ("unrecognised",)), "lowercase"),
        (("mode", "enum", ("e" * 39,)), "column constraint"),
    ],
)
def test_a_projection_cannot_declare_a_field_the_column_rejects(arguments, message):
    with pytest.raises(ValueError, match=message):
        FieldSpec(*arguments)


def test_projection_ids_and_field_names_match_the_column_constraints():
    for collector_id, projection in FACT_PROJECTIONS.items():
        assert projection.projection_id == f"{collector_id}/v1"
        assert len(projection.projection_id) <= 120
        assert len(collector_id) <= 120
        for spec in projection.fields:
            assert factprint.FIELD_NAME_PATTERN.fullmatch(spec.name)
            assert spec.kind in factprint.FIELD_KINDS


def _migrate(database):
    """Replace the hand-made worker fixture schema with the real migrated one."""
    backend = Path(__file__).resolve().parents[2] / "backend-api"
    with database.begin() as connection:
        connection.execute(text("DROP TABLE scan_result"))
        connection.execute(text("DROP TABLE scan"))
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": str(database.url).replace(
            "postgresql://", "postgresql+asyncpg://"
        ),
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
    }
    # nosec B603 B607 # fixed interpreter and Alembic arguments, disposable database
    migration = subprocess.run(  # nosec
        [
            "uv",
            "run",
            "--project",
            str(backend),
            "python",
            "-m",
            "alembic",
            "upgrade",
            "head",
        ],
        cwd=backend,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert migration.returncode == 0, migration.stdout + migration.stderr
    metadata = {"controls": [{"control_id": "1.2.1", "automation_status": "ready"}]}
    with database.begin() as connection:
        connection.execute(
            text("""INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
            VALUES (1,'user','synthetic@example.invalid','synthetic',true,false,true)""")
        )
        connection.execute(
            text("""INSERT INTO scan (id,user_id,framework,benchmark,version,status,selected_count,
            total_controls,semantics_version,metadata_snapshot,metadata_digest,correlation_id)
            VALUES (1,1,'cis','microsoft-365-foundations','v6.0.0','running',1,1,'phase3-v1',
            CAST(:metadata AS jsonb),:digest,:correlation)"""),
            {
                "metadata": json.dumps(metadata),
                "digest": hashlib.sha256(canonical_json(metadata).encode()).hexdigest(),
                "correlation": str(uuid4()),
            },
        )


def test_persist_is_idempotent(database, monkeypatch):
    """A redelivered Celery message cannot write a second observation."""
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", KEY_A)
    monkeypatch.setitem(factprint.FACT_PROJECTIONS, SYNTHETIC_ID, SYNTHETIC)
    _migrate(database)

    scalar = project_facts("entra.groups.groups", {"public_groups_count": 3}, TENANT_ID)
    members = project_facts(
        SYNTHETIC_ID,
        {"mode": "Enable", "teams_locations": ["All", "Selected"]},
        TENANT_ID,
    )
    assert len(scalar) == 1 and len(members) == 2

    def write():
        with Session(database) as session:
            written = persist_factprint(
                session,
                scan_id=1,
                control_id="1.2.1",
                collector_id="entra.groups.groups",
                fields=scalar,
            ) + persist_factprint(
                session,
                scan_id=1,
                control_id="1.2.2",
                collector_id=SYNTHETIC_ID,
                fields=members,
            )
            session.commit()
        return written

    assert write() == 3
    assert write() == 0

    with database.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT * FROM scan_result_factprint"
                    " ORDER BY control_id, field_name"
                )
            )
            .mappings()
            .all()
        )
    assert len(rows) == 3
    assert [row["field_name"] for row in rows] == [
        "public_groups_count",
        "mode",
        "teams_locations",
    ]
    assert all(row["factprint_schema"] == "phase8-factprint-v1" for row in rows)
    assert all(row["retention_policy_version"] == "phase8-draft-1" for row in rows)
    assert all(row["key_id"] == scalar[0]["key_id"] for row in rows)
    # recorded_at is timestamptz, so a bare now() is the correct expression.
    assert all(row["recorded_at"].tzinfo is not None for row in rows)
    scalar_row = rows[0]
    assert scalar_row["observed_value"] == 3
    assert scalar_row["member_digests"] is None
    assert scalar_row["member_tokens"] is None
    set_row = rows[2]
    assert set_row["observed_value"] is None
    assert set_row["member_tokens"] == ["all", "selected"]
    assert set_row["member_digests"] == members[1]["member_digests"]


# ---------------------------------------------------------------------------
# Tenant scoping. Without it, a server-wide key makes two tenants holding the
# same configuration produce the same digest, so a holder of the store could
# bucket tenants by configuration and -- controlling one tenant -- confirm
# another's values. These tests pin the property, not just the construction.
# ---------------------------------------------------------------------------

OTHER_TENANT_ID = "00000000-0000-0000-0000-0000000000bb"


def test_identical_configuration_in_two_tenants_produces_different_digests(synthetic):
    collected = {"mode": "Enable", "teams_locations": ["All"]}
    mine = project_facts(SYNTHETIC_ID, collected, TENANT_ID)
    theirs = project_facts(SYNTHETIC_ID, collected, OTHER_TENANT_ID)

    by_name = {entry["field_name"]: entry for entry in mine}
    other_by_name = {entry["field_name"]: entry for entry in theirs}
    assert set(by_name) == set(other_by_name)

    for name, entry in by_name.items():
        other = other_by_name[name]
        assert entry["value_digest"] != other["value_digest"], (
            f"{name}: identical configuration in two tenants produced the same "
            "value_digest, which is a cross-tenant confirmation oracle"
        )
        if entry["member_digests"] is not None:
            assert (
                entry["member_digests"] != other["member_digests"]
            ), f"{name}: member digests are comparable across tenants"


def test_digests_are_stable_for_the_same_tenant(synthetic):
    """Drift compares a tenant against itself, so the subkey must not move."""
    collected = {"mode": "Enable", "teams_locations": ["All"]}
    first = project_facts(SYNTHETIC_ID, collected, TENANT_ID)
    second = project_facts(SYNTHETIC_ID, collected, TENANT_ID)
    assert [e["value_digest"] for e in first] == [e["value_digest"] for e in second]
    assert [e["member_digests"] for e in first] == [e["member_digests"] for e in second]


def test_key_id_tracks_the_configured_key_not_the_tenant(synthetic):
    """One rotation is one visible key_id change across every tenant."""
    collected = {"mode": "Enable"}
    mine = project_facts(SYNTHETIC_ID, collected, TENANT_ID)
    theirs = project_facts(SYNTHETIC_ID, collected, OTHER_TENANT_ID)
    assert {e["key_id"] for e in mine} == {e["key_id"] for e in theirs}


@pytest.mark.parametrize("tenant", [None, "", "   ", 12345, b"tenant"])
def test_an_unidentified_tenant_writes_nothing(synthetic, tenant):
    """Never fall back to a cross-tenant-comparable digest."""
    assert project_facts(SYNTHETIC_ID, {"mode": "Enable"}, tenant) is None
