"""Configuration drift: comparability, the two event streams, and persistence.

Every fixture here is synthetic. No tenant value, credential or real identifier
appears in this module: the connection identity is a fixed synthetic GUID pair
and every digest is a sha256 of a literal label.
"""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import TextClause, create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from worker import drift
from worker.result_contract import TERMINAL_STATES
from worker.drift import (
    comparability_key,
    compare,
    connection_identity_digest,
    evaluate_scan_drift,
    event_key,
    observation_digest,
    observation_rows,
)

DRIFT_TABLES = (
    "drift_notification",
    "drift_event",
    "drift_run",
    "drift_baseline",
    "scan_result_factprint",
)

# A notification may not be able to carry evidence. These are the column names
# that would make that possible; drift_notification has none of them.
FORBIDDEN_NOTIFICATION_COLUMNS = frozenset(
    {
        "control_id",
        "fact_name",
        "previous_value",
        "current_value",
        "previous_digest",
        "current_digest",
        "member_ref",
        "collector_id",
        "message",
        "observed_value",
        "event_key",
        "evidence",
    }
)

# Scan columns whose value PostgreSQL now() misreads on a non-UTC server. The
# comparison must never order two observations by one of them.
FORBIDDEN_TIMESTAMP_COLUMNS = (
    "finished_at",
    "started_at",
    "last_progress_at",
    "deadline_at",
    "updated_at",
)

CONNECTION = {
    "tenant_id": "00000000-0000-4000-8000-000000000001",
    "client_id": "00000000-0000-4000-8000-000000000002",
    "sharepoint_admin_url": "https://synthetic-admin.sharepoint.example",
    "sharepoint_tenant_id": "synthetic",
    "sharepoint_certificate_alias": "default",
}

# 8.8.8 pins a severity the benchmark vocabulary does not contain and 9.9.9 is
# absent from the snapshot entirely; both must transcribe to informational.
METADATA = {
    "controls": [
        {"control_id": "1.1.1", "severity": "critical"},
        {"control_id": "1.2.1", "severity": "high"},
        {"control_id": "2.1.1", "severity": "medium"},
        {"control_id": "8.8.8", "severity": "catastrophic"},
    ]
}

SCAN_DEFAULTS = {
    "user_id": 1,
    "m365_connection_id": None,
    "framework": "cis",
    "benchmark": "microsoft-365-foundations",
    "version": "v6.0.0",
    "status": "completed",
    "semantics_version": "phase3-v1",
    "metadata_digest": "a" * 64,
    "policy_corpus_digest": "b" * 64,
    "metadata_snapshot": METADATA,
    "connection_snapshot": CONNECTION,
    "correlation_id": "00000000-0000-4000-8000-0000000000ff",
}

KEY_ID = "0123456789abcdef"


def digest(label: str) -> str:
    """A deterministic synthetic 64-hex digest standing in for a keyed one."""
    return hashlib.sha256(label.encode()).hexdigest()


def scan_row(scan_id: int, **overrides) -> dict:
    return {"id": scan_id, **SCAN_DEFAULTS, **overrides}


def baseline_row(scan: dict, **overrides) -> dict:
    row = {
        "id": 11,
        "user_id": scan["user_id"],
        "scan_id": scan["id"],
        "m365_connection_id": scan["m365_connection_id"],
        "framework": scan["framework"],
        "benchmark": scan["benchmark"],
        "version": scan["version"],
        "metadata_digest": scan["metadata_digest"],
        "policy_corpus_digest": scan["policy_corpus_digest"],
        "semantics_version": scan["semantics_version"],
        "connection_identity_digest": connection_identity_digest(
            scan["connection_snapshot"]
        ),
        "configuration_key": comparability_key("configuration", scan),
        "evaluation_key": comparability_key("evaluation", scan),
        "observation_digest": digest("baseline-observation"),
        "control_count": 3,
        "factprint_field_count": 3,
        "status": "active",
        "drift_version": drift.DRIFT_VERSION,
        "retention_policy_version": drift.RETENTION_POLICY_VERSION,
        # The fingerprint key the baseline's facts were produced under. The
        # production query selects it; the fixture must too, or the rotation
        # guard is silently untested.
        "key_id": KEY_ID,
    }
    row.update(overrides)
    return row


def result(control_id: str, status: str, reason_code: str | None = None) -> dict:
    return {
        "control_id": control_id,
        "status": status,
        "reason_code": reason_code,
        "selected": status != "skipped",
    }


def fact(
    control_id: str,
    field_name: str,
    value_digest: str,
    *,
    kind: str = "bool",
    observed: object = True,
    projection: str = "entra.groups.groups/v1",
    collector: str = "entra.groups.groups",
    members: list | None = None,
    tokens: list | None = None,
) -> dict:
    return {
        "control_id": control_id,
        "collector_id": collector,
        "projection_id": projection,
        "field_name": field_name,
        "field_kind": kind,
        "value_digest": value_digest,
        "member_digests": members,
        "member_tokens": tokens,
        "observed_value": None if kind == "enum_set" else observed,
        "key_id": KEY_ID,
    }


def observation(scan: dict, results=(), facts=()) -> dict:
    return {"scan": scan, "results": list(results), "facts": list(facts)}


def baseline_observation(scan: dict, results=(), facts=(), **overrides) -> dict:
    return {
        "baseline": baseline_row(scan, **overrides),
        **observation(scan, results, facts),
    }


def run(
    baseline_results=(),
    baseline_facts=(),
    current_results=(),
    current_facts=(),
    *,
    baseline_scan_id: int = 1,
    current_scan_id: int = 2,
    baseline_overrides: dict | None = None,
    current_overrides: dict | None = None,
):
    """Compare two synthetic observations that are comparable by construction."""
    previous = scan_row(baseline_scan_id, **(baseline_overrides or {}))
    current = scan_row(current_scan_id, **(current_overrides or {}))
    return compare(
        baseline_observation(previous, baseline_results, baseline_facts),
        observation(current, current_results, current_facts),
    )


def events_of(computation, event_class):
    return [e for e in computation.events if e["event_class"] == event_class]


# ---------------------------------------------------------------------------
# Comparability
# ---------------------------------------------------------------------------


def test_comparability_key_omits_policy_corpus_digest_on_the_configuration_axis():
    """A Rego edit cannot change tenant configuration, but it can change a verdict."""
    base = scan_row(1)
    edited = scan_row(1, policy_corpus_digest="c" * 64)
    assert comparability_key("configuration", base) == comparability_key(
        "configuration", edited
    )
    assert comparability_key("evaluation", base) != comparability_key(
        "evaluation", edited
    )
    # Absent, not null: a scan with no corpus digest at all still lands on the
    # same configuration key.
    assert comparability_key(
        "configuration", scan_row(1, policy_corpus_digest=None)
    ) == (comparability_key("configuration", base))


AXIS_MEMBERS = [
    ("user_id", {"user_id": 99}),
    ("m365_connection_id", {"m365_connection_id": 7}),
    ("framework", {"framework": "e8"}),
    ("benchmark", {"benchmark": "essential-eight"}),
    ("version", {"version": "v7.0.0"}),
    ("metadata_digest", {"metadata_digest": "c" * 64}),
    ("semantics_version", {"semantics_version": "phase4-v1"}),
] + [
    (
        f"connection_snapshot.{name}",
        {"connection_snapshot": {**CONNECTION, name: "moved"}},
    )
    for name in CONNECTION
]


@pytest.mark.parametrize(
    "override",
    [case for _, case in AXIS_MEMBERS],
    ids=[name for name, _ in AXIS_MEMBERS],
)
def test_comparability_key_changes_on_every_other_axis_member(override):
    base = scan_row(1)
    moved = scan_row(1, **override)
    for axis in ("configuration", "evaluation"):
        assert comparability_key(axis, base) != comparability_key(axis, moved)


@pytest.mark.parametrize(
    "override",
    [{"id": 900}, {"status": "failed"}, {"correlation_id": "other"}],
    ids=["id", "status", "correlation_id"],
)
def test_comparability_key_ignores_everything_outside_the_tuple(override):
    """Only the declared tuple decides comparability; nothing else leaks in."""
    base = scan_row(1)
    for axis in ("configuration", "evaluation"):
        assert comparability_key(axis, base) == comparability_key(
            axis, scan_row(1, **override)
        )


def test_comparability_key_rejects_an_unknown_axis():
    with pytest.raises(ValueError):
        comparability_key("everything", scan_row(1))


def test_connection_identity_digest_tolerates_a_missing_snapshot():
    assert connection_identity_digest(None) == connection_identity_digest({})
    assert connection_identity_digest(None) != connection_identity_digest(CONNECTION)


def test_scan_ordering_uses_the_surrogate_key_not_a_timestamp():
    """Ordering is scan.id, never a timestamp Phase 6 left naive.

    drift_run has its own started_at column, which this module writes; that one
    INSERT is removed before the grep so the assertion still means "no timestamp
    column is read or compared anywhere in the algorithm".
    """
    source = Path(drift.__file__).read_text(encoding="utf-8")
    outside_the_run_insert = source.replace(drift.INSERT_RUN.text, "")
    for name in FORBIDDEN_TIMESTAMP_COLUMNS:
        assert name not in outside_the_run_insert
        assert name not in drift.SELECT_SCAN.text
        assert name not in drift.SELECT_RESULTS.text
        assert name not in drift.SELECT_FACTS.text

    # And the behaviour the grep protects: a lower surrogate key is never newer.
    computation = run(current_scan_id=1, baseline_scan_id=5)
    assert not computation.configuration_comparable
    assert not computation.evaluation_comparable
    assert "scan_predates_baseline" in computation.axis_reasons["configuration"]
    assert "scan_predates_baseline" in computation.axis_reasons["evaluation"]


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"status": "running"}, "scan_not_completed"),
        ({"user_id": 42}, "scan_not_owned"),
        ({"semantics_version": "phase2-v1"}, "semantics_version_mismatch"),
    ],
)
def test_a_comparability_failure_is_recorded_never_skipped(overrides, reason):
    # Facts on both sides, so 'fingerprints_unavailable' cannot mask the reason
    # under test: this case is a genuinely incomparable pair of observations.
    computation = run(
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"), observed=False)],
        current_overrides=overrides,
    )
    assert reason in computation.axis_reasons["configuration"]
    assert reason in computation.axis_reasons["evaluation"]
    assert computation.status == "not_comparable"
    assert computation.events == ()
    assert computation.event_set_digest == run().event_set_digest


def test_every_recorded_reason_is_in_the_declared_vocabulary():
    computation = run(
        current_overrides={
            "status": "running",
            "user_id": 42,
            "policy_corpus_digest": "d" * 64,
        },
        baseline_scan_id=5,
        current_scan_id=1,
    )
    recorded = set(computation.axis_reasons["configuration"]) | set(
        computation.axis_reasons["evaluation"]
    )
    assert recorded
    assert recorded <= set(drift.COMPARABILITY_REASONS)


def test_no_facts_on_either_side_is_fingerprints_unavailable():
    """No key on the writing worker means no factprint row exists at all."""
    computation = run(
        baseline_results=[result("1.1.1", "passed")],
        current_results=[result("1.1.1", "passed")],
    )
    assert not computation.configuration_comparable
    assert computation.evaluation_comparable
    assert "fingerprints_unavailable" in computation.axis_reasons["configuration"]
    # The evaluation axis is fully live with no fingerprint key at all.
    assert computation.axis_reasons["evaluation"] == []
    assert computation.status == "completed"


def test_one_sided_facts_name_the_absent_side():
    computation = run(current_facts=[fact("1.1.1", "enabled", digest("x"))])
    assert "baseline_facts_absent" in computation.axis_reasons["configuration"]
    computation = run(baseline_facts=[fact("1.1.1", "enabled", digest("x"))])
    assert "current_facts_absent" in computation.axis_reasons["configuration"]


def test_a_baseline_from_another_drift_version_is_not_comparable():
    previous = scan_row(1)
    current = scan_row(2)
    computation = compare(
        baseline_observation(previous, drift_version="phase9-drift-v1"),
        observation(current),
    )
    assert "drift_version_mismatch" in computation.axis_reasons["configuration"]
    assert "drift_version_mismatch" in computation.axis_reasons["evaluation"]


def test_a_superseded_baseline_is_not_comparable():
    previous = scan_row(1)
    computation = compare(
        baseline_observation(previous, status="superseded"), observation(scan_row(2))
    )
    assert "baseline_not_active" in computation.axis_reasons["configuration"]


# ---------------------------------------------------------------------------
# The two streams
# ---------------------------------------------------------------------------


def test_configuration_and_evaluation_events_never_cross():
    """Facts moving cannot manufacture a verdict change, and vice versa."""
    facts_only = run(
        baseline_results=[result("1.1.1", "passed")],
        current_results=[result("1.1.1", "passed")],
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"), observed=False)],
    )
    assert [e["change_type"] for e in events_of(facts_only, "configuration")] == [
        "changed"
    ]
    assert events_of(facts_only, "evaluation") == []

    verdict_only = run(
        baseline_results=[result("1.1.1", "passed")],
        current_results=[result("1.1.1", "failed")],
        baseline_facts=[fact("1.1.1", "enabled", digest("same"))],
        current_facts=[fact("1.1.1", "enabled", digest("same"))],
    )
    assert events_of(verdict_only, "configuration") == []
    assert [e["change_type"] for e in events_of(verdict_only, "evaluation")] == [
        "status_changed"
    ]


def test_added_removed_changed_are_emitted_separately():
    computation = run(
        baseline_facts=[
            fact("1.2.1", "gone", digest("gone"), observed=True),
            fact("1.2.1", "moved", digest("moved-before"), observed=True),
        ],
        current_facts=[
            fact("1.2.1", "arrived", digest("arrived"), observed=False),
            fact("1.2.1", "moved", digest("moved-after"), observed=False),
        ],
    )
    by_field = {e["fact_name"]: e for e in events_of(computation, "configuration")}
    assert set(by_field) == {"gone", "moved", "arrived"}

    added = by_field["arrived"]
    assert added["change_type"] == "added"
    assert added["previous_value"] is None and added["current_value"] is False
    assert added["previous_digest"] is None
    assert added["current_digest"] == digest("arrived")

    removed = by_field["gone"]
    assert removed["change_type"] == "removed"
    assert removed["previous_value"] is True and removed["current_value"] is None
    assert removed["previous_digest"] == digest("gone")
    assert removed["current_digest"] is None

    changed = by_field["moved"]
    assert changed["change_type"] == "changed"
    assert changed["previous_value"] is True and changed["current_value"] is False
    assert changed["previous_digest"] == digest("moved-before")
    assert changed["current_digest"] == digest("moved-after")
    assert changed["member_ref"] is None
    # Every configuration event names the fact that moved; the CHECK constraint
    # ck_drift_event_fact_binding depends on it.
    assert all(e["fact_name"] for e in events_of(computation, "configuration"))


def test_an_identical_fact_emits_nothing():
    computation = run(
        baseline_facts=[fact("1.2.1", "enabled", digest("same"))],
        current_facts=[fact("1.2.1", "enabled", digest("same"))],
    )
    assert computation.events == ()
    assert computation.status == "completed"
    assert computation.controls_compared == 1


def test_enum_set_emits_one_event_per_member():
    kept, left, joined = digest("kept"), digest("left"), digest("joined")
    computation = run(
        baseline_facts=[
            fact(
                "1.2.1",
                "locations",
                digest("set-before"),
                kind="enum_set",
                members=[kept, left],
                tokens=["kept", "left"],
            )
        ],
        current_facts=[
            fact(
                "1.2.1",
                "locations",
                digest("set-after"),
                kind="enum_set",
                members=[kept, joined],
                tokens=["kept", "joined"],
            )
        ],
    )
    events = events_of(computation, "configuration")
    assert len(events) == 2
    by_type = {e["change_type"]: e for e in events}
    assert by_type["added"]["member_ref"] == joined
    assert by_type["added"]["current_value"] == "joined"
    assert by_type["added"]["previous_value"] is None
    assert by_type["removed"]["member_ref"] == left
    assert by_type["removed"]["previous_value"] == "left"
    assert by_type["removed"]["current_value"] is None
    # Two members moved, so the two events must be separable findings.
    assert by_type["added"]["event_key"] != by_type["removed"]["event_key"]


def test_enum_set_with_equal_members_but_a_moved_digest_is_one_unattributed_change():
    member = digest("only")
    computation = run(
        baseline_facts=[
            fact(
                "1.2.1",
                "locations",
                digest("set-before"),
                kind="enum_set",
                members=[member],
                tokens=["only"],
            )
        ],
        current_facts=[
            fact(
                "1.2.1",
                "locations",
                digest("set-after"),
                kind="enum_set",
                members=[member],
                tokens=["only"],
            )
        ],
    )
    events = events_of(computation, "configuration")
    assert len(events) == 1
    assert events[0]["change_type"] == "changed"
    assert events[0]["member_ref"] is None


def test_a_projection_change_skips_configuration_and_leaves_evaluation_alone():
    """A collector normalisation change is a code change, not tenant drift."""
    computation = run(
        baseline_results=[result("1.2.1", "passed")],
        current_results=[result("1.2.1", "failed")],
        baseline_facts=[
            fact("1.2.1", "enabled", digest("before"), projection="collector/v1")
        ],
        current_facts=[
            fact("1.2.1", "enabled", digest("after"), projection="collector/v2")
        ],
    )
    assert events_of(computation, "configuration") == []
    assert computation.controls_skipped["projection_changed"] == ["1.2.1"]
    assert [e["change_type"] for e in events_of(computation, "evaluation")] == [
        "status_changed"
    ]


@pytest.mark.parametrize(
    "baseline_facts,current_facts,reason",
    [
        ([], [], "facts_absent_both"),
        ([], [("1.2.1", "enabled")], "control_absent_baseline"),
        ([("1.2.1", "enabled")], [], "control_absent_current"),
    ],
)
def test_per_control_skip_reasons_are_recorded(baseline_facts, current_facts, reason):
    # One control always carries facts on both sides so the axis stays comparable.
    anchor_baseline = [fact("1.1.1", "enabled", digest("anchor"))]
    anchor_current = [fact("1.1.1", "enabled", digest("anchor"))]
    computation = run(
        baseline_results=[result("1.2.1", "passed")],
        current_results=[result("1.2.1", "passed")],
        baseline_facts=anchor_baseline
        + [fact(c, f, digest("b")) for c, f in baseline_facts],
        current_facts=anchor_current
        + [fact(c, f, digest("c")) for c, f in current_facts],
    )
    assert computation.controls_skipped.get(reason) == ["1.2.1"]


def test_an_observability_change_is_informational_not_a_configuration_change():
    """Unknown becoming known is not the tenant changing its configuration."""
    computation = run(
        baseline_facts=[fact("1.1.1", "enabled", digest("unknown"), observed=None)],
        current_facts=[fact("1.1.1", "enabled", digest("known"), observed=True)],
    )
    (event,) = events_of(computation, "configuration")
    assert event["change_type"] == "changed"
    assert event["severity"] == "informational"
    assert event["severity_basis"] == "observability_change"
    assert event["previous_value"] is None and event["current_value"] is True


def test_facts_identical_is_true_when_a_verdict_moves_with_unchanged_facts():
    """Same facts, different verdict is an engine or policy problem."""
    unchanged = run(
        baseline_results=[result("1.1.1", "passed", "policy_pass")],
        current_results=[result("1.1.1", "failed", "policy_fail")],
        baseline_facts=[fact("1.1.1", "enabled", digest("same"))],
        current_facts=[fact("1.1.1", "enabled", digest("same"))],
    )
    (event,) = events_of(unchanged, "evaluation")
    assert event["detail"]["facts_identical"] is True
    assert event["detail"]["previous_reason_code"] == "policy_pass"
    assert event["detail"]["current_reason_code"] == "policy_fail"
    assert event["previous_digest"] == event["current_digest"] is not None
    assert event["fact_name"] is None

    moved = run(
        baseline_results=[result("1.1.1", "passed")],
        current_results=[result("1.1.1", "failed")],
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"))],
    )
    (event,) = events_of(moved, "evaluation")
    assert event["detail"]["facts_identical"] is False


def test_facts_identical_is_false_when_a_side_has_no_facts():
    computation = run(
        baseline_results=[result("1.1.1", "passed")],
        current_results=[result("1.1.1", "failed")],
    )
    (event,) = events_of(computation, "evaluation")
    assert event["detail"]["facts_identical"] is False
    assert event["previous_digest"] is None and event["current_digest"] is None


@pytest.mark.parametrize(
    "previous,current,change_type",
    [
        ("passed", "indeterminate", "coverage_lost"),
        ("passed", "error", "coverage_lost"),
        ("failed", "not_assessable", "coverage_lost"),
        ("passed", "skipped", "coverage_lost"),
        ("indeterminate", "passed", "coverage_gained"),
        ("error", "failed", "coverage_gained"),
        ("passed", "failed", "status_changed"),
        ("indeterminate", "error", "status_changed"),
    ],
)
def test_coverage_lost_and_gained_are_first_class(previous, current, change_type):
    computation = run(
        baseline_results=[result("1.2.1", previous)],
        current_results=[result("1.2.1", current)],
    )
    (event,) = events_of(computation, "evaluation")
    assert event["change_type"] == change_type
    assert event["previous_value"] == previous
    assert event["current_value"] == current


def test_a_control_that_disappears_from_the_result_set_is_coverage_lost():
    computation = run(
        baseline_results=[result("1.2.1", "passed")],
        current_results=[],
    )
    (event,) = events_of(computation, "evaluation")
    assert event["change_type"] == "coverage_lost"
    assert event["current_value"] is None


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "control_id,severity,basis",
    [
        ("1.1.1", "critical", "benchmark_severity"),
        ("1.2.1", "high", "benchmark_severity"),
        ("2.1.1", "medium", "benchmark_severity"),
        ("8.8.8", "informational", "severity_unavailable"),
        ("9.9.9", "informational", "severity_unavailable"),
    ],
)
def test_severity_is_transcribed_from_the_pinned_snapshot(control_id, severity, basis):
    computation = run(
        baseline_facts=[fact(control_id, "enabled", digest("before"))],
        current_facts=[fact(control_id, "enabled", digest("after"), observed=False)],
    )
    (event,) = events_of(computation, "configuration")
    assert (event["severity"], event["severity_basis"]) == (severity, basis)


def test_a_missing_metadata_snapshot_never_invents_a_severity():
    computation = run(
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"), observed=False)],
        baseline_overrides={"metadata_snapshot": None},
        current_overrides={"metadata_snapshot": None},
    )
    (event,) = events_of(computation, "configuration")
    assert event["severity"] == "informational"
    assert event["severity_basis"] == "severity_unavailable"


@pytest.mark.parametrize(
    "previous,current,severity,basis",
    [
        ("passed", "failed", "critical", "evaluation_transition"),
        ("failed", "passed", "informational", "evaluation_transition"),
        ("passed", "indeterminate", "critical", "coverage_loss"),
        # A recovery is an observability CHANGE, not a coverage LOSS: a client
        # filtering severity_basis='coverage_loss' is asking what it stopped
        # being able to see, and must not be handed a gain.
        ("indeterminate", "passed", "informational", "observability_change"),
    ],
)
def test_evaluation_severity_is_directional(previous, current, severity, basis):
    """A regression carries the pinned severity; a recovery never does."""
    computation = run(
        baseline_results=[result("1.1.1", previous)],
        current_results=[result("1.1.1", current)],
    )
    (event,) = events_of(computation, "evaluation")
    assert (event["severity"], event["severity_basis"]) == (severity, basis)


# ---------------------------------------------------------------------------
# Keys, digests and limits
# ---------------------------------------------------------------------------


def test_event_key_is_stable_across_runs_and_unstable_across_baselines():
    arguments = (11, "1.1.1", "configuration", "changed", "enabled", None)
    assert event_key(*arguments) == event_key(*arguments)
    assert event_key(*arguments) != event_key(12, *arguments[1:])
    for position, replacement in enumerate(
        ["2.2.2", "evaluation", "added", "other", digest("member")], start=1
    ):
        moved = list(arguments)
        moved[position] = replacement
        assert event_key(*moved) != event_key(*arguments)

    # The same finding against the same baseline keeps its key when the current
    # scan changes, which is what lets an accepted_risk decision suppress it.
    first = run(
        current_scan_id=2,
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"), observed=False)],
    )
    second = run(
        current_scan_id=3,
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"), observed=False)],
    )
    assert [e["event_key"] for e in first.events] == [
        e["event_key"] for e in second.events
    ]
    assert first.event_set_digest == second.event_set_digest


def test_event_keys_are_full_length_hex():
    computation = run(
        baseline_facts=[fact("1.1.1", "enabled", digest("before"))],
        current_facts=[fact("1.1.1", "enabled", digest("after"), observed=False)],
    )
    for event in computation.events:
        assert re.fullmatch(r"[0-9a-f]{64}", event["event_key"])


def test_observation_digest_ignores_row_order():
    results = [result("1.1.1", "passed"), result("1.2.1", "failed")]
    facts = [
        fact("1.1.1", "enabled", digest("a")),
        fact("1.2.1", "enabled", digest("b")),
    ]
    forward = observation_digest(observation_rows(results, facts))
    reverse = observation_digest(observation_rows(results[::-1], facts[::-1]))
    assert forward == reverse
    moved = observation_digest(
        observation_rows(results, [fact("1.1.1", "enabled", digest("c")), facts[1]])
    )
    assert moved != forward


def test_event_limit_produces_a_run_with_no_events(monkeypatch):
    monkeypatch.setattr(drift.settings, "DRIFT_MAX_EVENTS_PER_RUN", 1)
    computation = run(
        baseline_facts=[
            fact("1.1.1", "enabled", digest("b1")),
            fact("1.2.1", "enabled", digest("b2")),
        ],
        current_facts=[
            fact("1.1.1", "enabled", digest("c1"), observed=False),
            fact("1.2.1", "enabled", digest("c2"), observed=False),
        ],
    )
    assert computation.status == "event_limit_exceeded"
    assert computation.events == ()
    assert computation.suppressed_event_count == 2
    assert computation.event_counts == {"configuration": {}, "evaluation": {}}


def test_event_counts_group_by_class_and_severity():
    computation = run(
        baseline_results=[result("1.1.1", "passed")],
        current_results=[result("1.1.1", "failed")],
        baseline_facts=[fact("1.2.1", "enabled", digest("before"))],
        current_facts=[fact("1.2.1", "enabled", digest("after"), observed=False)],
    )
    assert computation.event_counts == {
        "configuration": {"high": 1},
        "evaluation": {"critical": 1},
    }


def test_compare_needs_no_database_and_only_plain_dicts():
    computation = compare(
        {
            "baseline": {
                "id": 1,
                "user_id": 1,
                "scan_id": 1,
                "status": "active",
                "drift_version": drift.DRIFT_VERSION,
                "configuration_key": comparability_key("configuration", scan_row(1)),
                "evaluation_key": comparability_key("evaluation", scan_row(1)),
            },
            "results": [],
            "facts": [],
        },
        {"scan": scan_row(2), "results": [], "facts": []},
    )
    # No fingerprint key on the writing worker gates the configuration axis
    # only; the evaluation axis stays fully live, so the run still completes.
    assert computation.status == "completed"
    assert not computation.configuration_comparable
    assert computation.axis_reasons["configuration"] == ["fingerprints_unavailable"]
    assert computation.evaluation_comparable
    assert computation.events == ()


# ---------------------------------------------------------------------------
# Source-level guarantees
# ---------------------------------------------------------------------------


def test_no_rating_or_result_is_written():
    """Every statement in this module is a SELECT or a drift-table INSERT.

    Enumerating the module's own compiled statements is stronger than grepping
    prose: a new statement cannot be added anywhere in the module without
    appearing here, and 'FOR UPDATE' row locking is not mistaken for a write.
    """
    statements = [
        value.text for value in vars(drift).values() if isinstance(value, TextClause)
    ]
    assert len(statements) >= 8
    written = set()
    for sql in statements:
        words = " ".join(sql.lower().split()).split()
        assert words[0] in ("select", "insert"), sql
        if words[0] == "insert":
            assert words[1] == "into", sql
            written.add(words[2])
    assert written == {"drift_run", "drift_event", "drift_notification"}

    source = Path(drift.__file__).read_text(encoding="utf-8").lower()
    for table in ("scan", "scan_result", "scan_result_factprint", "scan_dispatch"):
        for statement in ("insert into", "update", "delete from"):
            assert not re.search(rf"{statement}\s+\"?{table}\b", source)
    # No rating, score or mapping vocabulary reaches this module at all.
    for name in (
        "compliance_score",
        "coverage_score",
        "mapping_id",
        "mapping_digest",
        "mapping_snapshot",
        "soc2",
    ):
        assert name not in source


def test_the_module_imports_nothing_from_the_backend():
    source = Path(drift.__file__).read_text(encoding="utf-8")
    assert "from app." not in source and "import app" not in source


def test_the_status_vocabulary_partitions_the_phase_three_contract():
    """A new Phase 3 status cannot slip through unclassified."""
    covered = drift.ASSESSED | drift.VISIBLE_UNASSESSED | drift.OUT_OF_SCOPE
    assert covered == set(TERMINAL_STATES) | {"pending"}
    assert not drift.ASSESSED & drift.VISIBLE_UNASSESSED
    assert not drift.ASSESSED & drift.OUT_OF_SCOPE
    assert not drift.VISIBLE_UNASSESSED & drift.OUT_OF_SCOPE


@pytest.mark.parametrize("status", ["pass", "PASSED", "compliant", "", "ok"])
def test_an_unrecognised_status_is_never_read_as_an_assessment(status):
    """Nothing becomes an assessment, or a coverage gain, by being unknown."""
    computation = run(
        baseline_results=[result("1.2.1", "indeterminate")],
        current_results=[result("1.2.1", status)],
    )
    changes = {e["change_type"] for e in events_of(computation, "evaluation")}
    assert "coverage_gained" not in changes
    assert changes == {"status_changed"}


# ---------------------------------------------------------------------------
# Persistence, against a real migrated PostgreSQL.
# ---------------------------------------------------------------------------


def _alembic(database):
    backend = Path(__file__).resolve().parents[2] / "backend-api"
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
        timeout=180,
    )
    assert migration.returncode == 0, migration.stdout + migration.stderr


@pytest.fixture(scope="module")
def migrated():
    url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not url:
        pytest.skip("Set MIGRATION_TEST_ADMIN_URL for disposable PostgreSQL tests")
    if "@127.0.0.1:" not in url:
        pytest.fail("Only loopback test databases are allowed")
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    name = "autoaudit_drift_test_" + uuid4().hex
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = create_engine(url.rsplit("/", 1)[0] + "/" + name)
    try:
        _alembic(engine)
        yield engine
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def database(migrated):
    """A migrated database emptied of every row this module can see.

    TRUNCATE is DDL and does not fire the append-only row triggers, so the
    Phase 8 history tables can be cleared between cases without weakening them.
    """
    with migrated.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE drift_notification, drift_event, drift_run, drift_baseline,"
                ' scan_result_factprint, scan_result, scan, "user"'
                " RESTART IDENTITY CASCADE"
            )
        )
        connection.execute(
            text("""INSERT INTO "user" (id,role,email,hashed_password,is_active,
            is_superuser,is_verified)
            VALUES (1,'user','synthetic@example.invalid','synthetic',true,false,true)""")
        )
    return migrated


INSERT_SCAN = text("""
    INSERT INTO scan (id,user_id,framework,benchmark,version,status,selected_count,
        total_controls,semantics_version,metadata_snapshot,metadata_digest,
        policy_corpus_digest,connection_snapshot,correlation_id)
    VALUES (:id,:user_id,:framework,:benchmark,:version,:status,3,3,
        :semantics_version,CAST(:metadata_snapshot AS jsonb),:metadata_digest,
        :policy_corpus_digest,CAST(:connection_snapshot AS jsonb),:correlation_id)
""")

INSERT_RESULT = text("""
    INSERT INTO scan_result (scan_id,control_id,status,selected,reason_code)
    VALUES (:scan_id,:control_id,:status,:selected,:reason_code)
""")

INSERT_FACT = text("""
    INSERT INTO scan_result_factprint (scan_id,control_id,collector_id,projection_id,
        field_name,field_kind,value_digest,member_digests,member_tokens,
        observed_value,factprint_schema,key_id,retention_policy_version,recorded_at)
    VALUES (:scan_id,:control_id,:collector_id,:projection_id,:field_name,
        :field_kind,:value_digest,CAST(:member_digests AS jsonb),
        CAST(:member_tokens AS jsonb),CAST(:observed_value AS jsonb),
        'phase8-factprint-v1',:key_id,'phase8-draft-1',now())
""")

INSERT_BASELINE = text("""
    INSERT INTO drift_baseline (user_id,scan_id,framework,benchmark,version,
        metadata_digest,policy_corpus_digest,semantics_version,
        connection_identity_digest,configuration_key,evaluation_key,
        observation_digest,control_count,factprint_field_count,status,
        drift_version,retention_policy_version,established_at)
    VALUES (:user_id,:scan_id,:framework,:benchmark,:version,:metadata_digest,
        :policy_corpus_digest,:semantics_version,:connection_identity_digest,
        :configuration_key,:evaluation_key,:observation_digest,:control_count,
        :factprint_field_count,'active',:drift_version,:retention_policy_version,
        now())
    RETURNING id
""")


def seed_scan(connection, scan: dict, results=(), facts=()) -> None:
    connection.execute(
        INSERT_SCAN,
        {
            **{
                key: scan[key]
                for key in (
                    "id",
                    "user_id",
                    "framework",
                    "benchmark",
                    "version",
                    "status",
                    "semantics_version",
                    "metadata_digest",
                    "policy_corpus_digest",
                    "correlation_id",
                )
            },
            "metadata_snapshot": json.dumps(scan["metadata_snapshot"]),
            "connection_snapshot": json.dumps(scan["connection_snapshot"]),
        },
    )
    for row in results:
        connection.execute(INSERT_RESULT, {"scan_id": scan["id"], **row})
    for row in facts:
        connection.execute(
            INSERT_FACT,
            {
                "scan_id": scan["id"],
                **{
                    key: row[key]
                    for key in (
                        "control_id",
                        "collector_id",
                        "projection_id",
                        "field_name",
                        "field_kind",
                        "value_digest",
                        "key_id",
                    )
                },
                "member_digests": (
                    None
                    if row["member_digests"] is None
                    else json.dumps(row["member_digests"])
                ),
                "member_tokens": (
                    None
                    if row["member_tokens"] is None
                    else json.dumps(row["member_tokens"])
                ),
                "observed_value": (
                    None
                    if row["observed_value"] is None
                    else json.dumps(row["observed_value"])
                ),
            },
        )


def seed_baseline(connection, scan: dict) -> int:
    row = baseline_row(scan)
    return connection.execute(
        INSERT_BASELINE,
        {
            key: row[key]
            for key in (
                "user_id",
                "scan_id",
                "framework",
                "benchmark",
                "version",
                "metadata_digest",
                "policy_corpus_digest",
                "semantics_version",
                "connection_identity_digest",
                "configuration_key",
                "evaluation_key",
                "observation_digest",
                "control_count",
                "factprint_field_count",
                "drift_version",
                "retention_policy_version",
            )
        },
    ).scalar_one()


def count(database, table: str) -> int:
    with database.connect() as connection:
        return connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()


def seed_pair(database, *, with_baseline=True, current_overrides=None):
    """A baseline scan and a later scan whose facts and verdict both moved."""
    previous = scan_row(1)
    current = scan_row(2, **(current_overrides or {}))
    with database.begin() as connection:
        seed_scan(
            connection,
            previous,
            results=[result("1.1.1", "passed"), result("1.2.1", "passed")],
            facts=[
                fact("1.1.1", "enabled", digest("before")),
                fact("1.2.1", "enabled", digest("stable")),
            ],
        )
        seed_scan(
            connection,
            current,
            results=[result("1.1.1", "passed"), result("1.2.1", "failed")],
            facts=[
                fact("1.1.1", "enabled", digest("after"), observed=False),
                fact("1.2.1", "enabled", digest("stable")),
            ],
        )
        return seed_baseline(connection, previous) if with_baseline else None


def test_no_baseline_writes_nothing(database):
    seed_pair(database, with_baseline=False)
    with Session(database) as session:
        outcome = evaluate_scan_drift(session, 2)
        session.commit()
    assert outcome == {"status": "no_baseline", "scan_id": 2}
    for table in DRIFT_TABLES:
        if table != "scan_result_factprint":
            assert count(database, table) == 0


def test_an_unfinished_scan_records_nothing(database):
    seed_pair(database, current_overrides={"status": "running"})
    with Session(database) as session:
        outcome = evaluate_scan_drift(session, 2)
        session.commit()
    assert outcome["status"] == "scan_not_completed"
    assert count(database, "drift_run") == 0


def test_a_completed_run_records_both_streams(database):
    baseline_id = seed_pair(database)
    with Session(database) as session:
        outcome = evaluate_scan_drift(session, 2)
        session.commit()
    assert outcome["status"] == "completed"
    assert outcome["baseline_id"] == baseline_id
    assert outcome["event_count"] == 2

    with database.connect() as connection:
        run_row = connection.execute(text("SELECT * FROM drift_run")).mappings().one()
        events = (
            connection.execute(
                text("SELECT * FROM drift_event ORDER BY event_class, control_id")
            )
            .mappings()
            .all()
        )
    assert run_row["status"] == "completed"
    assert run_row["trigger"] == "scan_finalised"
    assert run_row["configuration_comparable"] and run_row["evaluation_comparable"]
    assert run_row["drift_version"] == drift.DRIFT_VERSION
    assert run_row["retention_policy_version"] == drift.RETENTION_POLICY_VERSION
    assert run_row["key_id"] == KEY_ID
    assert run_row["started_at"].tzinfo is not None
    assert run_row["completed_at"].tzinfo is not None
    assert [(e["event_class"], e["change_type"]) for e in events] == [
        ("configuration", "changed"),
        ("evaluation", "status_changed"),
    ]
    configuration, evaluation = events
    assert configuration["control_id"] == "1.1.1"
    assert configuration["fact_name"] == "enabled"
    assert configuration["previous_value"] is True
    assert configuration["current_value"] is False
    assert evaluation["fact_name"] is None
    assert evaluation["detail"]["facts_identical"] is True
    assert evaluation["previous_value"] == "passed"
    assert evaluation["current_value"] == "failed"


def test_duplicate_run_is_ignored(database):
    seed_pair(database)
    outcomes = []
    for _ in range(2):
        with Session(database) as session:
            outcomes.append(evaluate_scan_drift(session, 2))
            session.commit()
    assert outcomes[0]["status"] == "completed"
    assert outcomes[1] == {
        "status": "ignored",
        "scan_id": 2,
        "baseline_id": outcomes[0]["baseline_id"],
    }
    assert count(database, "drift_run") == 1
    assert count(database, "drift_event") == 2


def test_event_limit_writes_zero_events(database, monkeypatch):
    seed_pair(database)
    monkeypatch.setattr(drift.settings, "DRIFT_MAX_EVENTS_PER_RUN", 1)
    with Session(database) as session:
        outcome = evaluate_scan_drift(session, 2)
        session.commit()
    assert outcome["status"] == "event_limit_exceeded"
    assert count(database, "drift_event") == 0
    with database.connect() as connection:
        row = connection.execute(text("SELECT * FROM drift_run")).mappings().one()
    assert row["event_count"] == 0
    assert row["event_counts"] == {"configuration": {}, "evaluation": {}}


def test_notification_payload_contains_no_evidence(database):
    seed_pair(database)
    with Session(database) as session:
        evaluate_scan_drift(session, 2)
        session.commit()
    with database.connect() as connection:
        rows = (
            connection.execute(text("SELECT * FROM drift_notification"))
            .mappings()
            .all()
        )
    assert rows
    for row in rows:
        assert not set(row.keys()) & FORBIDDEN_NOTIFICATION_COLUMNS
        assert row["channel"] == "inapp"
        assert row["scope"] in ("event", "run")
        assert row["action"] == "raised" and row["state_after"] == "open"
        assert row["revision_number"] == 1
        assert row["user_id"] == 1
        assert set(row["summary_counts"]) == {"configuration", "evaluation"}
        for bucket in row["summary_counts"].values():
            assert set(bucket) <= {
                "critical",
                "high",
                "medium",
                "low",
                "informational",
            }
        assert row["summary_code"] in {
            drift.SUMMARY_CONFIGURATION_CRITICAL,
            drift.SUMMARY_CONFIGURATION_HIGH,
            drift.SUMMARY_COVERAGE_LOST,
            drift.SUMMARY_EVALUATION_STATUS_CHANGED,
            drift.SUMMARY_RUN_NOT_COMPARABLE,
            drift.SUMMARY_RUN_FINGERPRINTS_UNAVAILABLE,
        }
        # Nothing in the row's text may echo a control id or a fact name.
        rendered = json.dumps({k: str(v) for k, v in row.items()})
        assert "1.1.1" not in rendered and "enabled" not in rendered


def test_a_thread_is_raised_once_and_never_reopened(database):
    """An accepted_risk decision must suppress the same finding on every run."""
    seed_pair(database)
    with Session(database) as session:
        evaluate_scan_drift(session, 2)
        session.commit()
    with database.connect() as connection:
        threads = set(
            connection.execute(
                text("SELECT thread_key FROM drift_notification WHERE scope='event'")
            ).scalars()
        )
        event_keys = set(
            connection.execute(text("SELECT event_key FROM drift_event")).scalars()
        )
        codes = set(
            connection.execute(
                text("SELECT summary_code FROM drift_notification")
            ).scalars()
        )
    # The thread key IS the event key, which is how the backend's remediation
    # verification joins a thread to the events of a later run.
    assert threads == event_keys
    assert codes == {
        drift.SUMMARY_CONFIGURATION_CRITICAL,
        drift.SUMMARY_EVALUATION_STATUS_CHANGED,
    }

    # A third scan reproducing the same finding must not raise a second thread.
    third = scan_row(3)
    with database.begin() as connection:
        seed_scan(
            connection,
            third,
            results=[result("1.1.1", "passed"), result("1.2.1", "failed")],
            facts=[
                fact("1.1.1", "enabled", digest("after"), observed=False),
                fact("1.2.1", "enabled", digest("stable")),
            ],
        )
    with Session(database) as session:
        outcome = evaluate_scan_drift(session, 3, trigger="api_request")
        session.commit()
    assert outcome["status"] == "completed"
    assert outcome["event_count"] == 2
    assert outcome["notifications_raised"] == 0
    assert count(database, "drift_run") == 2
    assert count(database, "drift_event") == 4
    assert count(database, "drift_notification") == 2


def test_a_not_comparable_run_raises_a_run_scope_thread(database):
    seed_pair(database, current_overrides={"metadata_digest": "f" * 64})
    with Session(database) as session:
        outcome = evaluate_scan_drift(session, 2, baseline_id=1)
        session.commit()
    assert outcome["status"] == "not_comparable"
    with database.connect() as connection:
        row = (
            connection.execute(text("SELECT * FROM drift_notification"))
            .mappings()
            .one()
        )
    assert row["scope"] == "run"
    assert row["drift_event_id"] is None
    assert row["routing_rule"] == "owner_not_comparable"
    assert row["summary_code"] == drift.SUMMARY_RUN_NOT_COMPARABLE
    assert row["severity"] == "informational"
    assert count(database, "drift_event") == 0


def test_an_unknown_trigger_is_refused(database):
    seed_pair(database)
    with Session(database) as session:
        with pytest.raises(ValueError):
            evaluate_scan_drift(session, 2, trigger="cron")
    assert count(database, "drift_run") == 0


def test_a_check_violation_is_never_reported_as_an_ignored_duplicate(
    database, monkeypatch
):
    """A defect must surface, not hide behind the redelivery no-op."""
    seed_pair(database)
    original = drift._event

    def poisoned(*arguments):
        event = original(*arguments)
        # ck_drift_event_severity rejects this; the write must raise rather than
        # be swallowed by the duplicate-delivery branch.
        event["severity"] = "apocalyptic"
        return event

    monkeypatch.setattr(drift, "_event", poisoned)
    with Session(database) as session:
        with pytest.raises(IntegrityError):
            evaluate_scan_drift(session, 2)
        session.rollback()
    assert count(database, "drift_run") == 0
    assert count(database, "drift_event") == 0


# ---------------------------------------------------------------------------
# Fingerprint key rotation. Every value_digest is an HMAC under the configured
# key, so a rotation changes every digest even when the tenant is untouched.
# Comparing across a rotation would manufacture a configuration event for every
# declared fact. It must be an honest "cannot compare" instead.
# ---------------------------------------------------------------------------

ROTATED_KEY_ID = "fedcba9876543210"


def test_key_rotation_is_not_comparable_rather_than_drift():
    computation = run(
        baseline_results=[result("1.1.1", "passed")],
        baseline_facts=[fact("1.1.1", "audit_disabled", digest("under-key-1"))],
        current_results=[result("1.1.1", "passed")],
        # Same tenant, same value; only the key that fingerprinted it moved, so
        # the digest differs and the row records the new key_id.
        current_facts=[
            dict(
                fact("1.1.1", "audit_disabled", digest("under-key-2")),
                key_id=ROTATED_KEY_ID,
            )
        ],
    )
    assert computation.configuration_comparable is False
    assert "fingerprint_key_rotated" in computation.axis_reasons["configuration"]
    assert events_of(computation, "configuration") == []
    # The evaluation axis does not depend on the fingerprint key at all.
    assert computation.evaluation_comparable is True


def test_unrotated_key_still_compares_configuration():
    computation = run(
        baseline_results=[result("1.1.1", "passed")],
        baseline_facts=[fact("1.1.1", "audit_disabled", digest("before"))],
        current_results=[result("1.1.1", "passed")],
        current_facts=[fact("1.1.1", "audit_disabled", digest("after"))],
    )
    assert computation.configuration_comparable is True
    assert "fingerprint_key_rotated" not in computation.axis_reasons["configuration"]
    assert len(events_of(computation, "configuration")) == 1
