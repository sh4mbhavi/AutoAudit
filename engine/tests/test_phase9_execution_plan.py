"""Collect once per collector, fan out to every policy that consumes it.

The census this phase exists for: 69 ready CIS v6.0.0 controls resolve to 43
distinct collectors, so a full scan re-collected 26 payloads it already held.
These tests pin the plan that removes that, and the properties a shared
collection must not lose -- per-control provenance, per-control results,
per-control factprints, and error isolation between policies that share evidence.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from worker import tasks
from worker.execution_plan import (
    COLLECTION_TASK,
    CONTROL_TASK,
    build_collection_plan,
    collection_dispatch_id,
    control_dispatch_id,
    index_controls,
    plan_summary,
)

METADATA = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "policies/cis/microsoft-365-foundations/v6.0.0/metadata.json"
    ).read_text(encoding="utf-8")
)

READY = [
    control
    for control in METADATA["controls"]
    if control["automation_status"] == "ready"
]


def _pairs(controls):
    return [
        ({"id": index + 1, "control_id": control["control_id"]}, control)
        for index, control in enumerate(controls)
    ]


# ---------------------------------------------------------------------------
# The census
# ---------------------------------------------------------------------------


def test_a_full_benchmark_scan_plans_one_collection_per_distinct_collector():
    """PERF-01, stated as a property rather than a number in a document."""
    groups, unplannable = build_collection_plan(_pairs(READY))
    distinct = {control["data_collector_id"] for control in READY}
    assert not unplannable
    assert len(READY) == 69
    assert len(distinct) == 43
    assert len(groups) == len(distinct)
    summary = plan_summary(groups)
    assert summary == {
        "collections": 43,
        "controls": 69,
        "shared_collections": 14,
    }
    # 69 controls, 43 collections: 26 collections that used to happen and no
    # longer do. Every control is still planned exactly once.
    assert summary["controls"] - summary["collections"] == 26
    planned = [member.control_id for group in groups for member in group.members]
    assert sorted(planned) == sorted(control["control_id"] for control in READY)
    assert len(planned) == len(set(planned))


def test_the_plan_is_deterministic_and_totally_ordered():
    groups, _ = build_collection_plan(_pairs(READY))
    again, _ = build_collection_plan(_pairs(list(reversed(READY))))
    assert [group.collector_id for group in groups] == sorted(
        group.collector_id for group in groups
    )
    assert [group.collector_id for group in groups] == [
        group.collector_id for group in again
    ]
    for group in groups:
        assert [member.control_id for member in group.members] == sorted(
            member.control_id for member in group.members
        )


def test_every_group_member_carries_its_own_policy_file():
    groups, _ = build_collection_plan(_pairs(READY))
    by_control = {control["control_id"]: control for control in READY}
    for group in groups:
        for member in group.members:
            assert member.policy_file == by_control[member.control_id]["policy_file"]
            assert member.policy_file is not None


def test_a_control_without_a_collector_is_returned_not_dropped():
    groups, unplannable = build_collection_plan(
        [
            ({"id": 1, "control_id": "1.1.1"}, {"data_collector_id": "entra.a"}),
            ({"id": 2, "control_id": "1.1.2"}, {"data_collector_id": None}),
            ({"id": 3, "control_id": "1.1.3"}, {}),
        ]
    )
    assert [group.collector_id for group in groups] == ["entra.a"]
    assert [row["id"] for row in unplannable] == [2, 3]


def test_dispatch_identity_is_deterministic_and_distinct_per_key():
    assert collection_dispatch_id(7, "entra.a") == collection_dispatch_id(7, "entra.a")
    assert collection_dispatch_id(7, "entra.a") != collection_dispatch_id(8, "entra.a")
    assert collection_dispatch_id(7, "entra.a") != collection_dispatch_id(7, "entra.b")
    # A collection row and a control row of the same scan can never collide.
    assert collection_dispatch_id(7, "entra.a") != control_dispatch_id(7, 1)


def test_index_controls_tolerates_a_corrupt_snapshot():
    assert index_controls(None) == {}
    assert index_controls({"controls": "not a list"}) == {}
    assert index_controls({"controls": [{"no_control_id": True}, 7]}) == {}


def test_task_names_are_the_ones_the_dispatcher_publishes():
    assert COLLECTION_TASK == "worker.tasks.evaluate_collection"
    assert CONTROL_TASK == "worker.tasks.evaluate_control"
    assert COLLECTION_TASK in tasks.celery_app.tasks
    assert CONTROL_TASK in tasks.celery_app.tasks


# ---------------------------------------------------------------------------
# Fan-out execution
# ---------------------------------------------------------------------------

CREDENTIALS = {
    "tenant_id": "synthetic",
    "client_id": "synthetic",
    "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
}


def _evaluate(members, collect=None, evaluate=None, capture=None):
    """Run the real group helper with a synthetic collector and OPA."""
    from collectors import graph_client, registry
    from opa_client import opa_client

    collected = {"synthetic": True}
    collector = type(
        "Collector",
        (),
        {"collect": collect or AsyncMock(return_value=collected)},
    )()
    result = MagicMock()
    result.opa_version = "synthetic"
    result.result.model_dump.return_value = {
        "compliant": True,
        "message": "ok",
        "details": {},
        "affected_resources": [],
    }
    with (
        patch.object(registry, "get_collector", return_value=collector),
        patch.object(graph_client, "GraphClient", lambda **_: object()),
        patch.object(
            tasks, "capture_policy", capture or (lambda *_: "package synthetic")
        ),
        patch.object(tasks, "engine_identity", lambda: {"engine_git_sha": "a" * 40}),
        patch.object(opa_client, "runtime_version", AsyncMock(return_value="1.20.2")),
        patch.object(
            opa_client,
            "evaluate_snapshot",
            evaluate or AsyncMock(return_value=result),
        ),
    ):
        return asyncio.run(
            tasks._evaluate_collection_async(
                collector_id="entra.synthetic",
                members=members,
                credentials=dict(CREDENTIALS),
                framework="cis",
                benchmark="microsoft-365-foundations",
                version="v6.0.0",
                scan_context={"metadata_digest": "d", "correlation_id": "synthetic"},
            )
        )


MEMBERS = [("1.1.1", "a.rego"), ("1.1.2", "b.rego"), ("1.1.3", "c.rego")]


def test_one_collection_serves_every_member():
    collect = AsyncMock(return_value={"synthetic": True})
    outcomes = _evaluate(MEMBERS, collect=collect)
    assert collect.await_count == 1
    assert sorted(outcomes) == ["1.1.1", "1.1.2", "1.1.3"]
    digests = {outcome["provenance"]["input_digest"] for outcome in outcomes.values()}
    assert len(digests) == 1 and next(iter(digests))


def test_every_member_keeps_its_own_provenance_record():
    outcomes = _evaluate(MEMBERS)
    for control_id, policy_file in MEMBERS:
        provenance = outcomes[control_id]["provenance"]
        assert provenance["control_id"] == control_id
        assert provenance["policy_file"] == policy_file
        assert provenance["collector_id"] == "entra.synthetic"
        assert provenance["provenance_status"] == "captured"
        assert provenance["policy_digest"]
        assert provenance["opa_version"]
        assert provenance["evaluation_started_at"] and provenance["evaluated_at"]
    # The collection genuinely was shared, and the record says so: one window.
    windows = {
        (
            outcome["provenance"]["collection_started_at"],
            outcome["provenance"]["collection_completed_at"],
        )
        for outcome in outcomes.values()
    }
    assert len(windows) == 1


def test_a_failing_policy_does_not_fail_the_policies_that_share_its_evidence():
    """The plan's own acceptance criterion, exercised end to end."""
    good = MagicMock()
    good.opa_version = "synthetic"
    good.result.model_dump.return_value = {
        "compliant": True,
        "message": "ok",
        "details": {},
        "affected_resources": [],
    }

    async def evaluate(package_path, *_):
        if package_path.endswith("control_1_1_2"):
            raise ValueError("synthetic policy failure")
        return good

    outcomes = _evaluate(MEMBERS, evaluate=AsyncMock(side_effect=evaluate))
    assert outcomes["1.1.1"]["compliant"] is True
    assert outcomes["1.1.3"]["compliant"] is True
    failure = outcomes["1.1.2"]
    assert isinstance(failure, tasks.EvaluationFailure)
    assert failure.reason_code == "evaluation_error"
    assert failure.provenance["control_id"] == "1.1.2"
    assert failure.provenance["provenance_status"] == "incomplete"


def test_an_evaluator_that_fails_for_everyone_fails_the_group_so_it_can_retry():
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, evaluate=AsyncMock(side_effect=RuntimeError("opa down")))
    assert failure.value.reason_code == "evaluation_error"
    assert failure.value.retryable is True
    # Every member of the group carries its own record of the same failure.
    assert sorted(failure.value.provenances) == ["1.1.1", "1.1.2", "1.1.3"]


def test_a_failed_collection_fails_every_member_with_its_own_provenance():
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, collect=AsyncMock(side_effect=RuntimeError("tenant down")))
    assert failure.value.reason_code == "collection_error"
    assert sorted(failure.value.provenances) == ["1.1.1", "1.1.2", "1.1.3"]
    for control_id, provenance in failure.value.provenances.items():
        assert provenance["control_id"] == control_id
        assert provenance["provenance_status"] == "incomplete"


def test_an_error_envelope_is_a_group_failure_and_is_not_retried():
    """Anti-pattern guard: deterministic failures must not be retried.

    A tenant whose Global Administrator role object is absent makes
    entra.roles.privileged_roles return an error envelope. Before Phase 9 that
    cost four full collections and four minutes of Celery backoff before
    settling on exactly the same terminal error.
    """
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, collect=AsyncMock(return_value={"error": "absent"}))
    assert failure.value.reason_code == "collection_error"
    assert failure.value.retryable is False


@pytest.mark.parametrize("status", [400, 403, 404, 409, 422])
def test_authorization_and_invalid_request_answers_are_not_retried(status):
    request = httpx.Request("GET", "https://graph.microsoft.com/v1.0/users")
    denied = httpx.HTTPStatusError(
        "synthetic", request=request, response=httpx.Response(status, request=request)
    )
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, collect=AsyncMock(side_effect=denied))
    assert failure.value.retryable is False


def test_a_stale_token_is_retryable_because_one_client_now_serves_a_whole_group():
    """401 is deliberately NOT in NON_RETRYABLE_STATUS.

    The pooled client caches one MSAL token for the lifetime of a collection
    group rather than one control, so a token that expires mid-group presents as
    401 and a fresh attempt acquires a new one. Treating it as deterministic
    would turn a longer token lifetime into a permanent error row.
    """
    request = httpx.Request("GET", "https://graph.microsoft.com/v1.0/users")
    stale = httpx.HTTPStatusError(
        "synthetic", request=request, response=httpx.Response(401, request=request)
    )
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, collect=AsyncMock(side_effect=stale))
    assert failure.value.retryable is True
    assert 401 not in tasks.NON_RETRYABLE_STATUS


def test_a_transient_opa_failure_is_retryable_not_a_permanent_error_row():
    """Found in review: every ValueError was classified as deterministic.

    opa_client._execute raises a bare ValueError for ANY non-zero exit of the
    opa subprocess, transient ones included, so a momentary OPA blip was written
    as a permanent error row for every control in the group with no retry at all.
    """
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(
            MEMBERS,
            evaluate=AsyncMock(
                side_effect=ValueError("OPA evaluation failed or returned no result")
            ),
        )
    assert failure.value.reason_code == "evaluation_error"
    assert failure.value.retryable is True
    # The collection stage keeps the opposite rule: our own evidence validation
    # is deterministic and retrying it only spends more tenant requests.
    assert tasks._is_retryable(ValueError("bad evidence"), "collection") is False
    assert (
        tasks._is_retryable(ValueError("no policy"), "provenance_unavailable") is False
    )


@pytest.mark.parametrize("status", [429, 500, 503])
def test_throttling_and_server_errors_stay_retryable(status):
    request = httpx.Request("GET", "https://graph.microsoft.com/v1.0/users")
    transient = httpx.HTTPStatusError(
        "synthetic", request=request, response=httpx.Response(status, request=request)
    )
    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, collect=AsyncMock(side_effect=transient))
    assert failure.value.retryable is True


def test_a_non_object_collection_gives_every_member_collection_only():
    outcomes = _evaluate(MEMBERS, collect=AsyncMock(return_value=["not an object"]))
    for control_id, _ in MEMBERS:
        outcome = outcomes[control_id]
        assert outcome["compliant"] is None
        assert outcome["provenance"]["provenance_status"] == "collection_only"
        assert "factprint" not in outcome


def test_the_shared_projection_is_computed_once_and_carried_by_every_member():
    with patch.object(tasks, "project_facts", return_value=[{"f": 1}]) as projection:
        outcomes = _evaluate(MEMBERS)
    assert projection.call_count == 1
    for control_id, _ in MEMBERS:
        assert outcomes[control_id]["factprint"] == [{"f": 1}]


def test_the_pooled_client_is_closed_when_the_group_finishes():
    from collectors import graph_client, registry
    from opa_client import opa_client

    closed = AsyncMock()
    client = type("Client", (), {"aclose": closed})()
    result = MagicMock()
    result.opa_version = "synthetic"
    result.result.model_dump.return_value = {
        "compliant": True,
        "message": "ok",
        "details": {},
        "affected_resources": [],
    }
    collector = type("Collector", (), {"collect": AsyncMock(return_value={})})()
    with (
        patch.object(registry, "get_collector", return_value=collector),
        patch.object(graph_client, "GraphClient", lambda **_: client),
        patch.object(tasks, "capture_policy", lambda *_: "package synthetic"),
        patch.object(tasks, "engine_identity", lambda: {"engine_git_sha": "a" * 40}),
        patch.object(opa_client, "runtime_version", AsyncMock(return_value="1.20.2")),
        patch.object(opa_client, "evaluate_snapshot", AsyncMock(return_value=result)),
    ):
        asyncio.run(
            tasks._evaluate_collection_async(
                collector_id="entra.synthetic",
                members=MEMBERS,
                credentials=dict(CREDENTIALS),
                framework="cis",
                benchmark="microsoft-365-foundations",
                version="v6.0.0",
            )
        )
    closed.assert_awaited_once()


# ---------------------------------------------------------------------------
# Findings from the adversarial review of this phase's own code
# ---------------------------------------------------------------------------


def test_a_non_ready_control_is_never_planned_as_a_collection():
    """Found in review: the reconciler can meet a pending non-ready control.

    29 non-ready CIS v6.0.0 controls name a collector. Planning one into a
    collection group produced a row the task refuses with "Control execution
    unavailable" and never writes -- so the row stayed live, was republished
    every dispatcher cycle, and eventually failed the WHOLE scan with
    dispatch_retry_exhausted. It falls back to the Phase 6 per-result row, which
    is exactly what would have been written before Phase 9.
    """
    groups, unplannable = build_collection_plan(
        [
            (
                {"id": 1, "control_id": "1.1.1"},
                {"data_collector_id": "entra.a", "automation_status": "ready"},
            ),
            (
                {"id": 2, "control_id": "7.2.1"},
                {"data_collector_id": "entra.a", "automation_status": "blocked"},
            ),
            (
                {"id": 3, "control_id": "1.2.1"},
                {"data_collector_id": "entra.b", "automation_status": "manual"},
            ),
        ]
    )
    assert [group.collector_id for group in groups] == ["entra.a"]
    assert [member.control_id for member in groups[0].members] == ["1.1.1"]
    assert [row["id"] for row in unplannable] == [2, 3]


def test_the_full_benchmark_plan_is_unchanged_by_the_ready_filter():
    """The orchestrator already filtered to ready, so nothing shifts there."""
    groups, unplannable = build_collection_plan(_pairs(READY))
    assert not unplannable
    assert plan_summary(groups)["collections"] == 43


def test_members_that_fail_differently_keep_their_own_reason_codes():
    """Found in review: a group failure took the FIRST member's reason code.

    A control whose policy file is missing was recorded as `evaluation_error`
    because some other control in its group failed at OPA first.
    """
    good = MagicMock()
    good.opa_version = "synthetic"
    good.result.model_dump.return_value = {
        "compliant": True,
        "message": "ok",
        "details": {},
        "affected_resources": [],
    }

    def capture(framework, benchmark, version, policy_file):
        if policy_file == "b.rego":
            raise ValueError("missing policy")
        return "package synthetic"

    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(
            MEMBERS,
            capture=capture,
            evaluate=AsyncMock(side_effect=RuntimeError("opa down")),
        )
    assert failure.value.reason_for("1.1.2") == "provenance_unavailable"
    assert failure.value.reason_for("1.1.1") == "evaluation_error"
    assert failure.value.reason_for("1.1.3") == "evaluation_error"


def test_one_deterministic_member_does_not_suppress_the_groups_retry():
    """Found in review: `retryable` was taken from the first member alone.

    A missing policy file on control 1.1.2 must not stop the group retrying the
    transient OPA outage that is stopping 1.1.1 and 1.1.3 from ever being
    assessed at all.
    """

    def capture(framework, benchmark, version, policy_file):
        if policy_file == "b.rego":
            raise ValueError("missing policy")
        return "package synthetic"

    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(
            MEMBERS,
            capture=capture,
            evaluate=AsyncMock(side_effect=RuntimeError("opa down")),
        )
    assert failure.value.retryable is True


def test_a_group_that_fails_only_deterministically_is_still_not_retried():
    def capture(framework, benchmark, version, policy_file):
        raise ValueError("missing policy")

    with pytest.raises(tasks.EvaluationFailure) as failure:
        _evaluate(MEMBERS, capture=capture)
    assert failure.value.reason_code == "provenance_unavailable"
    assert failure.value.retryable is False


def _terminal_write(exception):
    """Drive _run_collection to its terminal branch and capture what it wrote."""
    from contextlib import contextmanager

    session = MagicMock()

    @contextmanager
    def database():
        yield session

    saved = MagicMock(return_value=True)
    task = MagicMock()
    task.max_retries = 3
    task.request.retries = 0
    members = [
        tasks.PlannedControl(
            result_id=index + 1, control_id=control_id, policy_file=policy
        )
        for index, (control_id, policy) in enumerate(MEMBERS)
    ]
    with (
        patch.object(tasks, "get_db_session", database),
        patch.object(tasks, "get_execution_credentials", lambda *_: dict(CREDENTIALS)),
        patch.object(tasks, "update_scan_result", saved),
        patch.object(tasks, "finalize_scan_if_complete", MagicMock(return_value=False)),
        patch.object(
            tasks, "_evaluate_collection_async", AsyncMock(side_effect=exception)
        ),
    ):
        outcome = tasks._run_collection(
            task,
            1,
            3,
            "entra.synthetic",
            members,
            {
                "framework": "cis",
                "benchmark": "microsoft-365-foundations",
                "version": "v6.0.0",
                "metadata_digest": "d",
                "correlation_id": "synthetic",
            },
        )
    return outcome, saved


def test_a_deterministic_failure_is_not_described_as_having_been_retried():
    """Found in review: the terminal message always said "after retries".

    A deterministic failure is refused on the first attempt, so no retry was
    ever attempted. Saying otherwise misdescribes the audit record.
    """
    provenances = {control_id: {"control_id": control_id} for control_id, _ in MEMBERS}
    failure = tasks.EvaluationFailure(
        "collection_error",
        provenances["1.1.1"],
        provenances,
        retryable=False,
    )
    outcome, saved = _terminal_write(failure)
    assert outcome["status"] == "error"
    messages = {call.kwargs["message"] for call in saved.call_args_list}
    assert messages == {
        "Control execution failed; no compliance assessment was recorded."
    }
    # Every member of the group got its own row, with its own provenance.
    assert {call.kwargs["result_id"] for call in saved.call_args_list} == {1, 2, 3}
    assert all(call.kwargs["status"] == "error" for call in saved.call_args_list)


def test_an_exhausted_retryable_failure_still_says_it_was_retried():
    from contextlib import contextmanager

    session = MagicMock()

    @contextmanager
    def database():
        yield session

    saved = MagicMock(return_value=True)
    task = MagicMock()
    task.max_retries = 3
    task.request.retries = 3  # budget spent
    members = [
        tasks.PlannedControl(result_id=1, control_id="1.1.1", policy_file="a.rego")
    ]
    with (
        patch.object(tasks, "get_db_session", database),
        patch.object(tasks, "get_execution_credentials", lambda *_: dict(CREDENTIALS)),
        patch.object(tasks, "update_scan_result", saved),
        patch.object(tasks, "finalize_scan_if_complete", MagicMock(return_value=False)),
        patch.object(
            tasks, "_run_single", AsyncMock(side_effect=RuntimeError("tenant down"))
        ),
    ):
        tasks._run_collection(
            task,
            1,
            3,
            "entra.synthetic",
            members,
            {
                "framework": "cis",
                "benchmark": "microsoft-365-foundations",
                "version": "v6.0.0",
                "metadata_digest": "d",
                "correlation_id": "synthetic",
            },
        )
    assert saved.call_args.kwargs["message"] == (
        "Control execution failed after retries; no compliance assessment was recorded."
    )
