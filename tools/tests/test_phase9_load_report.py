"""The load harness must measure the thing it claims to measure.

It is the phase's only before/after evidence, so it is gated: a harness that
silently stops exercising the per-item loops would report a saving that is only
the absence of work.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "tools" / "perf"))

pytest.importorskip("httpx")

import scan_load_report as harness  # noqa: E402


def test_the_census_the_two_topologies_encode():
    before = harness.measure("per_control", size=1)
    after = harness.measure("per_collector", size=1)
    assert before["collector_executions"] == 69
    assert after["collector_executions"] == 43
    assert before["controls"] == after["controls"] == 69


def test_the_harness_contacts_no_tenant(monkeypatch):
    """Asserted by breaking the network, not by inspecting an attribute.

    Any real socket, at any layer, fails the run: the harness must answer every
    Graph request from its own MockTransport and every PowerShell operation from
    its own local object.
    """
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("the load harness opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    report = harness.measure("per_collector", size=2)
    assert report["collector_executions"] == 43
    assert "not a live-tenant load test" in harness.__doc__


def test_the_per_item_loops_actually_fire():
    """Without this the report would show a saving that is only absent work."""
    small = harness.measure("per_control", size=2)
    large = harness.measure("per_control", size=8)
    assert large["graph_requests"] > small["graph_requests"]
    assert large["powershell_operations"] > small["powershell_operations"]


def test_a_collector_that_rejects_the_synthetic_tenant_is_counted_not_hidden():
    report = harness.measure("per_control", size=2)
    assert report["collections_that_raised"] == sum(report["raised_by"].values())
    assert 0.0 <= report["error_rate"] <= 1.0
    # Excluded collectors are named, so a reader can see what is missing.
    for reason in report["raised_by"]:
        assert ":" in reason


def test_a_failed_shape_attempt_does_not_inflate_the_counters():
    tenant = harness.SyntheticTenant(2)
    from collections import Counter

    failures: Counter = Counter()
    harness.run_collector("entra.groups.groups", tenant, failures)
    # groups rejects the synthetic population; its attempts must leave the
    # counters where they were, or the fallback would double-count requests.
    assert tenant.counters() == (0, 0, 0)
    assert sum(failures.values()) == 1


def test_batched_sessions_are_fewer_than_one_session_per_operation():
    report = harness.measure("per_collector", size=20)
    assert report["powershell_sessions"] < report["powershell_operations"]


def test_the_rendered_report_states_its_limitation():
    report = {
        "tenant_size": 1,
        "before": harness.measure("per_control", size=1),
        "after": harness.measure("per_collector", size=1),
    }
    text = harness.render(report)
    assert "No tenant was contacted" in text
    assert "collector executions" in text


def test_the_counted_rows_do_not_move_with_measurement_order():
    """The rows the report presents as savings must be exact counts.

    Found in review: main() always runs per_control first, so whichever
    topology went first paid for the lazy import of ~43 collector modules and
    every first-touch allocation -- and the time and memory "savings" were that
    cost, with a sign that flipped when the columns were swapped.
    """
    forward_before = harness.measure("per_control", size=3)
    forward_after = harness.measure("per_collector", size=3)
    reversed_after = harness.measure("per_collector", size=3)
    reversed_before = harness.measure("per_control", size=3)
    for key in (
        "collector_executions",
        "graph_requests",
        "powershell_sessions",
        "powershell_operations",
        "collections_that_raised",
    ):
        assert forward_before[key] == reversed_before[key], key
        assert forward_after[key] == reversed_after[key], key


def test_each_topology_is_measured_after_a_warm_up_pass():
    """Asserted structurally, not by timing.

    A timing assertion over two short runs is noise; what is checkable is that
    every collector the topology will execute has already been executed once,
    outside the measured window. Reverting the warm-up removes this call.
    """
    import inspect

    source = inspect.getsource(harness.measure)
    warm_up, measured = source.split("tracemalloc.start()", 1)
    assert "run_collector" in warm_up
    assert "time.perf_counter()" not in warm_up
    assert "run_collector" in measured


def test_the_report_names_the_pre_phase9_session_count_explicitly():
    report = {
        "tenant_size": 4,
        "before": harness.measure("per_control", size=4),
        "after": harness.measure("per_collector", size=4),
    }
    text = harness.render(report)
    # The per_control column runs the CURRENT, already-batched collectors, so
    # its "PowerShell sessions" row is NOT the pre-Phase-9 count. The report has
    # to say which number is which, or it overstates or understates the saving.
    assert "pre-Phase-9 shape vs Phase 9 shape" in text
    assert (
        report["before"]["powershell_operations"]
        >= report["after"]["powershell_sessions"]
    )
