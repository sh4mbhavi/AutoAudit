"""Cheap polling and a consistent provenance projection (PERF-05).

Three claims:

* the summary endpoint is conditional, so a poll between two result writes costs
  one query and no body;
* the results endpoint can be paged, and omitting the page returns exactly what
  it always returned;
* every response that carries provenance now applies the same allowlist the SOC 2
  projection has always applied, so the Rego source text stops being published.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1 import scans, soc2
from app.schemas.provenance import (
    PUBLISHABLE_PROVENANCE_FIELDS,
    RESULT_PROVENANCE_FIELDS,
    WITHHELD_PROVENANCE_FIELDS,
    publishable_provenance,
)

# Every key engine/worker/provenance.py:initial_provenance writes, plus the two
# engine_identity adds. Transcribed rather than imported: the backend cannot
# import the worker, and a silent divergence is what this test exists to catch.
WORKER_PROVENANCE = {
    "schema_version": 1,
    "framework": "cis",
    "benchmark": "microsoft-365-foundations",
    "benchmark_version": "v6.0.0",
    "control_id": "1.1.1",
    "metadata_digest": "d" * 64,
    "correlation_id": "synthetic",
    "collector_id": "entra.roles.cloud_only_admins",
    "policy_file": "1.1.1_admin_cloud_only.rego",
    "policy_digest": "p" * 64,
    "policy_source": "package cis\nallow := true\n",
    "input_digest": "i" * 64,
    "engine_git_sha": "a" * 40,
    "engine_image_digest": None,
    "engine_worktree_dirty": False,
    "engine_source_digest": "e" * 64,
    "opa_version": "1.20.2",
    "collection_started_at": "2026-09-06T00:00:00+00:00",
    "collection_completed_at": "2026-09-06T00:00:01+00:00",
    "evaluation_started_at": "2026-09-06T00:00:01+00:00",
    "evaluated_at": "2026-09-06T00:00:02+00:00",
    "recorded_at": "2026-09-06T00:00:00+00:00",
    "provenance_status": "captured",
    "reason_code": None,
}


# ---------------------------------------------------------------------------
# The provenance projection
# ---------------------------------------------------------------------------


def test_a_result_publishes_every_provenance_field_except_the_policy_source():
    published = publishable_provenance(WORKER_PROVENANCE)
    assert set(WORKER_PROVENANCE) - set(published) == {"policy_source"}
    assert WITHHELD_PROVENANCE_FIELDS == ("policy_source",)
    # The exact field the SOC 2 report has always withheld, for the reason it
    # documents: the worker stores the complete Rego source there and file
    # content does not leave in a response.
    assert "policy_source" not in RESULT_PROVENANCE_FIELDS


def test_the_soc2_allowlist_is_unchanged_and_is_still_the_narrower_one():
    assert soc2.PUBLISHABLE_PROVENANCE_FIELDS == PUBLISHABLE_PROVENANCE_FIELDS
    assert set(PUBLISHABLE_PROVENANCE_FIELDS) < set(RESULT_PROVENANCE_FIELDS)
    assert set(RESULT_PROVENANCE_FIELDS) - set(PUBLISHABLE_PROVENANCE_FIELDS) == {
        "control_id",
        "framework",
        "benchmark",
        "benchmark_version",
        "engine_worktree_dirty",
        "engine_source_digest",
    }


def test_an_unknown_provenance_field_is_withheld_by_default():
    published = publishable_provenance({**WORKER_PROVENANCE, "tenant_secret": "x"})
    assert "tenant_secret" not in published


def test_a_result_that_never_executed_gets_no_provenance_object():
    assert publishable_provenance(None) is None
    assert publishable_provenance("not a dict") is None
    # An empty dict is a real (if empty) record and stays one.
    assert publishable_provenance({}) == {}


def test_the_projection_is_applied_to_every_result_row():
    rows = [
        SimpleNamespace(
            id=index,
            scan_id=1,
            control_id=f"1.1.{index}",
            status="passed",
            selected=True,
            reason_code=None,
            provenance=dict(WORKER_PROVENANCE),
            message="ok",
            evidence={"affected_resource_count": 0},
            created_at="2026-09-06T00:00:00+00:00",
            updated_at="2026-09-06T00:00:00+00:00",
        )
        for index in range(1, 4)
    ]
    projected = scans._projected_results(rows)
    assert len(projected) == 3
    for row in projected:
        assert "policy_source" not in row.provenance
        assert row.provenance["policy_digest"] == "p" * 64
    # The 69 Rego files total about 180 KB; this is what stopped being sent on
    # every three-second poll.
    assert "package cis" not in json.dumps(
        [row.model_dump(mode="json") for row in projected]
    )


# ---------------------------------------------------------------------------
# The conditional summary
# ---------------------------------------------------------------------------


def _scan(**overrides):
    fields = {
        "id": 1,
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "started_at": "2026-09-06T00:00:00",
        "selected_count": 69,
        "semantics_version": "phase3-v1",
        "metadata_digest": "d" * 64,
        "correlation_id": "synthetic",
        "status": "running",
        "last_progress_at": "2026-09-06T00:00:00",
        "finished_at": None,
        "total_controls": 69,
        "passed_count": 1,
        "failed_count": 0,
        "skipped_count": 0,
        "error_count": 0,
        "indeterminate_count": 0,
        "not_assessable_count": 0,
        "pending_count": 68,
        "compliance_score": None,
        "coverage_score": None,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_the_etag_is_weak_and_stable_for_an_unchanged_scan():
    etag = scans._summary_etag(_scan())
    assert etag.startswith('W/"')
    assert scans._summary_etag(_scan()) == etag


@pytest.mark.parametrize(
    "change",
    [
        {"status": "completed"},
        {"last_progress_at": "2026-09-06T00:00:01"},
        {"passed_count": 2},
        {"error_count": 1},
        {"coverage_score": "20"},
        {"finished_at": "2026-09-06T00:01:00"},
    ],
)
def test_the_etag_changes_when_anything_the_summary_reports_changes(change):
    assert scans._summary_etag(_scan(**change)) != scans._summary_etag(_scan())


def test_the_etag_tolerates_a_row_that_predates_a_counter():
    # A historical row missing a column must produce an ETag, not an exception.
    assert scans._summary_etag(SimpleNamespace(status="completed"))


@pytest.mark.parametrize(
    "header,matches",
    [
        (None, False),
        ("", False),
        ('W/"abc"', True),
        ('"abc"', True),  # weak comparison: the W/ prefix is not significant
        ('W/"other"', False),
        ('W/"other", W/"abc"', True),
        ("*", True),
    ],
)
def test_if_none_match_uses_weak_comparison_over_a_list(header, matches):
    assert scans._matches(header, 'W/"abc"') is matches


def test_an_unchanged_summary_answers_304_without_running_the_control_query():
    scan = _scan()
    etag = scans._summary_etag(scan)
    session = MagicMock()
    first = MagicMock()
    first.scalar_one_or_none.return_value = scan
    session.execute = AsyncMock(side_effect=[first])
    response = MagicMock()
    response.headers = {}
    import asyncio

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            scans.get_scan_summary(
                scan_id=1,
                response=response,
                current_user=SimpleNamespace(id=1),
                db=session,
                if_none_match=etag,
            )
        )
    assert raised.value.status_code == 304
    assert raised.value.headers["ETag"] == etag
    # One query, not two: the per-control aggregation never runs.
    assert session.execute.await_count == 1


def test_a_changed_summary_still_answers_200_and_carries_the_new_validator():
    import asyncio

    scan = _scan()
    session = MagicMock()
    first = MagicMock()
    first.scalar_one_or_none.return_value = scan
    second = MagicMock()
    second.all.return_value = [("1.1.1", "passed")]
    session.execute = AsyncMock(side_effect=[first, second])
    response = MagicMock()
    response.headers = {}
    summary = asyncio.run(
        scans.get_scan_summary(
            scan_id=1,
            response=response,
            current_user=SimpleNamespace(id=1),
            db=session,
            if_none_match='W/"stale"',
        )
    )
    assert session.execute.await_count == 2
    assert response.headers["ETag"] == scans._summary_etag(scan)
    assert response.headers["Cache-Control"] == "no-cache, private"
    assert summary.categories[0].category == "1"


# ---------------------------------------------------------------------------
# Result pagination
# ---------------------------------------------------------------------------


def test_the_page_ceiling_is_declared_and_bounded():
    assert scans.MAX_RESULT_PAGE == 500


def test_the_cors_policy_lets_a_browser_use_the_conditional_poll():
    """An ETag the browser cannot read is one the client cannot echo back."""
    from app.main import create_app

    app = create_app()
    cors = next(
        middleware
        for middleware in app.user_middleware
        if middleware.cls.__name__ == "CORSMiddleware"
    )
    assert "If-None-Match" in cors.kwargs["allow_headers"]
    assert "ETag" in cors.kwargs["expose_headers"]
    assert "X-Total-Count" in cors.kwargs["expose_headers"]


def test_the_etag_covers_every_field_the_summary_publishes():
    """Found in review: a hand-written field list had already fallen behind.

    dispatch_count and deadline_at are reported by the summary and moved by the
    dispatcher independently of any result write, so the endpoint answered 304
    while the body it would have sent had changed.
    """
    from app.schemas.scan import ScanSummary

    covered = {name for name in ScanSummary.model_fields if name != "categories"}
    for field in sorted(covered):
        changed = _scan(**{field: "phase9-sentinel"})
        assert scans._summary_etag(changed) != scans._summary_etag(_scan()), field


def test_two_fields_swapping_values_do_not_produce_the_same_etag():
    """The digest names each field, so a|b and b|a are different validators."""
    first = scans._summary_etag(_scan(passed_count=1, failed_count=2))
    second = scans._summary_etag(_scan(passed_count=2, failed_count=1))
    assert first != second


def test_the_conditional_response_is_in_the_published_schema():
    """The generated frontend contract must be able to see the 304 and the ETag."""
    from app.main import create_app

    schema = create_app().openapi()
    summary = schema["paths"]["/v1/scans/{scan_id}/summary"]["get"]
    assert "304" in summary["responses"]
    assert "ETag" in summary["responses"]["200"]["headers"]
    results = schema["paths"]["/v1/scans/{scan_id}/results"]["get"]
    assert "X-Total-Count" in results["responses"]["200"]["headers"]
