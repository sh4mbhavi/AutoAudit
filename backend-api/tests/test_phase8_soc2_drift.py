"""Phase 8 drift as a separate SOC 2 report stream (plan item 16.2 #6).

Drift is added to the SOC 2 report the same way Phase 7 added manual and
inherited evidence: as a third stream that sits *beside* the automated results.
The whole point of these tests is that adding it changed nothing else.

Four properties are asserted structurally rather than described:

* the report is byte-identical apart from one new key. Everything a Phase 7
  consumer read is still there, unchanged, whether or not drift exists;
* no drift number enters ``Soc2Coverage``, and no drift event moves a rating;
* an unreadable drift stream reports ``available: false`` with the *unavailable*
  note, which is the "unknown" claim, and is a different claim from the ordinary
  note that means "no drift run exists for this scan";
* ``is_real_time``, ``changes_ratings`` and ``counted_in_automated_coverage``
  cannot be set true at all - Pydantic rejects the payload.

The report inputs are the Phase 7 module's own helpers, imported rather than
re-created, so "unchanged" is asserted against the same fixture data Phase 7
asserts against. No test here edits a Phase 7 test.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from app.api.v1 import soc2
from app.models.drift import DriftRun
from app.schemas.drift import NO_EVENTS_SENTENCE
from app.schemas.soc2 import (
    DRIFT_NO_EVENTS_NOTE,
    DRIFT_STREAM_NOTE,
    DRIFT_STREAM_UNAVAILABLE_NOTE,
    Soc2DriftStream,
)
from app.services import drift as drift_service
from tests.test_phase7_soc2 import (
    BENCHMARK_RELATIVE,
    MAPPING_RELATIVE,
    REAL_MAPPINGS,
    REAL_POLICIES,
    _result_row,
    _scan_row,
    _synthetic_mapping,
    _synthetic_metadata,
)

# The top-level keys a Phase 7 consumer reads. Pinned literally: "additive"
# means exactly one new name appears here and no existing name leaves.
PHASE7_RESPONSE_KEYS = frozenset(
    {
        "scan_id",
        "projection_available",
        "projection_status",
        "message",
        "header",
        "provenance",
        "criteria_coverage_summary",
        "points_of_focus",
        "totals",
        "manual_evidence_stream",
        "mapping_resolution_findings",
    }
)

PHASE7_POINT_KEYS = frozenset(
    {
        "point_id",
        "criterion",
        "point_of_focus",
        "configuration_rating",
        "rating_source",
        "rating_is_computed",
        "evidence_selector",
        "selector_resolved",
        "mapped_control_ids",
        "automated_evidence",
        "coverage",
        "manual_residual_evidence",
        "limitations",
    }
)

PHASE7_COVERAGE_KEYS = frozenset(
    {
        "mapped_control_count",
        "in_scan_count",
        "applicable_count",
        "assessed_count",
        "passed_count",
        "failed_count",
        "indeterminate_count",
        "error_count",
        "not_assessable_count",
        "pending_count",
        "missing_result_count",
        "unassessed_count",
        "not_in_scope_count",
        "missing_from_benchmark_count",
        "coverage_percent",
        "compliance_percent",
        "assessment_completeness",
        "partial_assessment",
        "coverage_statement",
    }
)

PHASE7_MANUAL_STREAM_KEYS = frozenset(
    {"available", "approved_record_count", "counted_in_automated_coverage", "note"}
)

# The Phase 7 value of the provenance allowlist, transcribed. ``policy_source``
# is deliberately absent from it and must stay absent.
PHASE7_PUBLISHABLE_PROVENANCE_FIELDS = (
    "schema_version",
    "provenance_status",
    "reason_code",
    "collector_id",
    "policy_file",
    "policy_digest",
    "input_digest",
    "engine_git_sha",
    "engine_image_digest",
    "opa_version",
    "metadata_digest",
    "correlation_id",
    "collection_started_at",
    "collection_completed_at",
    "evaluation_started_at",
    "evaluated_at",
    "recorded_at",
)

# The human-owned ratings the real mapping carries today, transcribed here so a
# drift event that moved one would fail this file and not only Phase 7's.
EXPECTED_RATING_COUNTS = {"Yes": 13, "Partial": 16, "No": 18}

# The fixed sentence, pinned as text. It is a governance commitment, not an
# implementation detail, so a reword has to be a deliberate edit here too.
FIXED_NO_EVENTS_SENTENCE = (
    "Zero events means the compared observations were identical for every "
    "comparable control. It never means the tenant was not changed between "
    "scans, and it never means a control passed."
)

ALL_SEVERITIES = ("critical", "high", "medium", "low", "informational")

# The two stream notes, transcribed. They say what drift is and what an
# unreadable stream means; both are governance prose, so a reword must be a
# deliberate edit here as well as in the schema.
FIXED_DRIFT_STREAM_NOTE = (
    "Configuration drift is reported beside the automated results as a "
    "separate stream. Drift is a periodic comparison of two completed scans "
    "against a pinned baseline. It is not real-time monitoring, not SIEM "
    "correlation, and it changes no rating, result or score."
)

FIXED_DRIFT_STREAM_UNAVAILABLE_NOTE = (
    "The configuration drift stream could not be read, so none is shown. "
    "Absence here means unknown, not none, and never means compliant."
)


# --------------------------------------------------------------------- harness


class _Rows:
    """Minimal stand-in for a SQLAlchemy Result, with ``scalar_one``."""

    def __init__(self, items):
        self._items = list(items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def scalar_one(self):
        return self._items[0] if self._items else None

    def scalars(self):
        return self

    def all(self):
        return list(self._items)


def _drift_run(**overrides) -> DriftRun:
    """A detached ``drift_run`` row carrying every severity in both classes."""
    counts = {
        "configuration": {name: 3 for name in ALL_SEVERITIES},
        "evaluation": {name: 2 for name in ALL_SEVERITIES},
    }
    values = {
        "id": 41,
        "baseline_id": 17,
        "baseline_scan_id": 5,
        "current_scan_id": 9,
        "user_id": 7,
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "status": "completed",
        "trigger": "scan_finalised",
        "configuration_comparable": True,
        "evaluation_comparable": True,
        "axis_reasons": {},
        "controls_compared": 44,
        "controls_skipped": {},
        "event_count": sum(sum(bucket.values()) for bucket in counts.values()),
        "event_counts": counts,
        "event_set_digest": "0" * 64,
        "drift_version": "phase8-drift-v1",
        "retention_policy_version": "phase8-draft-1",
    }
    values.update(overrides)
    return DriftRun(**values)


def _report(scan, results=(), manual=(), drift=(), user_id=7, scan_id=None):
    """Render the report over a mocked session.

    ``drift`` is the tail of the ``db.execute`` script: empty means the real
    drift service runs and finds no run for this scan, which is the "no drift
    rows" case rather than a patched-out one.
    """
    script = [_Rows([scan] if scan else []), _Rows(results), _Rows(manual)]
    script.extend(drift if drift else [_Rows([])])
    db = MagicMock()
    db.execute = AsyncMock(side_effect=script)
    app = FastAPI()
    app.include_router(soc2.router)
    app.dependency_overrides[soc2.get_current_user] = lambda: SimpleNamespace(
        id=user_id
    )
    app.dependency_overrides[soc2.get_async_session] = lambda: db
    with TestClient(app) as client:
        return client.get(f"/scans/{scan_id or (scan.id if scan else 1)}/soc2-report")


def _with_events(open_notifications: int = 4):
    """The ``db.execute`` tail for a run that produced events of every severity."""
    return [_Rows([_drift_run()]), _Rows([open_notifications])]


def _normalised(body: dict) -> dict:
    """Everything except the new key, with the render clock removed.

    ``generated_at`` is the only value that legitimately differs between two
    renders of the same scan, so it is the only thing normalised away.
    """
    rest = {key: value for key, value in body.items() if key != "drift_stream"}
    if isinstance(rest.get("provenance"), dict):
        rest["provenance"] = {
            key: value
            for key, value in rest["provenance"].items()
            if key != "generated_at"
        }
    return rest


@pytest.fixture
def real_mapping():
    return json.loads((REAL_MAPPINGS / MAPPING_RELATIVE).read_text(encoding="utf-8"))


@pytest.fixture
def real_metadata():
    return json.loads(
        (REAL_POLICIES / BENCHMARK_RELATIVE / "metadata.json").read_text(
            encoding="utf-8"
        )
    )


def _synthetic_scan():
    controls = [
        {"control_id": "1.1.1", "title": "One", "automation_status": "ready"},
        {"control_id": "1.1.3", "title": "Three", "automation_status": "ready"},
        {"control_id": "6.1", "title": "Six", "automation_status": "ready"},
    ]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC6.1-P06",
                "criterion": "CC6.1",
                "point_of_focus": "Synthetic point",
                "rating": "Partial",
                "cis_control_ids": ["1.1.1", "1.1.3", "6.1"],
                "evidence_selector": None,
                "residual_limitation": "Synthetic residual limitation.",
                "residual_scope": "Synthetic residual scope.",
            }
        ]
    )
    return _scan_row(mapping, _synthetic_metadata(controls))


SYNTHETIC_RESULTS = (
    ("1.1.1", "passed"),
    ("1.1.3", "failed"),
    ("6.1", "indeterminate"),
)


# ------------------------------------------------------------ additive contract


def test_report_without_drift_is_byte_identical_apart_from_the_new_field():
    """No drift rows: one new key, and every other key and value untouched."""
    scan = _synthetic_scan()
    results = [
        _result_row(control_id, state) for control_id, state in SYNTHETIC_RESULTS
    ]

    without = _report(scan, results).json()

    assert set(without) == PHASE7_RESPONSE_KEYS | {"drift_stream"}
    assert set(without) - PHASE7_RESPONSE_KEYS == {"drift_stream"}
    assert PHASE7_RESPONSE_KEYS - set(without) == set()

    # Nested shapes a Phase 7 consumer reads are unchanged too.
    point = without["points_of_focus"][0]
    assert set(point) == PHASE7_POINT_KEYS
    assert set(point["coverage"]) == PHASE7_COVERAGE_KEYS
    assert set(without["manual_evidence_stream"]) == PHASE7_MANUAL_STREAM_KEYS

    stream = without["drift_stream"]
    assert stream["available"] is False
    # "No drift run" is a known state, not an unreadable one.
    assert stream["note"] == DRIFT_STREAM_NOTE
    assert stream["note"] == FIXED_DRIFT_STREAM_NOTE
    assert stream["note"] != DRIFT_STREAM_UNAVAILABLE_NOTE
    assert stream["event_count"] == 0
    assert stream["event_counts"] == {}
    assert stream["open_notification_count"] == 0
    assert stream["run_id"] is None
    assert stream["baseline_id"] is None
    assert stream["run_status"] is None

    # And a report rendered with a full drift run differs in nothing else.
    with_drift = _report(scan, results, drift=_with_events()).json()
    assert with_drift["drift_stream"]["available"] is True
    assert json.dumps(_normalised(with_drift), sort_keys=True) == json.dumps(
        _normalised(without), sort_keys=True
    )


def test_drift_stream_is_never_counted_in_coverage():
    """Coverage arithmetic is identical with and without drift events."""
    scan = _synthetic_scan()
    results = [
        _result_row(control_id, state) for control_id, state in SYNTHETIC_RESULTS
    ]

    without = _report(scan, results).json()
    with_drift = _report(scan, results, drift=_with_events()).json()

    quiet = [point["coverage"] for point in without["points_of_focus"]]
    loud = [point["coverage"] for point in with_drift["points_of_focus"]]
    assert loud == quiet
    assert quiet[0]["applicable_count"] == 3
    assert quiet[0]["assessed_count"] == 2
    assert quiet[0]["passed_count"] == 1

    stream = with_drift["drift_stream"]
    assert stream["event_count"] == 25
    assert stream["counted_in_automated_coverage"] is False
    # None of the drift numbers appears anywhere in the coverage block.
    assert stream["event_count"] not in loud[0].values()
    assert stream["open_notification_count"] == 4
    assert with_drift["totals"] == without["totals"]


def test_rating_is_unchanged_by_drift(real_mapping, real_metadata):
    """Every rating, and the whole rating tally, survives events of every severity."""
    scan = _scan_row(real_mapping, real_metadata)
    results = [
        _result_row(control["control_id"], "passed")
        for control in real_metadata["controls"]
        if control.get("automation_status") == "ready"
    ]

    without = _report(scan, results).json()
    with_drift = _report(scan, results, drift=_with_events()).json()

    counts = with_drift["drift_stream"]["event_counts"]
    for event_class in ("configuration", "evaluation"):
        assert set(counts[event_class]) == set(ALL_SEVERITIES)

    assert with_drift["totals"]["rating_counts"] == EXPECTED_RATING_COUNTS
    assert with_drift["totals"]["rating_counts"] == without["totals"]["rating_counts"]

    quiet = {
        point["point_id"]: point["configuration_rating"]
        for point in without["points_of_focus"]
    }
    loud = {
        point["point_id"]: point["configuration_rating"]
        for point in with_drift["points_of_focus"]
    }
    assert loud == quiet
    assert all(
        point["rating_is_computed"] is False
        and point["rating_source"] == "pinned_mapping"
        for point in with_drift["points_of_focus"]
    )
    assert with_drift["drift_stream"]["changes_ratings"] is False


def test_unreadable_drift_reports_unavailable_not_none(monkeypatch):
    """A database fault in the last read is unknown, never "no drift"."""

    async def _explode(*_args, **_kwargs):
        raise OperationalError("synthetic", None, Exception("synthetic"))

    monkeypatch.setattr(drift_service, "soc2_drift_summary", _explode)

    scan = _synthetic_scan()
    results = [
        _result_row(control_id, state) for control_id, state in SYNTHETIC_RESULTS
    ]
    body = _report(scan, results).json()

    stream = body["drift_stream"]
    assert stream["available"] is False
    assert stream["note"] == DRIFT_STREAM_UNAVAILABLE_NOTE
    assert stream["note"] == FIXED_DRIFT_STREAM_UNAVAILABLE_NOTE
    assert "unknown, not none" in stream["note"]
    assert stream["event_count"] == 0
    assert stream["run_id"] is None

    # The automated projection above it rendered exactly as it always does.
    assert body["projection_available"] is True
    assert body["points_of_focus"][0]["coverage"]["assessed_count"] == 2
    assert body["points_of_focus"][0]["configuration_rating"] == "Partial"


def test_literal_pins():
    """The three constant flags are typed, so no payload can set them true."""
    for field in ("is_real_time", "changes_ratings", "counted_in_automated_coverage"):
        with pytest.raises(ValidationError):
            Soc2DriftStream(available=True, note=DRIFT_STREAM_NOTE, **{field: True})

    stream = Soc2DriftStream(available=True, note=DRIFT_STREAM_NOTE)
    assert stream.is_real_time is False
    assert stream.changes_ratings is False
    assert stream.counted_in_automated_coverage is False
    # The whole field set, pinned. The only field naming a rating is the
    # constant that refuses to move one; there is no rating value here.
    assert set(Soc2DriftStream.model_fields) == {
        "available",
        "baseline_id",
        "baseline_scan_id",
        "run_id",
        "run_status",
        "configuration_comparable",
        "evaluation_comparable",
        "event_counts",
        "event_count",
        "open_notification_count",
        "counted_in_automated_coverage",
        "is_real_time",
        "changes_ratings",
        "no_events_means",
        "note",
    }


def test_no_events_sentence_matches_the_drift_schema_constant():
    """Byte for byte, and against the transcribed sentence itself."""
    assert DRIFT_NO_EVENTS_NOTE == NO_EVENTS_SENTENCE
    assert DRIFT_NO_EVENTS_NOTE == FIXED_NO_EVENTS_SENTENCE
    assert DRIFT_NO_EVENTS_NOTE.encode() == FIXED_NO_EVENTS_SENTENCE.encode()

    scan = _synthetic_scan()
    body = _report(scan, [_result_row("1.1.1", "passed")]).json()
    assert body["drift_stream"]["no_events_means"] == FIXED_NO_EVENTS_SENTENCE


def test_publishable_provenance_fields_is_unchanged():
    """The allowlist is the Phase 7 tuple, in order, and still excludes Rego source."""
    assert soc2.PUBLISHABLE_PROVENANCE_FIELDS == PHASE7_PUBLISHABLE_PROVENANCE_FIELDS
    assert "policy_source" not in soc2.PUBLISHABLE_PROVENANCE_FIELDS
    assert "message" not in soc2.PUBLISHABLE_PROVENANCE_FIELDS
    assert "observed_value" not in soc2.PUBLISHABLE_PROVENANCE_FIELDS
