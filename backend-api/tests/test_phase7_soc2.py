"""Phase 7 SOC 2 mapping pin and report projection (plan items 15.1.3/15.1.4).

The non-negotiable semantics under test:

* a rating is transcribed from the pinned mapping and never computed, so a
  tenant that passes everything cannot turn a "No" into a "Yes";
* manual and inherited evidence is a separate stream that never raises automated
  coverage;
* error, indeterminate, not-assessable and pending results are not assessed and
  not compliant, and stay in the coverage denominator;
* an unselected control is out of scope for the scan, not a gap;
* the CC7.1 ``all_automated_cis_m365_v6`` selector resolves against the scan's
  pinned metadata snapshot, not the live benchmark on disk;
* the pin itself is written once and is immutable in the database afterwards.

No test edits a real mapping or policy file. Everything that needs a mutable
corpus copies one into ``tmp_path`` first.
"""

import asyncio
import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import asyncpg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import scans, soc2
from app.models.compliance import Scan
from app.models.manual_evidence import ManualEvidenceRecord
from app.models.scan_result import ScanResult
from app.services.crosswalk_reader import (
    CrosswalkFileReader,
    CrosswalkIntegrityError,
    CrosswalkNotFoundError,
    check_control_resolution,
    policy_corpus_digest_for_directory,
)
from tests import test_migrations as migration_helpers
from tests.test_migrations import _alembic, _query

database_url = migration_helpers.database_url

REPO = Path(__file__).resolve().parents[2]
REAL_MAPPINGS = REPO / "engine" / "mappings"
REAL_POLICIES = REPO / "engine" / "policies"
MAPPING_RELATIVE = Path("soc2/common-criteria/v1.0.0/mapping.json")
BENCHMARK_RELATIVE = Path("cis/microsoft-365-foundations/v6.0.0")

MAPPING_ID = "soc2-common-criteria-to-cis-m365"
MAPPING_VERSION = "v1.0.0"

# The human-owned ratings the mapping carries today. Transcription is the whole
# contract, so the counts are asserted rather than derived.
EXPECTED_RATING_COUNTS = {"Yes": 13, "Partial": 16, "No": 18}
EXPECTED_POINTS = 47
EXPECTED_UNIQUE_CONTROL_IDS = 44


# --------------------------------------------------------------------- corpus


@pytest.fixture
def corpus(tmp_path):
    """A private, writable copy of the real mapping and policy corpus."""
    mappings = tmp_path / "mappings"
    policies = tmp_path / "policies"
    shutil.copytree(REAL_MAPPINGS, mappings)
    shutil.copytree(REAL_POLICIES, policies)
    return SimpleNamespace(
        mappings=mappings,
        policies=policies,
        mapping_file=mappings / MAPPING_RELATIVE,
        benchmark_dir=policies / BENCHMARK_RELATIVE,
        reader=CrosswalkFileReader(mappings_dir=mappings, policies_dir=policies),
    )


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


# ------------------------------------------------------------- reader digests


def test_mapping_digest_is_over_raw_bytes_and_follows_the_file(corpus):
    mapping = corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)
    assert (
        mapping.digest == hashlib.sha256(corpus.mapping_file.read_bytes()).hexdigest()
    )
    assert mapping.mapping_id == MAPPING_ID
    assert mapping.mapping_version == MAPPING_VERSION

    document = json.loads(corpus.mapping_file.read_text(encoding="utf-8"))
    document["points_of_focus"][0]["residual_limitation"] = "Edited for this test."
    corpus.mapping_file.write_text(json.dumps(document, indent=2), encoding="utf-8")

    reloaded = corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)
    assert reloaded.digest != mapping.digest
    assert (
        reloaded.digest == hashlib.sha256(corpus.mapping_file.read_bytes()).hexdigest()
    )


def test_policy_corpus_digest_tracks_rego_and_ignores_metadata(corpus):
    before = corpus.reader.policy_corpus_digest(
        "cis", "microsoft-365-foundations", "v6.0.0"
    )

    metadata_file = corpus.benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    metadata["release_date"] = "2099-01-01"
    metadata_file.write_text(json.dumps(metadata), encoding="utf-8")
    assert (
        corpus.reader.policy_corpus_digest("cis", "microsoft-365-foundations", "v6.0.0")
        == before
    ), "metadata.json is covered by metadata_digest, not the policy corpus digest"

    policy = min(corpus.benchmark_dir.glob("*.rego"))
    policy.write_text(
        policy.read_text(encoding="utf-8") + "\n# edited for this test\n",
        encoding="utf-8",
    )
    after = corpus.reader.policy_corpus_digest(
        "cis", "microsoft-365-foundations", "v6.0.0"
    )
    assert after != before

    # A rename is a change too: the digest is over {filename: sha256}.
    renamed = policy.with_name("renamed_" + policy.name)
    policy.rename(renamed)
    assert (
        corpus.reader.policy_corpus_digest("cis", "microsoft-365-foundations", "v6.0.0")
        != after
    )


def test_policy_corpus_digest_is_canonical_json_of_per_file_digests(corpus):
    expected = hashlib.sha256(
        json.dumps(
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in corpus.benchmark_dir.glob("*.rego")
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert policy_corpus_digest_for_directory(corpus.benchmark_dir) == expected


def test_reader_fails_closed_and_loudly(corpus, tmp_path):
    with pytest.raises(CrosswalkNotFoundError):
        corpus.reader.load_mapping(MAPPING_ID, "v9.9.9")
    with pytest.raises(CrosswalkNotFoundError):
        corpus.reader.policy_corpus_digest("cis", "microsoft-365-foundations", "v0.0.0")
    assert (
        CrosswalkFileReader(mappings_dir=tmp_path / "absent").mappings_available()
        is False
    )
    with pytest.raises(CrosswalkNotFoundError):
        CrosswalkFileReader(mappings_dir=tmp_path / "absent").load_mapping(
            MAPPING_ID, MAPPING_VERSION
        )

    # A corrupt mapping is never skipped the way benchmark_reader skips one.
    corpus.mapping_file.write_text("{not json", encoding="utf-8")
    with pytest.raises(CrosswalkIntegrityError):
        corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)


def test_unreadable_mapping_is_an_integrity_failure_not_an_absence(corpus):
    """A permission error must never look like "there is no mapping here"."""
    corpus.mapping_file.chmod(0o000)
    try:
        with pytest.raises(CrosswalkIntegrityError):
            corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)
    finally:
        corpus.mapping_file.chmod(0o644)


@pytest.mark.parametrize(
    "body",
    [
        "[]",
        "null",
        '"a string"',
    ],
)
def test_a_non_object_mapping_root_raises_the_sanitised_error(corpus, body):
    corpus.mapping_file.write_text(body, encoding="utf-8")
    with pytest.raises(CrosswalkIntegrityError):
        corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda doc: doc["approval"].update(approved="false"),
            id="truthy_string_approval",
        ),
        pytest.param(
            lambda doc: doc["control_resolution"].append(None),
            id="null_control_resolution_row",
        ),
        pytest.param(
            lambda doc: doc["control_resolution"].append({"policy_file": "x.rego"}),
            id="control_resolution_row_without_id",
        ),
        pytest.param(
            lambda doc: doc["points_of_focus"][0].update(cis_control_ids=[None]),
            id="malformed_control_id",
        ),
        pytest.param(
            lambda doc: doc["points_of_focus"][0].update(evidence_selector=7),
            id="non_string_selector",
        ),
        pytest.param(
            lambda doc: doc.update(criteria_coverage_summary=["CC6"]),
            id="malformed_criteria_summary",
        ),
    ],
)
def test_structurally_unrenderable_mappings_are_never_pinnable(corpus, mutate):
    document = json.loads(corpus.mapping_file.read_text(encoding="utf-8"))
    mutate(document)
    corpus.mapping_file.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(CrosswalkIntegrityError):
        corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)


def test_a_same_size_same_mtime_replacement_is_still_re_read(corpus):
    """Nothing is cached, so a timestamp-preserving swap cannot serve stale bytes."""
    import os

    before = corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)
    original = corpus.mapping_file.read_bytes()
    stat = corpus.mapping_file.stat()
    swapped = original.replace(b"Common Criteria", b"Common_Criteria", 1)
    assert len(swapped) == len(original) and swapped != original
    corpus.mapping_file.write_bytes(swapped)
    os.utime(corpus.mapping_file, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert corpus.mapping_file.stat().st_mtime_ns == stat.st_mtime_ns
    assert corpus.mapping_file.stat().st_size == stat.st_size

    after = corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)
    assert after.digest != before.digest
    assert after.digest == hashlib.sha256(swapped).hexdigest()


def test_rating_outside_the_declared_vocabulary_is_rejected(corpus):
    document = json.loads(corpus.mapping_file.read_text(encoding="utf-8"))
    document["points_of_focus"][0]["rating"] = "Compliant"
    corpus.mapping_file.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(CrosswalkIntegrityError):
        corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION)


def test_resolution_check_reports_findings_without_touching_ratings(
    real_mapping, real_metadata
):
    assert check_control_resolution(real_mapping, real_metadata) == []

    mapped = [row["control_id"] for row in real_mapping["control_resolution"]]
    first, second, third = mapped[0], mapped[1], mapped[2]
    broken_metadata = json.loads(json.dumps(real_metadata))
    broken_metadata["controls"] = [
        control
        for control in broken_metadata["controls"]
        if control["control_id"] != first
    ]
    for control in broken_metadata["controls"]:
        if control["control_id"] == second:
            control["automation_status"] = "blocked"
        if control["control_id"] == third:
            control["policy_file"] = "renamed.rego"
    codes = {
        finding["code"]
        for finding in check_control_resolution(real_mapping, broken_metadata)
    }
    assert codes == {"control_missing", "control_not_ready", "policy_file_mismatch"}

    # A point of focus citing a control the mapping no longer resolves.
    broken_mapping = json.loads(json.dumps(real_mapping))
    broken_mapping["control_resolution"] = [
        row
        for row in broken_mapping["control_resolution"]
        if row["control_id"] != first
    ]
    assert "unresolved_point_reference" in {
        finding["code"]
        for finding in check_control_resolution(broken_mapping, real_metadata)
    }
    # Reporting only: the mapping document is untouched.
    assert [point["rating"] for point in real_mapping["points_of_focus"]].count(
        "No"
    ) == EXPECTED_RATING_COUNTS["No"]


# ------------------------------------------------------- scan creation (mock)


@pytest.fixture
def api(monkeypatch, corpus, real_metadata):
    reader = MagicMock()
    reader.get_benchmark_metadata.return_value = real_metadata
    monkeypatch.setattr(scans, "get_file_reader", lambda: reader)
    monkeypatch.setattr(scans, "get_crosswalk_reader", lambda: corpus.reader)

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.scalar_one_or_none.return_value = SimpleNamespace(id=1)

    async def flush():
        for call in db.add.call_args_list:
            if isinstance(call.args[0], Scan):
                call.args[0].id = 9

    db.flush = AsyncMock(side_effect=flush)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    app = FastAPI()
    app.include_router(scans.router)
    app.dependency_overrides[scans.get_current_user] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[scans.get_async_session] = lambda: db
    return SimpleNamespace(client=TestClient(app), db=db, metadata=real_metadata)


def _create(api, version="v6.0.0", benchmark="microsoft-365-foundations"):
    return api.client.post(
        "/scans/",
        json={
            "m365_connection_id": 1,
            "framework": "cis",
            "benchmark": benchmark,
            "version": version,
            "control_ids": ["1.1.1", "1.1.3"],
        },
    )


def _created_scan(api):
    return next(
        call.args[0]
        for call in api.db.add.call_args_list
        if isinstance(call.args[0], Scan)
    )


def test_creation_pins_all_six_columns(api, corpus):
    assert _create(api).status_code == 201
    scan = _created_scan(api)
    assert scan.mapping_id == MAPPING_ID
    assert scan.mapping_version == MAPPING_VERSION
    assert (
        scan.mapping_digest
        == hashlib.sha256(corpus.mapping_file.read_bytes()).hexdigest()
    )
    assert scan.mapping_snapshot["mapping_id"] == MAPPING_ID
    assert len(scan.mapping_snapshot["points_of_focus"]) == EXPECTED_POINTS
    assert scan.policy_corpus_digest == policy_corpus_digest_for_directory(
        corpus.benchmark_dir
    )
    assert scan.evidence_version == "phase7-v1"
    # The snapshot is a copy: editing the file afterwards cannot reach the pin.
    corpus.mapping_file.write_text("{}", encoding="utf-8")
    assert scan.mapping_snapshot["mapping_id"] == MAPPING_ID


def test_creation_of_another_benchmark_leaves_the_mapping_null(api):
    assert _create(api, version="v3.1.0").status_code == 201
    scan = _created_scan(api)
    assert scan.mapping_id is None
    assert scan.mapping_version is None
    assert scan.mapping_digest is None
    assert scan.mapping_snapshot is None
    # Still a fully valid scan with its own frozen policy corpus identity.
    assert scan.evidence_version == "phase7-v1"
    assert scan.policy_corpus_digest is not None
    assert scan.metadata_digest is not None


def test_creation_without_a_mapping_corpus_still_succeeds(
    monkeypatch, api, tmp_path, corpus
):
    monkeypatch.setattr(
        scans,
        "get_crosswalk_reader",
        lambda: CrosswalkFileReader(
            mappings_dir=tmp_path / "absent", policies_dir=corpus.policies
        ),
    )
    assert _create(api).status_code == 201
    scan = _created_scan(api)
    assert scan.mapping_id is None
    assert scan.evidence_version == "phase7-v1"


def test_creation_refuses_when_the_applicable_mapping_is_corrupt(
    monkeypatch, api, corpus
):
    corpus.mapping_file.write_text('{"mapping_id": "half', encoding="utf-8")
    monkeypatch.setattr(scans, "get_crosswalk_reader", lambda: corpus.reader)
    response = _create(api)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "soc2_mapping_unavailable"
    api.db.add.assert_not_called()
    api.db.commit.assert_not_awaited()


def test_creation_refuses_when_a_mounted_mapping_cannot_be_read(
    monkeypatch, api, corpus
):
    """An unreadable mapping must not silently create a permanently unpinned scan."""
    corpus.mapping_file.chmod(0o000)
    monkeypatch.setattr(scans, "get_crosswalk_reader", lambda: corpus.reader)
    try:
        response = _create(api)
    finally:
        corpus.mapping_file.chmod(0o644)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "soc2_mapping_unavailable"
    api.db.add.assert_not_called()


# ------------------------------------------------------------- report harness


class _Rows:
    """Minimal stand-in for a SQLAlchemy Result."""

    def __init__(self, items):
        self._items = list(items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def scalars(self):
        return self

    def all(self):
        return list(self._items)


def _scan_row(mapping_snapshot, metadata_snapshot, **overrides):
    values = {
        "id": 9,
        "user_id": 7,
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "status": "completed",
        "total_controls": len((metadata_snapshot or {}).get("controls", [])),
        "selected_count": None,
        "semantics_version": "phase3-v1",
        "lifecycle_version": "phase6-v1",
        "evidence_version": "phase7-v1",
        "correlation_id": "synthetic-correlation",
        "metadata_snapshot": metadata_snapshot,
        "metadata_digest": "synthetic-metadata-digest",
        "connection_snapshot": {"tenant_id": "synthetic"},
        "mapping_id": MAPPING_ID,
        "mapping_version": MAPPING_VERSION,
        "mapping_digest": "synthetic-mapping-digest",
        "mapping_snapshot": mapping_snapshot,
        "policy_corpus_digest": "synthetic-policy-digest",
    }
    values.update(overrides)
    return Scan(**values)


def _result_row(control_id, status, selected=True, reason_code=None, provenance=None):
    return ScanResult(
        scan_id=9,
        control_id=control_id,
        status=status,
        selected=selected,
        reason_code=reason_code,
        provenance=provenance,
    )


def _report(scan, results=(), manual=(), user_id=7, scan_id=None):
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[_Rows([scan] if scan else []), _Rows(results), _Rows(manual)]
    )
    app = FastAPI()
    app.include_router(soc2.router)
    app.dependency_overrides[soc2.get_current_user] = lambda: SimpleNamespace(
        id=user_id
    )
    app.dependency_overrides[soc2.get_async_session] = lambda: db
    with TestClient(app) as client:
        return client.get(f"/scans/{scan_id or (scan.id if scan else 1)}/soc2-report")


def _point(response, point_id):
    return next(
        point
        for point in response.json()["points_of_focus"]
        if point["point_id"] == point_id
    )


def _synthetic_mapping(points, control_resolution=None):
    return {
        "schema_version": 1,
        "mapping_id": MAPPING_ID,
        "mapping_version": MAPPING_VERSION,
        "status": "proposed_pending_grc_approval",
        "benchmark": {
            "framework": "cis",
            "benchmark": "CIS Microsoft 365 Foundations",
            "slug": "microsoft-365-foundations",
            "version": "v6.0.0",
        },
        "soc2": {
            "framework": "SOC 2",
            "criteria_family": "Common Criteria",
            "authoritative_criteria": ["CC6", "CC7"],
        },
        "rating_vocabulary": ["Yes", "Partial", "No"],
        "approval": {
            "approved": False,
            "reviewer_name": None,
            "reviewer_role": None,
            "approved_at": None,
            "decision_reference": None,
            "note": "Unapproved draft.",
        },
        "criteria_coverage_summary": [],
        "points_of_focus": points,
        "control_resolution": control_resolution or [],
    }


def _synthetic_metadata(controls):
    return {
        "framework": "cis",
        "benchmark": "CIS Microsoft 365 Foundations",
        "slug": "microsoft-365-foundations",
        "version": "v6.0.0",
        "platform": "m365",
        "controls": controls,
    }


# ----------------------------------------------------------- report semantics


def test_report_transcribes_every_rating_verbatim(real_mapping, real_metadata):
    """A tenant that passes everything still gets the mapping's own ratings."""
    results = [
        _result_row(control["control_id"], "passed")
        for control in real_metadata["controls"]
    ]
    response = _report(_scan_row(real_mapping, real_metadata), results)
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["totals"]["points_of_focus_count"] == EXPECTED_POINTS
    assert body["totals"]["rating_counts"] == EXPECTED_RATING_COUNTS
    assert body["totals"]["unique_mapped_control_ids"] == EXPECTED_UNIQUE_CONTROL_IDS

    expected = {
        point["point_id"]: point["rating"] for point in real_mapping["points_of_focus"]
    }
    rendered = {
        point["point_id"]: point["configuration_rating"]
        for point in body["points_of_focus"]
    }
    assert rendered == expected
    assert all(
        point["rating_is_computed"] is False
        and point["rating_source"] == "pinned_mapping"
        for point in body["points_of_focus"]
    )

    # Every "No" survives a completely passing tenant.
    no_points = [
        point
        for point in body["points_of_focus"]
        if point["configuration_rating"] == "No"
    ]
    assert len(no_points) == EXPECTED_RATING_COUNTS["No"]
    assert all(point["configuration_rating"] == "No" for point in no_points)


def test_every_coverage_figure_adds_up_across_the_whole_real_mapping(
    real_mapping, real_metadata
):
    """One mixed scan, then arithmetic invariants on all 47 points at once."""
    states = ["passed", "failed", "error", "indeterminate", "not_assessable", "pending"]
    results = []
    for index, control in enumerate(real_metadata["controls"]):
        if index % 7 == 0:  # unselected
            results.append(
                _result_row(
                    control["control_id"],
                    "skipped",
                    selected=False,
                    reason_code="unselected",
                )
            )
        elif index % 11 == 0:  # no result row at all
            continue
        else:
            results.append(_result_row(control["control_id"], states[index % 6]))

    body = _report(_scan_row(real_mapping, real_metadata), results).json()
    assert len(body["points_of_focus"]) == EXPECTED_POINTS
    for point in body["points_of_focus"]:
        c = point["coverage"]
        evidence = point["automated_evidence"]
        assert (
            len(evidence)
            == c["mapped_control_count"]
            == len(point["mapped_control_ids"])
        )
        assert (
            c["in_scan_count"]
            + c["missing_result_count"]
            + c["missing_from_benchmark_count"]
            == c["mapped_control_count"]
        )
        assert c["assessed_count"] == c["passed_count"] + c["failed_count"]
        assert c["applicable_count"] == c["assessed_count"] + c["unassessed_count"]
        assert c["unassessed_count"] == (
            c["indeterminate_count"]
            + c["error_count"]
            + c["not_assessable_count"]
            + c["pending_count"]
            + c["missing_result_count"]
        )
        selected = sum(1 for row in evidence if row["in_scan"] and row["selected"])
        assert c["applicable_count"] == selected + c["missing_result_count"]
        assert c["not_in_scope_count"] == (
            c["in_scan_count"] - selected + c["missing_from_benchmark_count"]
        )
        assert (
            c["mapped_control_count"] == c["applicable_count"] + c["not_in_scope_count"]
        )
        if c["applicable_count"]:
            assert c["coverage_percent"] == round(
                100 * c["assessed_count"] / c["applicable_count"], 2
            )
        else:
            assert c["coverage_percent"] is None
        if c["assessed_count"]:
            assert c["compliance_percent"] == round(
                100 * c["passed_count"] / c["assessed_count"], 2
            )
        else:
            assert c["compliance_percent"] is None
        # Nothing above ever touched the rating.
        assert point["configuration_rating"] in {"Yes", "Partial", "No"}


def test_report_header_carries_the_unapproved_approval_block_and_disclaimer(
    real_mapping, real_metadata
):
    response = _report(_scan_row(real_mapping, real_metadata))
    header = response.json()["header"]
    assert header["approval"] == real_mapping["approval"]
    assert header["approval"]["approved"] is False
    assert header["approval_pending"] is True
    assert header["mapping_status"] == "proposed_pending_grc_approval"
    assert "not a SOC 2 certification" in header["not_a_certification"]
    assert "never creates, computes, promotes or lowers" in header["rating_ownership"]
    assert response.json()["provenance"]["rendered_from"] == "pinned_mapping_snapshot"
    assert response.json()["provenance"]["connection_snapshot_present"] is True


def test_report_renders_from_the_pin_not_the_file_on_disk(
    corpus, real_mapping, real_metadata
):
    """Editing the on-disk mapping must not change an existing scan's report."""
    scan = _scan_row(json.loads(json.dumps(real_mapping)), real_metadata)
    before = _report(scan).json()

    document = json.loads(corpus.mapping_file.read_text(encoding="utf-8"))
    for point in document["points_of_focus"]:
        point["rating"] = "Yes"
    corpus.mapping_file.write_text(json.dumps(document), encoding="utf-8")
    # The file really did change, and the reader really does see it.
    assert all(
        point["rating"] == "Yes"
        for point in corpus.reader.load_mapping(MAPPING_ID, MAPPING_VERSION).document[
            "points_of_focus"
        ]
    )

    after = _report(scan).json()
    assert after["totals"]["rating_counts"] == EXPECTED_RATING_COUNTS
    assert [point["configuration_rating"] for point in after["points_of_focus"]] == [
        point["configuration_rating"] for point in before["points_of_focus"]
    ]


def test_unpinned_scan_reports_no_projection_without_reading_disk(real_metadata):
    scan = _scan_row(
        None,
        real_metadata,
        mapping_id=None,
        mapping_version=None,
        mapping_digest=None,
    )
    body = _report(scan).json()
    assert body["projection_available"] is False
    assert body["projection_status"] == "no_projection"
    assert body["header"] is None
    assert body["points_of_focus"] == []
    assert "no SOC 2 projection" in body["message"]
    assert "deliberately not substituted" in body["message"]


def test_report_of_an_unknown_scan_is_404(real_mapping, real_metadata):
    """Owner scoping itself is proved against a real database below."""
    assert _report(None, scan_id=9).status_code == 404


def test_coverage_exposes_both_terms_and_labels_a_partial_assessment():
    """Error, indeterminate and pending stay in the denominator, unassessed."""
    controls = [
        {"control_id": cid, "automation_status": "ready", "title": f"Control {cid}"}
        for cid in ("1.1", "1.2", "1.3", "1.4", "1.5")
    ]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC6.1-P01",
                "criterion": "CC6.1",
                "point_of_focus": "Synthetic point",
                "rating": "Partial",
                "cis_control_ids": ["1.1", "1.2", "1.3", "1.4", "1.5"],
                "evidence_selector": None,
                "residual_limitation": "Synthetic limitation.",
                "residual_scope": "automated_m365_configuration",
            }
        ]
    )
    results = [
        _result_row("1.1", "passed"),
        _result_row("1.2", "error", reason_code="collector_failed"),
        _result_row("1.3", "indeterminate", reason_code="policy_undefined"),
        _result_row("1.4", "not_assessable", reason_code="automation_blocked"),
        _result_row("1.5", "skipped", selected=False, reason_code="unselected"),
    ]
    response = _report(_scan_row(mapping, _synthetic_metadata(controls)), results)
    coverage = _point(response, "CC6.1-P01")["coverage"]

    assert coverage["mapped_control_count"] == 5
    assert coverage["applicable_count"] == 4
    assert coverage["assessed_count"] == 1
    assert coverage["passed_count"] == 1
    assert coverage["failed_count"] == 0
    assert coverage["error_count"] == 1
    assert coverage["indeterminate_count"] == 1
    assert coverage["not_assessable_count"] == 1
    assert coverage["unassessed_count"] == 3
    assert coverage["not_in_scope_count"] == 1
    # 100% of what was assessed, but only a quarter of the scope was assessed.
    assert coverage["compliance_percent"] == 100.0
    assert coverage["coverage_percent"] == 25.0
    assert coverage["partial_assessment"] is True
    assert coverage["assessment_completeness"] == "partial"
    assert "1 of 4 selected controls were assessed" in coverage["coverage_statement"]

    evidence = {
        row["control_id"]: row
        for row in _point(response, "CC6.1-P01")["automated_evidence"]
    }
    assert evidence["1.5"]["selected"] is False
    assert evidence["1.5"]["status"] == "skipped"
    assert evidence["1.2"]["reason_code"] == "collector_failed"


def test_fully_assessed_point_is_labelled_complete_and_a_no_stays_no():
    controls = [
        {"control_id": cid, "automation_status": "ready"} for cid in ("2.1", "2.2")
    ]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC6.6-P02",
                "criterion": "CC6.6",
                "point_of_focus": "Synthetic point rated No",
                "rating": "No",
                "cis_control_ids": ["2.1", "2.2"],
                "evidence_selector": None,
                "residual_limitation": "Organization-level control.",
                "residual_scope": "organizational_or_inherited",
            }
        ]
    )
    results = [_result_row("2.1", "passed"), _result_row("2.2", "passed")]
    point = _point(
        _report(_scan_row(mapping, _synthetic_metadata(controls)), results),
        "CC6.6-P02",
    )
    assert point["configuration_rating"] == "No"
    assert point["rating_is_computed"] is False
    assert point["coverage"]["assessment_completeness"] == "complete"
    assert point["coverage"]["partial_assessment"] is False
    assert point["coverage"]["coverage_percent"] == 100.0
    assert point["limitations"] == {
        "residual_limitation": "Organization-level control.",
        "residual_scope": "organizational_or_inherited",
    }


def test_point_whose_controls_were_all_unselected_is_out_of_scope_not_a_gap():
    controls = [{"control_id": "3.1", "automation_status": "ready"}]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC7.2-P03",
                "criterion": "CC7.2",
                "point_of_focus": "Synthetic point",
                "rating": "Partial",
                "cis_control_ids": ["3.1", "9.9"],
                "evidence_selector": None,
                "residual_limitation": None,
                "residual_scope": None,
            }
        ]
    )
    results = [_result_row("3.1", "skipped", selected=False, reason_code="unselected")]
    point = _point(
        _report(_scan_row(mapping, _synthetic_metadata(controls)), results),
        "CC7.2-P03",
    )
    coverage = point["coverage"]
    assert coverage["applicable_count"] == 0
    assert coverage["assessed_count"] == 0
    assert coverage["coverage_percent"] is None
    assert coverage["compliance_percent"] is None
    assert coverage["assessment_completeness"] == "not_applicable"
    assert coverage["not_in_scope_count"] == 2
    assert coverage["missing_from_benchmark_count"] == 1
    assert "out of scope for it" in coverage["coverage_statement"]

    absent = next(
        row for row in point["automated_evidence"] if row["control_id"] == "9.9"
    )
    assert absent["in_benchmark"] is False
    assert absent["in_scan"] is False
    assert absent["status"] == "not_in_benchmark"
    assert absent["reason_code"] == "not_present_in_pinned_benchmark"


def test_a_missing_result_row_never_reads_as_full_coverage():
    """A control the pinned benchmark defines but the scan lost is unknown."""
    controls = [
        {"control_id": cid, "automation_status": "ready"} for cid in ("8.1", "8.2")
    ]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC6.7-P07",
                "criterion": "CC6.7",
                "point_of_focus": "Synthetic point",
                "rating": "Partial",
                "cis_control_ids": ["8.1", "8.2"],
                "evidence_selector": None,
                "residual_limitation": None,
                "residual_scope": None,
            }
        ]
    )
    # Only one of the two mapped controls has a result row at all.
    point = _point(
        _report(
            _scan_row(mapping, _synthetic_metadata(controls)),
            [_result_row("8.1", "passed")],
        ),
        "CC6.7-P07",
    )
    coverage = point["coverage"]
    assert coverage["applicable_count"] == 2
    assert coverage["assessed_count"] == 1
    assert coverage["missing_result_count"] == 1
    assert coverage["missing_from_benchmark_count"] == 0
    assert coverage["not_in_scope_count"] == 0
    assert coverage["coverage_percent"] == 50.0
    assert coverage["assessment_completeness"] == "partial"
    assert coverage["partial_assessment"] is True
    assert "no result row at all" in coverage["coverage_statement"]

    absent = next(
        row for row in point["automated_evidence"] if row["control_id"] == "8.2"
    )
    assert absent["in_benchmark"] is True
    assert absent["in_scan"] is False
    assert absent["status"] == "missing_result"
    assert absent["reason_code"] == "result_row_missing"


def test_selector_resolves_against_the_pinned_snapshot_not_live_metadata(
    real_mapping, real_metadata
):
    """CC7.1 maps to the ready controls the scan itself froze."""
    pinned = _synthetic_metadata(
        [
            {"control_id": "1.1.1", "automation_status": "ready"},
            {"control_id": "1.1.3", "automation_status": "ready"},
            {"control_id": "1.2.1", "automation_status": "blocked"},
            {"control_id": "1.3.1", "automation_status": "not_started"},
        ]
    )
    live_ready = sum(
        1
        for control in real_metadata["controls"]
        if control["automation_status"] == "ready"
    )
    assert live_ready == 69

    point = _point(
        _report(_scan_row(real_mapping, pinned), [_result_row("1.1.1", "passed")]),
        "CC7.1-P26",
    )
    assert point["evidence_selector"] == "all_automated_cis_m365_v6"
    assert point["selector_resolved"] is True
    assert point["mapped_control_ids"] == ["1.1.1", "1.1.3"]
    assert point["coverage"]["mapped_control_count"] == 2 != live_ready
    # Only one of the two pinned-ready controls has a result row. The other is a
    # missing row, which stays in the denominator rather than vanishing from it.
    assert point["coverage"]["in_scan_count"] == 1
    assert point["coverage"]["missing_from_benchmark_count"] == 0
    assert point["coverage"]["missing_result_count"] == 1
    assert point["coverage"]["applicable_count"] == 2
    assert point["coverage"]["assessed_count"] == 1
    assert point["coverage"]["coverage_percent"] == 50.0
    assert point["coverage"]["partial_assessment"] is True


def test_unknown_selector_is_flagged_and_never_widens_coverage():
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC7.1-P99",
                "criterion": "CC7.1",
                "point_of_focus": "Synthetic point with an unknown selector",
                "rating": "Partial",
                "cis_control_ids": [],
                "evidence_selector": "everything_everywhere",
                "residual_limitation": None,
                "residual_scope": None,
            }
        ]
    )
    controls = [{"control_id": "4.1", "automation_status": "ready"}]
    point = _point(
        _report(
            _scan_row(mapping, _synthetic_metadata(controls)),
            [_result_row("4.1", "passed")],
        ),
        "CC7.1-P99",
    )
    assert point["selector_resolved"] is False
    assert point["mapped_control_ids"] == []
    assert point["coverage"]["assessment_completeness"] == "no_automated_coverage"
    assert point["coverage"]["coverage_percent"] is None


def test_manual_evidence_is_a_separate_stream_that_never_raises_coverage():
    controls = [
        {"control_id": cid, "automation_status": "ready"} for cid in ("5.1", "5.2")
    ]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC6.2-P04",
                "criterion": "CC6.2",
                "point_of_focus": "Synthetic point",
                "rating": "Partial",
                "cis_control_ids": ["5.1", "5.2"],
                "evidence_selector": None,
                "residual_limitation": None,
                "residual_scope": None,
            }
        ]
    )
    results = [
        _result_row("5.1", "failed"),
        _result_row("5.2", "not_assessable", reason_code="automation_blocked"),
    ]
    scan = _scan_row(mapping, _synthetic_metadata(controls))
    without = _point(_report(scan, results), "CC6.2-P04")["coverage"]

    record = ManualEvidenceRecord(
        id=3,
        scan_id=9,
        scan_result_id=11,
        control_id="5.2",
        user_id=7,
        reviewer_user_id=8,
        evidence_source="inherited",
        status="approved",
        control_owner="Security lead",
        evidence_owner="Provider",
        cadence="annual",
        retention_policy_version="phase7-draft-1",
        current_revision_number=2,
    )
    response = _report(scan, results, manual=[record])
    point = _point(response, "CC6.2-P04")

    assert point["coverage"] == without
    assert point["coverage"]["assessed_count"] == 1
    assert point["coverage"]["compliance_percent"] == 0.0
    assert len(point["manual_residual_evidence"]) == 1
    entry = point["manual_residual_evidence"][0]
    assert entry["control_id"] == "5.2"
    assert entry["evidence_source"] == "inherited"
    assert entry["counted_in_automated_coverage"] is False
    stream = response.json()["manual_evidence_stream"]
    assert stream["available"] is True
    assert stream["approved_record_count"] == 1
    assert stream["counted_in_automated_coverage"] is False


def test_manual_evidence_read_failure_reports_unknown_not_none():
    from sqlalchemy.exc import OperationalError

    controls = [{"control_id": "6.1", "automation_status": "ready"}]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC6.3-P05",
                "criterion": "CC6.3",
                "point_of_focus": "Synthetic point",
                "rating": "Yes",
                "cis_control_ids": ["6.1"],
                "evidence_selector": None,
                "residual_limitation": None,
                "residual_scope": None,
            }
        ]
    )
    scan = _scan_row(mapping, _synthetic_metadata(controls))
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            _Rows([scan]),
            _Rows([_result_row("6.1", "passed")]),
            OperationalError("synthetic", None, Exception("synthetic")),
        ]
    )
    app = FastAPI()
    app.include_router(soc2.router)
    app.dependency_overrides[soc2.get_current_user] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[soc2.get_async_session] = lambda: db
    with TestClient(app) as client:
        body = client.get("/scans/9/soc2-report").json()
    stream = body["manual_evidence_stream"]
    assert stream["available"] is False
    assert "unknown, not none" in stream["note"]
    assert body["points_of_focus"][0]["coverage"]["assessed_count"] == 1


@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param({"points_of_focus": "not a list"}, id="scalar_points"),
        pytest.param({"points_of_focus": [1, 2, 3]}, id="non_object_points"),
    ],
)
def test_a_structurally_broken_pin_reports_no_projection(hostile):
    """A pin that cannot be rendered is no projection, never a blank pass."""
    body = _report(_scan_row(hostile, _synthetic_metadata([]))).json()
    assert body["projection_available"] is False
    assert body["projection_status"] == "no_projection"


def test_a_hostile_pinned_snapshot_never_raises_or_reads_as_approved():
    """A pin that did not come through the loader still cannot 500 or self-approve."""
    hostile = {
        "mapping_id": "soc2-common-criteria-to-cis-m365",
        "mapping_version": "v1.0.0",
        "status": ["not", "a", "string"],
        "schema_version": "one",
        "soc2": ["not an object"],
        "benchmark": "not an object",
        "source": 12,
        # Pydantic's lax boolean parsing would read "yes" as true.
        "approval": {"approved": "yes", "note": "Preserved verbatim."},
        "rating_vocabulary": {"Yes": 1},
        "criteria_coverage_summary": [
            "not an object",
            {"criterion": "CC6", "configuration_coverage_classification": 7},
        ],
        "control_resolution": [None, {"control_id": 5}],
        "points_of_focus": [
            None,
            "not an object",
            {
                "point_id": "CC6.1-P01",
                "criterion": "CC6.1",
                "point_of_focus": "Synthetic",
                "rating": "No",
                "cis_control_ids": "9.9",
                "evidence_selector": 42,
                "residual_limitation": {"nested": "object"},
                "residual_scope": None,
            },
        ],
    }
    scan = _scan_row(hostile, {"controls": "not a list"})
    response = _report(scan, [_result_row("9.9", "passed")])
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["header"]["approval"]["approved"] is False
    assert body["header"]["approval_pending"] is True
    assert body["header"]["approval"]["note"] == "Preserved verbatim."
    assert body["header"]["rating_vocabulary"] == []
    assert body["header"]["mapping_status"] is None
    assert body["criteria_coverage_summary"] == [
        {"criterion": "CC6", "configuration_coverage_classification": None}
    ]
    assert body["mapping_resolution_findings"] == []

    point = body["points_of_focus"][0]
    assert point["configuration_rating"] == "No"
    # A string is not a list of control ids: nothing is mapped, so nothing is
    # covered, and the passing 9.9 result is not borrowed by this point.
    assert point["mapped_control_ids"] == []
    assert point["evidence_selector"] is None
    assert point["coverage"]["coverage_percent"] is None
    assert point["coverage"]["assessment_completeness"] == "no_automated_coverage"
    assert body["totals"]["unique_mapped_control_ids"] == 0


def test_report_publishes_execution_provenance_but_no_collected_payload():
    controls = [{"control_id": "7.1", "automation_status": "ready"}]
    mapping = _synthetic_mapping(
        [
            {
                "point_id": "CC7.3-P06",
                "criterion": "CC7.3",
                "point_of_focus": "Synthetic point",
                "rating": "Yes",
                "cis_control_ids": ["7.1"],
                "evidence_selector": None,
                "residual_limitation": None,
                "residual_scope": None,
            }
        ]
    )
    provenance = {
        "policy_file": "7.1.rego",
        "policy_digest": "synthetic-policy-digest",
        "opa_version": "1.20.2",
        "provenance_status": "executed",
        # The worker stores the complete Rego source here. File content must
        # never leave in a response, however non-secret it looks.
        "policy_source": "package cis\nallow := true\n",
        "tenant_secret": "should-never-be-published",  # pragma: allowlist secret - synthetic value the test proves is NOT published
        "raw_collector_output": {"users": ["a@example.invalid"]},
    }
    point = _point(
        _report(
            _scan_row(mapping, _synthetic_metadata(controls)),
            [_result_row("7.1", "passed", provenance=provenance)],
        ),
        "CC7.3-P06",
    )
    published = point["automated_evidence"][0]["provenance"]
    assert published == {
        "policy_file": "7.1.rego",
        "policy_digest": "synthetic-policy-digest",
        "opa_version": "1.20.2",
        "provenance_status": "executed",
    }
    body = json.dumps(point)
    assert "tenant_secret" not in body
    assert "example.invalid" not in body
    assert "policy_source" not in body
    assert "package cis" not in body
    assert "policy_source" not in soc2.PUBLISHABLE_PROVENANCE_FIELDS


# ------------------------------------------------------ real database (pin)


def _app_over(database_url, monkeypatch, corpus, metadata, user):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(
        database_url.replace("postgresql://", "postgresql+asyncpg://"),
        poolclass=NullPool,
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def db():
        async with sessions() as session:
            yield session

    reader = MagicMock()
    reader.get_benchmark_metadata.return_value = metadata
    monkeypatch.setattr(scans, "get_file_reader", lambda: reader)
    monkeypatch.setattr(scans, "get_crosswalk_reader", lambda: corpus.reader)

    app = FastAPI()
    app.include_router(scans.router)
    app.include_router(soc2.router)
    app.dependency_overrides[scans.get_async_session] = db
    app.dependency_overrides[scans.get_current_user] = lambda: user
    app.dependency_overrides[soc2.get_async_session] = db
    app.dependency_overrides[soc2.get_current_user] = lambda: user
    return app, engine


SEED = """
INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
VALUES(1,'user','owner@example.invalid','synthetic',true,false,true),
      (2,'user','reviewer@example.invalid','synthetic',true,false,true);
INSERT INTO m365_connection(id,user_id,name,tenant_id,client_id,encrypted_client_secret)
VALUES(1,1,'Synthetic','synthetic','synthetic','synthetic-ciphertext');
"""

FROZEN_COLUMNS = {
    "mapping_id": "'other-mapping'",
    "mapping_version": "'v9.9.9'",
    "mapping_digest": "'0000000000000000000000000000000000000000000000000000000000000000'",
    "mapping_snapshot": "'{\"points_of_focus\": []}'::jsonb",
    "policy_corpus_digest": "'1111111111111111111111111111111111111111111111111111111111111111'",
    "evidence_version": "'phase7-v2'",
}


def test_real_creation_pins_the_mapping_and_the_columns_cannot_be_updated(
    database_url, monkeypatch, corpus, real_metadata
):
    _alembic(database_url, "upgrade", "head")
    asyncio.run(_query(database_url, SEED, execute=True))
    user = SimpleNamespace(id=1)
    app, engine = _app_over(database_url, monkeypatch, corpus, real_metadata, user)

    with TestClient(app) as client:
        created = client.post(
            "/scans/",
            json={
                "m365_connection_id": 1,
                "framework": "cis",
                "benchmark": "microsoft-365-foundations",
                "version": "v6.0.0",
                "control_ids": ["1.1.1", "1.1.3", "1.2.1"],
            },
        )
        assert created.status_code == 201, created.text
        scan_id = created.json()["id"]

        row = asyncio.run(
            _query(
                database_url, "SELECT * FROM scan WHERE id = $1", parameters=(scan_id,)
            )
        )[0]
        assert row["mapping_id"] == MAPPING_ID
        assert row["mapping_version"] == MAPPING_VERSION
        assert (
            row["mapping_digest"]
            == hashlib.sha256(corpus.mapping_file.read_bytes()).hexdigest()
        )
        assert row["policy_corpus_digest"] == policy_corpus_digest_for_directory(
            corpus.benchmark_dir
        )
        assert row["evidence_version"] == "phase7-v1"
        assert json.loads(row["mapping_snapshot"])["mapping_id"] == MAPPING_ID

        # Every pinned column is frozen by the database, not by convention.
        for column, literal in FROZEN_COLUMNS.items():
            with pytest.raises(asyncpg.PostgresError) as raised:
                asyncio.run(
                    _query(
                        database_url,
                        f"UPDATE scan SET {column} = {literal} WHERE id = $1",  # nosec B608 # fixed column/literal pairs from this module
                        execute=True,
                        parameters=(scan_id,),
                    )
                )
            assert "Phase 3 scan inputs are immutable" in str(raised.value)

        after = asyncio.run(
            _query(
                database_url, "SELECT * FROM scan WHERE id = $1", parameters=(scan_id,)
            )
        )[0]
        assert after["mapping_digest"] == row["mapping_digest"]

        provenance = client.get(f"/scans/{scan_id}/provenance").json()
        assert provenance["mapping_id"] == MAPPING_ID
        assert provenance["mapping_approved"] is False
        assert provenance["mapping_snapshot_present"] is True
        assert provenance["mapping_points_of_focus_count"] == EXPECTED_POINTS
        assert provenance["soc2_projection_available"] is True
        assert provenance["metadata_snapshot_present"] is True
        assert provenance["metadata_control_count"] == len(real_metadata["controls"])
        assert provenance["policy_corpus_digest"] == row["policy_corpus_digest"]
        assert provenance["connection_snapshot_present"] is True
        assert provenance["connection_snapshot_fields"] == ["client_id", "tenant_id"]
        # Presence only: no tenant or client value is ever returned.
        assert "synthetic" not in json.dumps(provenance)

        # Owner scoping, against the real predicate and a real row.
        user.id = 2
        assert client.get(f"/scans/{scan_id}/soc2-report").status_code == 404
        assert client.get(f"/scans/{scan_id}/provenance").status_code == 404
        user.id = 1
        assert client.get(f"/scans/{scan_id}/soc2-report").status_code == 200

        detail = client.get(f"/scans/{scan_id}").json()
        assert detail["mapping_id"] == MAPPING_ID
        assert detail["evidence_version"] == "phase7-v1"
        assert detail["policy_corpus_digest"] == row["policy_corpus_digest"]
        assert "mapping_snapshot" not in detail
        assert "metadata_snapshot" not in detail
        listed = client.get("/scans/").json()[0]
        assert listed["mapping_digest"] == row["mapping_digest"]
        assert "mapping_snapshot" not in listed

        # One selected control passes, one fails, one is left pending.
        for control_id, state in (("1.1.1", "passed"), ("1.1.3", "failed")):
            asyncio.run(
                _query(
                    database_url,
                    "UPDATE scan_result SET status = $2"
                    " WHERE scan_id = $1 AND control_id = $3",
                    execute=True,
                    parameters=(scan_id, state, control_id),
                )
            )
        # Approved inherited evidence for the failing control, from a reviewer
        # who is not the submitter.
        asyncio.run(
            _query(
                database_url,
                """
                INSERT INTO manual_evidence_record
                    (scan_result_id, scan_id, control_id, user_id, reviewer_user_id,
                     evidence_source, status, retention_policy_version,
                     current_revision_number, reviewed_at)
                SELECT id, scan_id, control_id, 1, 2, 'inherited', 'approved',
                       'phase7-draft-1', 1, now()
                FROM scan_result WHERE scan_id = $1 AND control_id = '1.1.3';
                """,
                execute=True,
                parameters=(scan_id,),
            )
        )

        report = client.get(f"/scans/{scan_id}/soc2-report").json()
        assert report["projection_available"] is True
        assert report["totals"]["rating_counts"] == EXPECTED_RATING_COUNTS
        assert report["header"]["approval"]["approved"] is False
        assert report["provenance"]["mapping_digest"] == row["mapping_digest"]
        assert (
            report["provenance"]["policy_corpus_digest"] == row["policy_corpus_digest"]
        )
        assert report["mapping_resolution_findings"] == []
        assert report["manual_evidence_stream"]["approved_record_count"] == 1

        manual_points = [
            point
            for point in report["points_of_focus"]
            if point["manual_residual_evidence"]
        ]
        assert manual_points
        for point in manual_points:
            assert point["manual_residual_evidence"][0]["control_id"] == "1.1.3"
            assert (
                point["manual_residual_evidence"][0]["counted_in_automated_coverage"]
                is False
            )
            # The manual record does not enter the automated arithmetic.
            assert point["coverage"]["assessed_count"] == (
                point["coverage"]["passed_count"] + point["coverage"]["failed_count"]
            )

        selector_point = _point(SimpleNamespace(json=lambda: report), "CC7.1-P26")
        assert selector_point["coverage"]["applicable_count"] == 3
        assert selector_point["coverage"]["assessed_count"] == 2
        assert selector_point["coverage"]["partial_assessment"] is True
        assert selector_point["coverage"]["compliance_percent"] == 50.0
        assert selector_point["coverage"]["mapped_control_count"] == 69

    asyncio.run(engine.dispose())


def test_real_scan_of_another_benchmark_has_a_null_pin_and_no_projection(
    database_url, monkeypatch, corpus
):
    _alembic(database_url, "upgrade", "head")
    asyncio.run(_query(database_url, SEED, execute=True))
    metadata = {
        "platform": "m365",
        "framework": "cis",
        "slug": "microsoft-365-foundations",
        "version": "v3.1.0",
        "controls": [{"control_id": "1.1.1", "automation_status": "ready"}],
    }
    user = SimpleNamespace(id=1)
    app, engine = _app_over(database_url, monkeypatch, corpus, metadata, user)

    with TestClient(app) as client:
        created = client.post(
            "/scans/",
            json={
                "m365_connection_id": 1,
                "framework": "cis",
                "benchmark": "microsoft-365-foundations",
                "version": "v3.1.0",
                "control_ids": ["1.1.1"],
            },
        )
        assert created.status_code == 201, created.text
        scan_id = created.json()["id"]
        row = asyncio.run(
            _query(
                database_url, "SELECT * FROM scan WHERE id = $1", parameters=(scan_id,)
            )
        )[0]
        assert row["mapping_id"] is None
        assert row["mapping_version"] is None
        assert row["mapping_digest"] is None
        assert row["mapping_snapshot"] is None
        assert row["evidence_version"] == "phase7-v1"
        assert row["policy_corpus_digest"] == policy_corpus_digest_for_directory(
            corpus.policies / "cis/microsoft-365-foundations/v3.1.0"
        )

        report = client.get(f"/scans/{scan_id}/soc2-report").json()
        assert report["projection_available"] is False
        assert report["projection_status"] == "no_projection"
        assert report["header"] is None
        provenance = client.get(f"/scans/{scan_id}/provenance").json()
        assert provenance["soc2_projection_available"] is False
        assert provenance["mapping_snapshot_present"] is False

    asyncio.run(engine.dispose())
