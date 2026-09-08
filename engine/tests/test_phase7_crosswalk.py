"""The SOC 2 crosswalk resolves structurally and no code path may touch a rating."""

from __future__ import annotations

import builtins
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from collectors.registry import DATA_COLLECTORS
from worker import crosswalk

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "engine"
MAPPINGS = ENGINE / "mappings"
POLICIES = ENGINE / "policies"
MODULE_PATH = ENGINE / "worker" / "crosswalk.py"
BENCHMARK = ("cis", "microsoft-365-foundations", "v6.0.0")

MAPPING_PATH = crosswalk.mapping_path(root=MAPPINGS)
MAPPING = crosswalk.load_mapping(MAPPING_PATH)
METADATA = crosswalk.load_metadata(*BENCHMARK, root=POLICIES)
REGISTRY = frozenset(DATA_COLLECTORS)
SOURCE = MODULE_PATH.read_text(encoding="utf-8")

# The human-owned Appendix A ratings, transcribed once here so any silent edit to
# the artifact fails the suite. A histogram alone would let two ratings be swapped
# unnoticed, so each point of focus is pinned to its own reviewed rating. Nothing
# in the engine may change these values; only a GRC reviewer may.
EXPECTED_RATING_BY_POINT = {
    "CC6.1-P01": "No",
    "CC6.1-P02": "Yes",
    "CC6.1-P03": "Yes",
    "CC6.1-P04": "No",
    "CC6.1-P05": "Yes",
    "CC6.1-P06": "Partial",
    "CC6.2-P07": "Yes",
    "CC6.2-P08": "Yes",
    "CC6.3-P09": "Yes",
    "CC6.3-P10": "Yes",
    "CC6.3-P11": "Yes",
    "CC6.4-P12": "No",
    "CC6.4-P13": "No",
    "CC6.5-P14": "No",
    "CC6.5-P15": "No",
    "CC6.6-P16": "Partial",
    "CC6.6-P17": "Yes",
    "CC6.6-P18": "Yes",
    "CC6.6-P19": "Partial",
    "CC6.7-P20": "Partial",
    "CC6.7-P21": "Partial",
    "CC6.7-P22": "No",
    "CC6.8-P23": "Partial",
    "CC6.8-P24": "Partial",
    "CC6.8-P25": "No",
    "CC7.1-P26": "Yes",
    "CC7.1-P27": "Partial",
    "CC7.1-P28": "Partial",
    "CC7.1-P29": "Partial",
    "CC7.1-P30": "No",
    "CC7.2-P31": "Yes",
    "CC7.2-P32": "Yes",
    "CC7.2-P33": "Partial",
    "CC7.2-P34": "Partial",
    "CC7.3-P35": "Partial",
    "CC7.3-P36": "Partial",
    "CC7.3-P37": "No",
    "CC7.3-P38": "No",
    "CC7.4-P39": "No",
    "CC7.4-P40": "Partial",
    "CC7.4-P41": "No",
    "CC7.4-P42": "Partial",
    "CC7.4-P43": "No",
    "CC7.4-P44": "No",
    "CC7.5-P45": "No",
    "CC7.5-P46": "No",
    "CC7.5-P47": "No",
}
EXPECTED_RATINGS = {"Yes": 13, "Partial": 16, "No": 18}
EXPECTED_POINTS = 47
EXPECTED_CONTROLS = 44


def _point(mapping: dict, point_id: str) -> dict:
    return next(p for p in mapping["points_of_focus"] if p["point_id"] == point_id)


def _row(mapping: dict, control_id: str) -> dict:
    return next(
        r for r in mapping["control_resolution"] if r["control_id"] == control_id
    )


def _control(metadata: dict, control_id: str) -> dict:
    return next(c for c in metadata["controls"] if c["control_id"] == control_id)


def _real(value):
    """Swap a placeholder name for the real artifact; anything else passes through."""
    if isinstance(value, str):
        return {
            "MAPPING": MAPPING,
            "METADATA": METADATA,
            "REGISTRY": REGISTRY,
            "POLICIES": POLICIES,
        }.get(value, value)
    return value


# ---------------------------------------------------------------------------
# The mapping resolves today
# ---------------------------------------------------------------------------


def test_mapping_resolves_with_zero_findings():
    assert crosswalk.validate_mapping(MAPPING, METADATA, REGISTRY, POLICIES) == []


def test_mapping_pins_the_benchmark_it_is_validated_against():
    assert MAPPING["benchmark"]["framework"] == METADATA["framework"]
    assert MAPPING["benchmark"]["slug"] == METADATA["slug"]
    assert MAPPING["benchmark"]["version"] == METADATA["version"]
    assert MAPPING["mapping_version"] == crosswalk.DEFAULT_MAPPING_VERSION


def test_selector_row_expands_to_every_ready_control():
    ready = crosswalk.ready_control_ids(METADATA)
    resolved = {
        point.point_id: point
        for point in crosswalk.resolve_points_of_focus(MAPPING, METADATA)
    }
    selector_row = resolved["CC7.1-P26"]
    assert selector_row.evidence_selector == crosswalk.ALL_READY_SELECTOR
    assert selector_row.control_ids == ready
    assert len(ready) == 69
    # Expansion is a read: the artifact still carries an empty explicit list.
    assert _point(MAPPING, "CC7.1-P26")["cis_control_ids"] == []


def test_a_selector_always_widens_a_row_rather_than_being_ignored():
    """resolve_points_of_focus and validate_mapping must agree on the population."""
    mapping = deepcopy(MAPPING)
    _point(mapping, "CC7.1-P26")["cis_control_ids"] = ["7.2.1"]
    assert _control(METADATA, "7.2.1")["automation_status"] != crosswalk.READY_STATUS

    resolved = {
        point.point_id: point
        for point in crosswalk.resolve_points_of_focus(mapping, METADATA)
    }
    assert set(resolved["CC7.1-P26"].control_ids) == {"7.2.1"} | set(
        crosswalk.ready_control_ids(METADATA)
    )
    # And the validator sees the same widened population, so it cannot pass.
    codes = {
        finding.code
        for finding in crosswalk.validate_mapping(mapping, METADATA, REGISTRY, POLICIES)
    }
    assert crosswalk.CONTROL_NOT_READY in codes


def test_validator_returns_structured_findings_instead_of_raising():
    findings = crosswalk.validate_mapping({}, {}, ())
    assert findings
    assert all(isinstance(finding, crosswalk.Finding) for finding in findings)
    assert all(
        finding.code and finding.severity and finding.subject and finding.detail
        for finding in findings
    )


# ---------------------------------------------------------------------------
# Rating preservation
# ---------------------------------------------------------------------------


def test_rating_distribution_is_exactly_the_reviewed_appendix():
    points = MAPPING["points_of_focus"]
    assert len(points) == EXPECTED_POINTS
    assert Counter(point["rating"] for point in points) == EXPECTED_RATINGS
    assert set(MAPPING["rating_vocabulary"]) == set(EXPECTED_RATINGS)


def test_every_point_of_focus_keeps_its_own_reviewed_rating():
    assert {
        point["point_id"]: point["rating"] for point in MAPPING["points_of_focus"]
    } == EXPECTED_RATING_BY_POINT


def test_mapping_resolves_exactly_forty_four_unique_controls():
    ids = crosswalk.mapping_control_ids(MAPPING)
    referenced = {
        control_id
        for point in MAPPING["points_of_focus"]
        for control_id in point["cis_control_ids"]
    }
    assert len(ids) == EXPECTED_CONTROLS
    assert len(set(ids)) == EXPECTED_CONTROLS
    assert set(ids) == referenced


def test_resolution_copies_every_rating_verbatim():
    resolved = crosswalk.resolve_points_of_focus(MAPPING, METADATA)
    assert [point.rating for point in resolved] == [
        point["rating"] for point in MAPPING["points_of_focus"]
    ]


def test_validation_never_mutates_the_mapping_or_the_metadata():
    mapping = deepcopy(MAPPING)
    metadata = deepcopy(METADATA)
    crosswalk.validate_mapping(mapping, metadata, REGISTRY, POLICIES)
    crosswalk.resolve_points_of_focus(mapping, metadata)
    assert mapping == MAPPING
    assert metadata == METADATA


def test_validation_writes_no_file(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("crosswalk validation must never write")

    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in "wxa+"):
            refuse()
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", refuse)
    monkeypatch.setattr(Path, "write_bytes", refuse)
    monkeypatch.setattr(Path, "mkdir", refuse)
    monkeypatch.setattr(Path, "unlink", refuse)
    monkeypatch.setattr(builtins, "open", guarded_open)
    assert crosswalk.validate_mapping(MAPPING, METADATA, REGISTRY, POLICIES) == []


@pytest.mark.parametrize(
    "forbidden",
    [
        "write_text(",
        "write_bytes(",
        "mkdir(",
        "unlink(",
        "os.remove",
        "shutil",
        '["rating"] =',
        ".rating =",
        "setattr(",
    ],
)
def test_module_source_neither_writes_nor_assigns_a_rating(forbidden):
    assert forbidden not in SOURCE


def test_module_import_touches_no_file(monkeypatch):
    """Executing the module body must not read or write anything."""

    def refuse(*args, **kwargs):
        raise AssertionError("importing worker.crosswalk must not touch the filesystem")

    monkeypatch.setattr(builtins, "open", refuse)
    monkeypatch.setattr(Path, "read_bytes", refuse)
    monkeypatch.setattr(Path, "read_text", refuse)
    monkeypatch.setattr(Path, "write_text", refuse)
    monkeypatch.setattr(Path, "glob", refuse)
    spec = importlib.util.spec_from_file_location("phase7_import_probe", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.SCHEMA_VERSION == crosswalk.SCHEMA_VERSION


def test_module_needs_no_worker_configuration(tmp_path):
    """A fresh interpreter must load the mapping without building WorkerSettings.

    ``APP_ENV=test`` makes ``worker.config`` refuse the development defaults, so
    this fails loudly if the module ever imports settings at module scope. The
    probe loads the file directly because importing ``worker.crosswalk`` also
    runs ``worker/__init__.py``, which builds the Celery app and the settings.
    """
    probe = (
        "import importlib.util, sys;"
        f"spec = importlib.util.spec_from_file_location('probe', {str(MODULE_PATH)!r});"
        "module = importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(module);"
        "print(len(module.mapping_control_ids()), 'worker.config' in sys.modules)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        env={**os.environ, "APP_ENV": "test"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.split() == [str(EXPECTED_CONTROLS), "False"]


# ---------------------------------------------------------------------------
# Approval honesty
# ---------------------------------------------------------------------------


def test_approval_block_claims_no_grc_approval():
    approval = MAPPING["approval"]
    assert approval["approved"] is False
    assert approval["reviewer_name"] is None
    assert approval["reviewer_role"] is None
    assert approval["approved_at"] is None
    assert approval["decision_reference"] is None
    assert MAPPING["status"] == "proposed_pending_grc_approval"


# ---------------------------------------------------------------------------
# Digest sensitivity (plan 15.3: a policy/metadata/mapping edit moves its digest)
# ---------------------------------------------------------------------------

REAL_DIGESTS = {
    "mapping": crosswalk.mapping_digest(MAPPING_PATH),
    "metadata": crosswalk.benchmark_metadata_digest(*BENCHMARK, root=POLICIES),
    "policy_corpus": crosswalk.policy_corpus_digest(*BENCHMARK, root=POLICIES),
}


@pytest.fixture
def artifact_copy(tmp_path):
    """Throwaway copies of the real artifacts; the originals are never touched."""
    mappings = tmp_path / "mappings"
    policies = tmp_path / "policies"
    shutil.copytree(MAPPINGS, mappings)
    shutil.copytree(
        POLICIES / BENCHMARK[0] / BENCHMARK[1] / BENCHMARK[2],
        policies / BENCHMARK[0] / BENCHMARK[1] / BENCHMARK[2],
    )
    return mappings, policies


def _digests(mappings: Path, policies: Path) -> dict[str, str]:
    return {
        "mapping": crosswalk.mapping_digest(crosswalk.mapping_path(root=mappings)),
        "metadata": crosswalk.benchmark_metadata_digest(*BENCHMARK, root=policies),
        "policy_corpus": crosswalk.policy_corpus_digest(*BENCHMARK, root=policies),
    }


def _edit_mapping(mappings: Path, policies: Path) -> None:
    path = crosswalk.mapping_path(root=mappings)
    # Whitespace only: the mapping digest is over raw bytes, so this must move it.
    path.write_bytes(path.read_bytes() + b"\n")


def _edit_metadata(mappings: Path, policies: Path) -> None:
    path = crosswalk.metadata_path(*BENCHMARK, root=policies)
    metadata = json.loads(path.read_text(encoding="utf-8"))
    metadata["controls"][0]["notes"] = "synthetic drift"
    path.write_text(json.dumps(metadata), encoding="utf-8")


def _edit_policy(mappings: Path, policies: Path) -> None:
    path = (
        crosswalk.benchmark_dir(*BENCHMARK, root=policies)
        / "1.1.1_admin_cloud_only.rego"
    )
    path.write_text(path.read_text(encoding="utf-8") + "\n# synthetic drift\n")


@pytest.mark.parametrize(
    "edit,moved",
    [
        (_edit_mapping, "mapping"),
        (_edit_metadata, "metadata"),
        (_edit_policy, "policy_corpus"),
    ],
    ids=["mapping.json", "metadata.json", "policy.rego"],
)
def test_editing_one_artifact_moves_exactly_one_digest(artifact_copy, edit, moved):
    mappings, policies = artifact_copy
    before = _digests(mappings, policies)
    assert before == REAL_DIGESTS
    edit(mappings, policies)
    after = _digests(mappings, policies)
    assert after[moved] != before[moved]
    assert {name: after[name] for name in after if name != moved} == {
        name: before[name] for name in before if name != moved
    }
    # The real artifacts must be untouched by any of this.
    assert _digests(MAPPINGS, POLICIES) == REAL_DIGESTS


def test_mapping_digest_is_taken_over_raw_file_bytes():
    data = MAPPING_PATH.read_bytes()
    assert crosswalk.mapping_digest(data) == crosswalk.mapping_digest(MAPPING_PATH)
    # Re-serialised JSON with identical content still hashes differently.
    assert (
        crosswalk.mapping_digest(json.dumps(MAPPING).encode())
        != REAL_DIGESTS["mapping"]
    )


def test_policy_corpus_digest_covers_every_rego_not_just_metadata(artifact_copy):
    mappings, policies = artifact_copy
    directory = crosswalk.benchmark_dir(*BENCHMARK, root=policies)
    before = crosswalk.policy_corpus_digest(*BENCHMARK, root=policies)
    assert len(list(directory.glob("*.rego"))) == 69
    (directory / "1.1.1_admin_cloud_only.rego").unlink()
    assert crosswalk.policy_corpus_digest(*BENCHMARK, root=policies) != before
    assert (
        crosswalk.benchmark_metadata_digest(*BENCHMARK, root=policies)
        == (REAL_DIGESTS["metadata"])
    )


def test_policy_corpus_digest_rejects_an_empty_benchmark(tmp_path):
    (tmp_path / BENCHMARK[0] / BENCHMARK[1] / BENCHMARK[2]).mkdir(parents=True)
    with pytest.raises(ValueError, match="No Rego policies"):
        crosswalk.policy_corpus_digest(*BENCHMARK, root=tmp_path)


@pytest.mark.parametrize("segment", ["..", "../etc", "cis/../..", ""])
def test_benchmark_paths_reject_traversal(segment):
    with pytest.raises(ValueError):
        crosswalk.benchmark_dir(segment, BENCHMARK[1], BENCHMARK[2], POLICIES)


def test_a_symlinked_benchmark_directory_is_rejected(tmp_path):
    outside = tmp_path / "outside" / BENCHMARK[0]
    (outside / BENCHMARK[1] / BENCHMARK[2]).mkdir(parents=True)
    root = tmp_path / "root"
    root.mkdir()
    (root / BENCHMARK[0]).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes its root"):
        crosswalk.benchmark_dir(*BENCHMARK, root=root)


def test_a_symlinked_policy_is_rejected(artifact_copy, tmp_path):
    _, policies = artifact_copy
    outside = tmp_path / "outside.rego"
    outside.write_text("package outside\n")
    directory = crosswalk.benchmark_dir(*BENCHMARK, root=policies)
    (directory / "9.9.9_outside.rego").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes its root"):
        crosswalk.policy_corpus_digest(*BENCHMARK, root=policies)


# ---------------------------------------------------------------------------
# Drift cases: each mutation of an in-memory copy raises its own finding code
# ---------------------------------------------------------------------------


def _unknown_control(mapping, metadata, registry):
    _point(mapping, "CC6.1-P02")["cis_control_ids"].append("9.9.9")
    mapping["control_resolution"].append(
        {
            "control_id": "9.9.9",
            "policy_file": "9.9.9_absent.rego",
            "data_collector_id": "entra.groups.groups",
        }
    )


def _downgraded_automation_status(mapping, metadata, registry):
    _control(metadata, "1.1.1")["automation_status"] = "blocked"


def _policy_file_mismatch(mapping, metadata, registry):
    _row(mapping, "1.1.1")["policy_file"] = "1.1.3_global_admin_count.rego"


def _policy_file_absent_on_disk(mapping, metadata, registry):
    _control(metadata, "1.1.1")["policy_file"] = "1.1.1_deleted.rego"
    _row(mapping, "1.1.1")["policy_file"] = "1.1.1_deleted.rego"


def _collector_id_mismatch(mapping, metadata, registry):
    _row(mapping, "1.1.1")["data_collector_id"] = "entra.groups.groups"


def _unregistered_collector(mapping, metadata, registry):
    registry.discard("entra.roles.cloud_only_admins")


def _benchmark_identity_mismatch(mapping, metadata, registry):
    mapping["benchmark"]["version"] = "v5.0.0"


def _rating_outside_vocabulary(mapping, metadata, registry):
    _point(mapping, "CC6.1-P02")["rating"] = "Maybe"


def _no_rating_carrying_controls(mapping, metadata, registry):
    _point(mapping, "CC6.1-P01")["cis_control_ids"] = ["1.1.1"]


def _duplicate_point_id(mapping, metadata, registry):
    mapping["points_of_focus"].append(deepcopy(mapping["points_of_focus"][0]))


def _missing_resolution_row(mapping, metadata, registry):
    mapping["control_resolution"] = [
        row for row in mapping["control_resolution"] if row["control_id"] != "1.1.1"
    ]


def _unreferenced_resolution_row(mapping, metadata, registry):
    mapping["control_resolution"].append(
        {
            "control_id": "1.2.2",
            "policy_file": "1.2.2_shared_mailbox_signin_blocked.rego",
            "data_collector_id": "exchange.mailbox.mailboxes",
        }
    )


def _duplicate_resolution_row(mapping, metadata, registry):
    mapping["control_resolution"].append(deepcopy(_row(mapping, "1.1.1")))


def _unknown_evidence_selector(mapping, metadata, registry):
    _point(mapping, "CC7.1-P26")["evidence_selector"] = "everything_we_wish_we_had"


def _unsupported_schema_version(mapping, metadata, registry):
    mapping["schema_version"] = 2


def _unbacked_approval_claim(mapping, metadata, registry):
    mapping["approval"]["approved"] = True


def _missing_criterion(mapping, metadata, registry):
    mapping["criteria_coverage_summary"] = [
        row for row in mapping["criteria_coverage_summary"] if row["criterion"] != "CC9"
    ]


def _duplicate_metadata_control(mapping, metadata, registry):
    duplicate = deepcopy(_control(metadata, "1.1.1"))
    duplicate["automation_status"] = "blocked"
    metadata["controls"].insert(0, duplicate)


def _unhashable_evidence_selector(mapping, metadata, registry):
    _point(mapping, "CC7.1-P26")["evidence_selector"] = ["all", "of", "them"]


DRIFT_CASES = [
    (_unknown_control, crosswalk.CONTROL_NOT_IN_METADATA),
    (_duplicate_metadata_control, crosswalk.DUPLICATE_METADATA_CONTROL),
    (_unhashable_evidence_selector, crosswalk.UNKNOWN_EVIDENCE_SELECTOR),
    (_downgraded_automation_status, crosswalk.CONTROL_NOT_READY),
    (_policy_file_mismatch, crosswalk.POLICY_FILE_MISMATCH),
    (_policy_file_absent_on_disk, crosswalk.POLICY_FILE_MISSING),
    (_collector_id_mismatch, crosswalk.COLLECTOR_ID_MISMATCH),
    (_unregistered_collector, crosswalk.COLLECTOR_NOT_REGISTERED),
    (_benchmark_identity_mismatch, crosswalk.BENCHMARK_IDENTITY_MISMATCH),
    (_rating_outside_vocabulary, crosswalk.RATING_OUT_OF_VOCABULARY),
    (_no_rating_carrying_controls, crosswalk.RATING_NO_WITH_EVIDENCE),
    (_duplicate_point_id, crosswalk.DUPLICATE_POINT_ID),
    (_missing_resolution_row, crosswalk.RESOLUTION_ROW_MISSING),
    (_unreferenced_resolution_row, crosswalk.RESOLUTION_ROW_UNREFERENCED),
    (_duplicate_resolution_row, crosswalk.DUPLICATE_RESOLUTION_ROW),
    (_unknown_evidence_selector, crosswalk.UNKNOWN_EVIDENCE_SELECTOR),
    (_unsupported_schema_version, crosswalk.UNSUPPORTED_SCHEMA),
    (_unbacked_approval_claim, crosswalk.APPROVAL_INCONSISTENT),
    (_missing_criterion, crosswalk.CRITERIA_COVERAGE_INCOMPLETE),
]


@pytest.mark.parametrize(
    "mutate,code", DRIFT_CASES, ids=[code for _, code in DRIFT_CASES]
)
def test_each_drift_produces_exactly_its_own_finding_code(mutate, code):
    mapping = deepcopy(MAPPING)
    metadata = deepcopy(METADATA)
    registry = set(REGISTRY)
    mutate(mapping, metadata, registry)
    findings = crosswalk.validate_mapping(mapping, metadata, registry, POLICIES)
    assert {finding.code for finding in findings} == {code}
    assert all(finding.severity == crosswalk.SEVERITY_ERROR for finding in findings)


def test_a_resolution_row_nobody_references_is_still_proved():
    """Drift must be reported once for every id the mapping names, anywhere."""
    mapping = deepcopy(MAPPING)
    mapping["control_resolution"].append(
        {
            "control_id": "9.9.9",
            "policy_file": "9.9.9_absent.rego",
            "data_collector_id": "not.a.registered.collector",
        }
    )
    findings = crosswalk.validate_mapping(mapping, METADATA, REGISTRY, POLICIES)
    assert {finding.code for finding in findings} == {
        crosswalk.CONTROL_NOT_IN_METADATA,
        crosswalk.RESOLUTION_ROW_UNREFERENCED,
    }


def test_a_point_without_an_id_still_has_its_controls_proved():
    mapping = deepcopy(MAPPING)
    nameless = deepcopy(_point(mapping, "CC6.1-P02"))
    del nameless["point_id"]
    nameless["cis_control_ids"] = ["9.9.9"]
    mapping["points_of_focus"].append(nameless)
    findings = crosswalk.validate_mapping(mapping, METADATA, REGISTRY, POLICIES)
    assert {finding.code for finding in findings} == {
        crosswalk.MALFORMED_POINT,
        crosswalk.CONTROL_NOT_IN_METADATA,
        crosswalk.RESOLUTION_ROW_MISSING,
    }


@pytest.mark.parametrize(
    "mapping,metadata,registry,policies_root",
    [
        (None, "METADATA", "REGISTRY", "POLICIES"),
        ([], "METADATA", "REGISTRY", "POLICIES"),
        ("text", "METADATA", "REGISTRY", "POLICIES"),
        ("MAPPING", None, "REGISTRY", "POLICIES"),
        ("MAPPING", [], "REGISTRY", "POLICIES"),
        ("MAPPING", 0, "REGISTRY", "POLICIES"),
        ("MAPPING", "METADATA", None, "POLICIES"),
        ("MAPPING", "METADATA", 0, "POLICIES"),
        ("MAPPING", "METADATA", [None, 1, object()], "POLICIES"),
        ("MAPPING", "METADATA", "REGISTRY", []),
        ("MAPPING", "METADATA", "REGISTRY", 0),
    ],
    ids=[
        "mapping-none",
        "mapping-list",
        "mapping-str",
        "metadata-none",
        "metadata-list",
        "metadata-int",
        "registry-none",
        "registry-int",
        "registry-junk-items",
        "policies-root-list",
        "policies-root-int",
    ],
)
def test_hostile_input_produces_findings_rather_than_an_exception(
    mapping, metadata, registry, policies_root
):
    """Each argument is attacked on its own so no guard can mask another."""
    findings = crosswalk.validate_mapping(
        _real(mapping), _real(metadata), _real(registry), _real(policies_root)
    )
    assert findings
    assert all(isinstance(finding, crosswalk.Finding) for finding in findings)


def test_metadata_defects_cannot_quietly_shrink_the_selector_population():
    """A duplicated or nameless metadata row must fail, not just vanish."""
    duplicated = deepcopy(METADATA)
    # 1.2.2 reaches the gate only through the selector, never by name.
    assert "1.2.2" not in crosswalk.mapping_control_ids(MAPPING)
    shadow = deepcopy(_control(duplicated, "1.2.2"))
    shadow["automation_status"] = "blocked"
    duplicated["controls"].append(shadow)
    assert {
        finding.code
        for finding in crosswalk.validate_mapping(
            MAPPING, duplicated, REGISTRY, POLICIES
        )
    } == {crosswalk.DUPLICATE_METADATA_CONTROL}

    for blank in (None, "", "   ", "\t\n", 7, []):
        nameless = deepcopy(METADATA)
        _control(nameless, "1.2.2")["control_id"] = blank
        assert crosswalk.MALFORMED_METADATA_CONTROL in {
            finding.code
            for finding in crosswalk.validate_mapping(
                MAPPING, nameless, REGISTRY, POLICIES
            )
        }, blank


def test_an_unresolvable_policies_root_is_a_finding_not_an_exception(tmp_path):
    looping = tmp_path / "loop"
    looping.symlink_to(looping)
    findings = crosswalk.validate_mapping(MAPPING, METADATA, REGISTRY, looping)
    assert crosswalk.BENCHMARK_PATH_UNUSABLE in {finding.code for finding in findings}


def test_a_symlink_loop_is_a_finding_not_an_exception(artifact_copy):
    _, policies = artifact_copy
    directory = crosswalk.benchmark_dir(*BENCHMARK, root=policies)
    policy = directory / "1.1.1_admin_cloud_only.rego"
    policy.unlink()
    policy.symlink_to(policy)
    findings = crosswalk.validate_mapping(MAPPING, METADATA, REGISTRY, policies)
    assert [
        finding.subject for finding in findings if finding.code == "policy_file_missing"
    ] == ["1.1.1"]


def test_resolve_control_applies_the_same_containment(artifact_copy, tmp_path):
    _, policies = artifact_copy
    outside = tmp_path / "outside.rego"
    outside.write_text("package outside\n")
    directory = crosswalk.benchmark_dir(*BENCHMARK, root=policies)
    policy = directory / "1.1.1_admin_cloud_only.rego"
    policy.unlink()
    policy.symlink_to(outside)
    with pytest.raises(ValueError, match="escapes its root"):
        crosswalk.resolve_control("1.1.1", METADATA, policies)


def test_selector_expansion_validates_controls_the_mapping_never_names():
    """The 'every ready control' row must drag the whole ready set into the gate."""
    metadata = deepcopy(METADATA)
    _control(metadata, "1.2.2")["data_collector_id"] = "sharepoint.spo_tenant"
    assert "1.2.2" not in crosswalk.mapping_control_ids(MAPPING)

    findings = crosswalk.validate_mapping(MAPPING, metadata, REGISTRY, POLICIES)
    assert [
        finding.subject
        for finding in findings
        if finding.code == crosswalk.COLLECTOR_NOT_REGISTERED
    ] == ["1.2.2"]

    without_selector = deepcopy(MAPPING)
    _point(without_selector, "CC7.1-P26")["evidence_selector"] = None
    codes = {
        finding.code
        for finding in crosswalk.validate_mapping(
            without_selector, metadata, REGISTRY, POLICIES
        )
    }
    assert crosswalk.COLLECTOR_NOT_REGISTERED not in codes


def test_selector_that_matches_nothing_is_reported():
    metadata = deepcopy(METADATA)
    for control in metadata["controls"]:
        control["automation_status"] = "blocked"
    codes = {
        finding.code
        for finding in crosswalk.validate_mapping(MAPPING, metadata, REGISTRY, POLICIES)
    }
    assert crosswalk.SELECTOR_RESOLVES_TO_NOTHING in codes
    assert crosswalk.CONTROL_NOT_READY in codes


# ---------------------------------------------------------------------------
# resolve_control
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control_id", crosswalk.mapping_control_ids(MAPPING))
def test_resolve_control_returns_the_metadata_record_policy_and_collector(control_id):
    resolved = crosswalk.resolve_control(control_id, METADATA, POLICIES)
    record, policy_path, collector_id = resolved.as_tuple()
    row = _row(MAPPING, control_id)
    assert record["control_id"] == control_id
    assert record["automation_status"] == crosswalk.READY_STATUS
    assert policy_path.is_file()
    assert policy_path.name == row["policy_file"]
    assert collector_id == row["data_collector_id"]
    assert collector_id in DATA_COLLECTORS


def test_resolve_control_rejects_an_unknown_control():
    with pytest.raises(ValueError, match="Unknown control"):
        crosswalk.resolve_control("9.9.9", METADATA, POLICIES)
