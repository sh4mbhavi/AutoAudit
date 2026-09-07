"""The candidate policy tree is reviewable, declared, and structurally unreachable.

``engine/policies/candidate/`` holds Rego that has been written and tested but is
not wired to any scan. These tests pin the three properties that make that safe:

  1. It stays invisible to every benchmark mechanism. Policy discovery walks down
     from a ``metadata.json`` with a NON-recursive ``*.rego`` glob
     (``test_wiring.py:124-132``, ``worker/crosswalk.py:311``), while the parents
     themselves are found with a RECURSIVE ``rglob("metadata.json")``
     (``test_wiring.py:65-71``, ``tools/docs/generate_control_status.py:443``).
     A ``metadata.json`` in this tree would therefore pull every candidate file
     into the benchmark corpus, so its absence is asserted, not assumed.
  2. Everything it promises on promotion is declared in ``candidates.json`` and
     matches the live metadata, the live collector registry and the file on disk,
     so promotion is a byte-identical ``git mv`` with no edit to the Rego.
  3. Promotion is blocked today by named, unresolved gates from a closed
     vocabulary, and the recorded promotion delta is recomputed from the live
     artifacts so it cannot go stale while promotion has not happened.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from collectors.registry import DATA_COLLECTORS
from worker import crosswalk
from worker.provenance import canonical_digest

ENGINE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ENGINE_ROOT.parent
POLICIES_DIR = ENGINE_ROOT / "policies"

# Renaming the manifest (see the CONTINGENCY note in engine/policies/candidate/README.md)
# means changing this constant and promote_candidate.py's MANIFEST_PATH, nothing else.
MANIFEST_NAME = "candidates.json"
CANDIDATE_ROOT = POLICIES_DIR / "candidate"
MANIFEST_PATH = CANDIDATE_ROOT / MANIFEST_NAME

MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
CANDIDATES = MANIFEST["candidates"]
CANDIDATE_IDS = [candidate["control_id"] for candidate in CANDIDATES]
CANDIDATE_DIR = REPO_ROOT / MANIFEST["candidate_dir"]
TARGET_DIR = REPO_ROOT / MANIFEST["target_dir"]

METADATA = json.loads((TARGET_DIR / "metadata.json").read_text(encoding="utf-8"))
CONTROLS_BY_ID = {control["control_id"]: control for control in METADATA["controls"]}

_PACKAGE_RE = re.compile(r"^package\s+(\S+)", re.MULTILINE)
_COMPLIANT_VALUE_RE = re.compile(r'"compliant":\s*(\S+?)[,\s}]')


def _expected_package(framework: str, slug: str, version: str, control_id: str) -> str:
    """Replicate the package-path logic from worker/tasks.py:419-427."""
    framework_normalized = framework.replace("-", "_")
    benchmark_normalized = slug.replace("-", "_")
    version_normalized = version.replace(".", "_")
    control_suffix = control_id.replace(".", "_").replace("-", "_").lower()
    return f"{framework_normalized}.{benchmark_normalized}.{version_normalized}.control_{control_suffix}"


def _candidate_text(candidate: dict) -> str:
    return (CANDIDATE_DIR / candidate["candidate_file"]).read_text(encoding="utf-8")


def _annotated_permissions(text: str, label: str) -> set[str]:
    """Parse the permission annotation with test_policy_permissions.py:24-33 verbatim."""
    custom = re.search(r"^# custom:\n((?:#(?:  .*|)\n)+)", text, re.MULTILINE)
    assert custom, f"{label}: missing custom metadata"
    permission_block = re.search(
        r"^#   requires_permissions:\n((?:#   (?:  )?- [A-Za-z0-9.-]+\n)+)",
        custom[1],
        re.MULTILINE,
    )
    assert permission_block, f"{label}: missing permission block"
    permissions = re.findall(r"- ([A-Za-z0-9.-]+)", permission_block[1])
    assert len(permissions) == len(
        set(permissions)
    ), f"{label}: duplicate permission annotations"
    return set(permissions)


def test_manifest_identifies_the_benchmark_it_targets():
    assert MANIFEST["schema_version"] == 1
    assert MANIFEST["framework"] == METADATA["framework"]
    assert MANIFEST["benchmark"] == METADATA["slug"]
    assert MANIFEST["version"] == METADATA["version"]
    assert CANDIDATE_DIR.is_dir()
    assert TARGET_DIR.is_dir()
    assert CANDIDATE_IDS == sorted(set(CANDIDATE_IDS))


def test_no_metadata_json_in_candidate_tree():
    # A metadata.json here would make this a benchmark version directory: the
    # recursive rglob at test_wiring.py:65-71 would find it and the non-recursive
    # glob at test_wiring.py:130 would then pull every candidate .rego into
    # test_no_orphaned_rego_files, and the docs gate would generate a phantom
    # controls document for it.
    strays = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in CANDIDATE_ROOT.rglob("metadata.json")
    )
    assert strays == [], (
        "engine/policies/candidate must never contain a metadata.json; "
        f"found {strays}. The manifest is {MANIFEST_NAME} for this reason."
    )


def test_every_candidate_rego_is_listed_and_every_listed_file_exists():
    listed = {candidate["candidate_file"] for candidate in CANDIDATES}
    assert listed == {path.name for path in CANDIDATE_DIR.glob("*.rego")}

    # No candidate Rego may hide in another subdirectory of the tree either.
    assert {path.parent for path in CANDIDATE_ROOT.rglob("*.rego")} == {CANDIDATE_DIR}

    for candidate in CANDIDATES:
        path = CANDIDATE_DIR / candidate["candidate_file"]
        assert path.is_file(), f"{candidate['control_id']}: {path} does not exist"
        # Promotion is a git mv, so the promoted name is the candidate name.
        assert candidate["target_policy_file"] == candidate["candidate_file"]
        assert not (
            TARGET_DIR / candidate["target_policy_file"]
        ).exists(), (
            f"{candidate['control_id']}: already present in the benchmark directory"
        )


@pytest.mark.parametrize("candidate", CANDIDATES, ids=CANDIDATE_IDS)
def test_packages_match_promoted_names(candidate):
    # The package is the one the worker will build after promotion, so the file
    # moves without a single edit to the Rego.
    expected = _expected_package(
        MANIFEST["framework"],
        MANIFEST["benchmark"],
        MANIFEST["version"],
        candidate["control_id"],
    )
    match = _PACKAGE_RE.search(_candidate_text(candidate))
    assert match, f"{candidate['control_id']}: no package declaration"
    assert match.group(1) == expected


@pytest.mark.parametrize("candidate", CANDIDATES, ids=CANDIDATE_IDS)
def test_can_return_true_matches_the_policy_text(candidate):
    # Two of the three controls decide only the objective half of an audit the
    # source says a human decides, so they can never emit a pass. That claim is
    # recorded in the manifest and checked here against the Rego, and the
    # never-pass property tests
    # (engine/tests/test_phase8_candidate_never_pass.rego) sweep it over a matrix
    # of missing, malformed and out-of-range evidence.
    emitted = set(_COMPLIANT_VALUE_RE.findall(_candidate_text(candidate)))
    assert emitted <= {"null", "false", "true"}, (
        f"{candidate['control_id']}: 'compliant' must be a literal in a candidate "
        f"policy so this claim stays checkable; found {sorted(emitted)}"
    )
    assert ("true" in emitted) is candidate["can_return_true"]


@pytest.mark.parametrize("candidate", CANDIDATES, ids=CANDIDATE_IDS)
def test_permission_annotation_matches_manifest_and_metadata(candidate):
    control_id = candidate["control_id"]
    annotated = _annotated_permissions(_candidate_text(candidate), control_id)
    assert annotated == set(candidate["requires_permissions"])

    control = CONTROLS_BY_ID[control_id]
    assert (
        control["requires_permissions"] is not None
    ), f"{control_id}: metadata.json declares no requires_permissions"
    assert annotated == set(control["requires_permissions"])


@pytest.mark.parametrize("candidate", CANDIDATES, ids=CANDIDATE_IDS)
def test_collectors_are_registered(candidate):
    control_id = candidate["control_id"]
    collector_id = candidate["data_collector_id"]
    assert (
        collector_id in DATA_COLLECTORS
    ), f"{control_id}: collector '{collector_id}' is not registered"
    assert CONTROLS_BY_ID[control_id]["data_collector_id"] == collector_id


@pytest.mark.parametrize("candidate", CANDIDATES, ids=CANDIDATE_IDS)
def test_every_candidate_has_unresolved_gates_from_the_closed_vocabulary(candidate):
    vocabulary = set(MANIFEST["gate_vocabulary"])
    gates = candidate["blocking_gates"]
    assert gates, f"{candidate['control_id']}: no blocking gates recorded"
    names = [gate["gate"] for gate in gates]
    assert len(names) == len(set(names))
    assert set(names) <= vocabulary, f"unknown gate names: {set(names) - vocabulary}"
    for gate in gates:
        assert gate["resolved"] is False, (
            f"{candidate['control_id']}: gate '{gate['gate']}' is recorded as resolved; "
            "promotion is a tools/policies/promote_candidate.py decision, not a manifest edit"
        )
        assert isinstance(gate["note"], str) and gate["note"].strip()


@pytest.mark.parametrize("candidate", CANDIDATES, ids=CANDIDATE_IDS)
def test_procedure_source_records_the_d07_caveat(candidate):
    source = candidate["procedure_source"]
    assert source["path"] == "docs/engine/Framework/CIS_M365_Benchmarks.json"
    assert (REPO_ROOT / source["path"]).is_file()
    assert source["number"] == candidate["control_id"]
    # Read the edition from the extract rather than pinning a literal: this field
    # exists to record what the source document declares about itself, so a
    # transcription that merely looks right is not good enough. The source string
    # contains an en dash, which an ASCII transcription silently loses.
    declared = json.loads((REPO_ROOT / source["path"]).read_text(encoding="utf-8"))[
        "document_version"
    ]
    assert source["edition_declared"] == declared
    # D07: the extract declares v6.0.1 while the runtime and this mapping are
    # v6.0.0, so it cannot establish the licensed v6.0.0 procedure.
    assert not declared.startswith("v6.0.0")
    assert source["licensed_v6_0_0_confirmed"] is False


def test_promotion_delta_matches_live_metadata():
    # Recomputed from the live artifacts so the recorded delta cannot go stale
    # while promotion has not happened.
    statuses = Counter(control["automation_status"] for control in METADATA["controls"])
    delta = MANIFEST["promotion_delta"]
    promoted = len(CANDIDATES)

    ready = delta["automation_status"]["ready"]
    blocked = delta["automation_status"]["blocked"]
    assert ready["before"] == statuses["ready"]
    assert ready["after"] == statuses["ready"] + promoted
    assert blocked["before"] == statuses["blocked"]
    assert blocked["after"] == statuses["blocked"] - promoted

    rego_files = delta["target_dir_rego_files"]
    assert rego_files["before"] == len(list(TARGET_DIR.glob("*.rego")))
    assert rego_files["after"] == rego_files["before"] + promoted

    for candidate in CANDIDATES:
        # Every candidate is blocked today and ready afterwards, which is what
        # makes the delta above the whole delta.
        assert CONTROLS_BY_ID[candidate["control_id"]]["automation_status"] == "blocked"
        assert candidate["target_automation_status"] == "ready"


def test_candidate_files_are_absent_from_the_policy_corpus_digest():
    # crosswalk.policy_corpus_digest globs *.rego non-recursively in the benchmark
    # directory (crosswalk.py:311), so the candidate tree must contribute nothing
    # to the provenance digest of the executable corpus.
    directory = crosswalk.benchmark_dir(
        MANIFEST["framework"],
        MANIFEST["benchmark"],
        MANIFEST["version"],
        root=POLICIES_DIR,
    )
    corpus = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.glob("*.rego"))
    }
    assert set(corpus).isdisjoint(
        {candidate["candidate_file"] for candidate in CANDIDATES}
    )
    # The digest is the digest of exactly that corpus and of nothing in the
    # candidate tree, recomputed here rather than trusted.
    assert crosswalk.policy_corpus_digest(
        MANIFEST["framework"],
        MANIFEST["benchmark"],
        MANIFEST["version"],
        root=POLICIES_DIR,
    ) == canonical_digest(corpus)
