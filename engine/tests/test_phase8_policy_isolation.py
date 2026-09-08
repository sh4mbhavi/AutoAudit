"""Candidate-policy isolation is a property of the code, not a convention.

``engine/policies/candidate/`` is a sibling of the benchmark tree, so the
non-recursive ``*.rego`` globs in ``worker/crosswalk.py:311`` and
``test_wiring.py:124-132`` never see it. That is the discovery half of the
isolation and it is asserted here rather than assumed.

The loading half is ``worker.provenance.capture_policy``, which is the ONLY way a
policy file's text reaches OPA. Before Phase 8 it joined ``policy_file`` onto the
benchmark directory and accepted anything that stayed under the policies root and
ended in ``.rego`` -- so a metadata entry of
``"policy_file": "candidate/3.2.2_dlp_policies_teams.rego"`` would have resolved,
loaded and been evaluated, and candidate isolation would have been enforced only
by the tests that happen to look. It now rejects any nested path structurally.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from worker import crosswalk
from worker.provenance import canonical_digest, capture_policy

ENGINE_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = ENGINE_ROOT / "policies"
CANDIDATE_ROOT = POLICIES_DIR / "candidate"

FRAMEWORK = "cis"
BENCHMARK = "microsoft-365-foundations"
VERSION = "v6.0.0"
BENCHMARK_DIR = POLICIES_DIR / FRAMEWORK / BENCHMARK / VERSION

# D-P8-01 pins this number: the candidate tree adds no executable policy.
SHIPPED_REGO_FILES = 69

METADATA = json.loads((BENCHMARK_DIR / "metadata.json").read_text(encoding="utf-8"))
READY_CONTROLS = [
    control
    for control in METADATA["controls"]
    if control["automation_status"] == "ready"
]
CANDIDATE_FILENAMES = sorted(path.name for path in CANDIDATE_ROOT.rglob("*.rego"))


def _corpus(directory: Path) -> dict[str, str]:
    """Rebuild what ``crosswalk.policy_corpus_digest`` digests, without trusting it."""
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.glob("*.rego"))
    }


# ---------------------------------------------------------------------------
# capture_policy: the only loader
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_file",
    [
        "candidate/3.2.2_dlp_policies_teams.rego",
        "candidate\\3.2.2_dlp_policies_teams.rego",
        "../candidate/3.2.2_dlp_policies_teams.rego",
        "candidate/cis/microsoft-365-foundations/v6.0.0/3.2.1_dlp_policies_enabled.rego",
        "",
        ".",
        "..",
    ],
)
def test_capture_policy_rejects_path_separators(policy_file):
    with pytest.raises(ValueError, match="Invalid policy path"):
        capture_policy(FRAMEWORK, BENCHMARK, VERSION, policy_file)


def test_capture_policy_still_loads_a_flat_policy_file():
    """The rejection above is a no-op for every value metadata actually holds."""
    control = READY_CONTROLS[0]
    source = capture_policy(FRAMEWORK, BENCHMARK, VERSION, control["policy_file"])
    assert source.strip()
    assert "package " in source


def test_capture_policy_still_loads_every_shipped_policy():
    assert len(READY_CONTROLS) == SHIPPED_REGO_FILES
    for control in READY_CONTROLS:
        policy_file = control["policy_file"]
        assert "/" not in policy_file and "\\" not in policy_file, (
            f"{control['control_id']} declares a nested policy_file {policy_file!r}, "
            "which capture_policy now refuses to load"
        )
        source = capture_policy(FRAMEWORK, BENCHMARK, VERSION, policy_file)
        assert source.strip(), f"{control['control_id']} loaded an empty policy"


def test_capture_policy_rejects_a_non_string_policy_file():
    """A null policy_file is what every blocked control carries."""
    for policy_file in (None, 1, ["3.2.2_dlp_policies_teams.rego"]):
        with pytest.raises(ValueError, match="Invalid policy path"):
            capture_policy(FRAMEWORK, BENCHMARK, VERSION, policy_file)


def test_capture_policy_rejects_an_absolute_path(tmp_path):
    """An absolute policy_file never reaches the filesystem resolution either."""
    outside = tmp_path / "outside.rego"
    outside.write_text("package outside\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid policy path"):
        capture_policy(FRAMEWORK, BENCHMARK, VERSION, str(outside))
    # The refusal is structural, so the file is never read even though it exists
    # and ends in .rego.
    assert outside.read_text(encoding="utf-8") == "package outside\n"


# ---------------------------------------------------------------------------
# Discovery: the candidate tree contributes nothing
# ---------------------------------------------------------------------------


def test_no_candidate_file_is_in_the_policy_corpus_digest(tmp_path):
    assert CANDIDATE_FILENAMES, "no candidate policies found; this test is vacuous"

    corpus = _corpus(BENCHMARK_DIR)
    assert len(corpus) == SHIPPED_REGO_FILES
    assert set(corpus).isdisjoint(CANDIDATE_FILENAMES)

    live = crosswalk.policy_corpus_digest(
        FRAMEWORK, BENCHMARK, VERSION, root=POLICIES_DIR
    )
    assert live == canonical_digest(corpus)

    # The same digest computed from a policies root that has no candidate tree at
    # all. Equality proves the live digest is unaffected by the candidate tree's
    # presence, so promoting or editing a candidate cannot move the provenance
    # digest of the executable corpus.
    without_candidates = tmp_path / "policies"
    shutil.copytree(
        POLICIES_DIR,
        without_candidates,
        ignore=shutil.ignore_patterns("candidate", "__pycache__"),
    )
    assert not (without_candidates / "candidate").exists()
    assert live == crosswalk.policy_corpus_digest(
        FRAMEWORK, BENCHMARK, VERSION, root=without_candidates
    )


def test_candidate_tree_is_invisible_to_metadata_discovery():
    """Benchmarks are discovered with a RECURSIVE rglob('metadata.json').

    ``test_wiring.py:65-71`` and ``tools/docs/generate_control_status.py:443`` both
    walk down from every metadata.json they find. One in the candidate tree would
    pull every candidate .rego into the benchmark corpus beside it.
    """
    discovered = sorted(POLICIES_DIR.rglob("metadata.json"))
    assert discovered, "no benchmark metadata found; this test is vacuous"
    assert [path for path in discovered if CANDIDATE_ROOT in path.parents] == []


def test_no_candidate_filename_is_referenced_by_any_control():
    referenced = {
        control.get("policy_file")
        for control in METADATA["controls"]
        if control.get("policy_file")
    }
    assert referenced.isdisjoint(CANDIDATE_FILENAMES)
    for control_id in ("3.2.1", "3.2.2", "3.3.1"):
        control = next(
            item for item in METADATA["controls"] if item["control_id"] == control_id
        )
        assert control["policy_file"] is None
        assert control["automation_status"] == "blocked"
