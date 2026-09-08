"""The CC1-CC9 organizational register and the validator that guards it.

Two kinds of test, both taken from Phase 7's crosswalk precedent:

* a mutation table, proving the validator rejects each way the register could
  become dishonest;
* source-text assertions, proving the validator cannot write a file or assign a
  human-owned value. A process that could set an owner could manufacture
  accountability, which is the failure a SOC 2 register exists to prevent.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools" / "ci" / "check_organizational_register.py"
REGISTER = (
    ROOT
    / "engine"
    / "mappings"
    / "soc2"
    / "organizational"
    / "v1.0.0"
    / "register.json"
)
CROSSWALK = (
    ROOT
    / "engine"
    / "mappings"
    / "soc2"
    / "common-criteria"
    / "v1.0.0"
    / "mapping.json"
)

CRITERIA = tuple(f"CC{n}" for n in range(1, 10))


@pytest.fixture(scope="module")
def checker():
    spec = importlib.util.spec_from_file_location(
        "check_organizational_register", CHECKER
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def register():
    return json.loads(REGISTER.read_text())


# ---------------------------------------------------------------------------
# The register as shipped.
# ---------------------------------------------------------------------------


def test_the_register_validates(checker, register):
    assert checker.findings(register) == []


def test_every_criterion_is_present_exactly_once(register):
    seen = [row["criterion"] for row in register["criteria"]]
    assert seen == list(CRITERIA)


def test_no_criterion_has_an_owner_or_a_reviewer(register):
    """Three consecutive phases recorded 'no named owners' as an open gap.

    Engineering has no authority to appoint one, and a register populated with
    guessed owners would read as accountability that does not exist.
    """
    for row in register["criteria"]:
        assert row["owner"] is None, row["criterion"]
        assert row["owner_status"] == "unassigned", row["criterion"]
        assert row["reviewer"] is None, row["criterion"]
        assert row["reviewer_status"] == "unassigned", row["criterion"]


def test_nothing_claims_to_be_operating(register):
    """There is no production environment and no scheduler anywhere.

    No control in this program has ever executed on a cadence with a retained
    record, so nothing may say it has.
    """
    for row in register["criteria"]:
        assert row["operating_status"] != "operating", row["criterion"]


def test_the_register_is_excluded_from_automated_coverage(register):
    """Structural, not advisory: organizational assurance must never enter the
    compliance or coverage arithmetic Phase 3 defined over CIS controls."""
    assert register["counted_in_automated_coverage"] is False


def test_the_register_is_unapproved_with_null_reviewer_fields(register):
    approval = register["approval"]
    assert approval["approved"] is False
    for field in (
        "reviewer_name",
        "reviewer_role",
        "approved_at",
        "decision_reference",
    ):
        assert approval[field] is None, field
    # The reason must name the decision that blocks it, not merely say "pending".
    assert "D01-D10" in approval["note"] or "D06" in approval["note"]


def test_retention_is_bound_to_a_draft_policy_version(register):
    """The phase7-draft-1 / phase8-draft-1 precedent: a label, not a commitment."""
    assert register["retention"]["policy_version"] == "phase10-draft-1"
    assert "D04" in register["retention"]["note"]
    for row in register["criteria"]:
        assert row["retention_policy_version"] == "phase10-draft-1"


def test_every_named_supporting_artifact_exists(register):
    for row in register["criteria"]:
        for artifact in row["supporting_repository_artifacts"]:
            assert (ROOT / artifact).exists(), f"{row['criterion']}: {artifact}"


def test_classifications_match_the_reviewed_crosswalk(register):
    """These are GRC judgments transcribed from the plan's Appendix A.

    A second copy that can drift is how two documents come to disagree about
    what a criterion covers.
    """
    mapping = json.loads(CROSSWALK.read_text())
    authoritative = {
        row["criterion"]: row["configuration_coverage_classification"]
        for row in mapping["criteria_coverage_summary"]
    }
    for row in register["criteria"]:
        expected = authoritative[row["criterion"]]
        actual = row["configuration_coverage_classification"]
        assert actual in {
            expected,
            expected.replace("fully mapped above", "fully mapped in the crosswalk"),
        }, row["criterion"]


def test_the_register_is_a_separate_file_from_the_crosswalk():
    """mapping.json's SHA-256 is pinned into every scan at creation.

    Adding organizational fields to it would change the mapping digest of every
    future scan and desynchronise it from every historical scan's pinned
    snapshot.
    """
    assert REGISTER != CROSSWALK
    mapping = json.loads(CROSSWALK.read_text())
    assert "criteria" not in mapping, "the crosswalk must not grow register rows"
    for row in mapping["criteria_coverage_summary"]:
        assert set(row) == {"criterion", "configuration_coverage_classification"}, row


# ---------------------------------------------------------------------------
# The mutation table: each way the register could become dishonest.
# ---------------------------------------------------------------------------


def _mutate(register, mutation):
    copied = copy.deepcopy(register)
    mutation(copied)
    return copied


MUTATIONS = {
    "claims a control operates": lambda r: r["criteria"][0].__setitem__(
        "operating_status", "operating"
    ),
    "names an owner without changing owner_status": lambda r: r["criteria"][
        0
    ].__setitem__("owner", "A. Person"),
    "marks an owner assigned without naming one": lambda r: r["criteria"][
        0
    ].__setitem__("owner_status", "assigned"),
    "names a reviewer without changing reviewer_status": lambda r: r["criteria"][
        0
    ].__setitem__("reviewer", "A. Reviewer"),
    "declares itself approved": lambda r: r["approval"].__setitem__("approved", True),
    "fills a reviewer field while unapproved": lambda r: r["approval"].__setitem__(
        "reviewer_name", "A. Person"
    ),
    "enters automated coverage": lambda r: r.__setitem__(
        "counted_in_automated_coverage", True
    ),
    "drops a criterion": lambda r: r["criteria"].pop(),
    "duplicates a criterion": lambda r: r["criteria"].append(
        copy.deepcopy(r["criteria"][0])
    ),
    "adds an unknown criterion": lambda r: r["criteria"].append(
        {**copy.deepcopy(r["criteria"][0]), "criterion": "CC10"}
    ),
    "uses a cadence outside the vocabulary": lambda r: r["criteria"][0].__setitem__(
        "cadence", "fortnightly"
    ),
    "uses an operating status outside the vocabulary": lambda r: r["criteria"][
        0
    ].__setitem__("operating_status", "probably_fine"),
    "names a supporting artifact that does not exist": lambda r: r["criteria"][
        0
    ].__setitem__("supporting_repository_artifacts", ["tools/ops/imaginary.py"]),
    "disagrees with the crosswalk classification": lambda r: r["criteria"][
        0
    ].__setitem__("configuration_coverage_classification", "Fully automated"),
    "drops a required field": lambda r: r["criteria"][0].pop("cadence"),
    # The direction that flatters: claiming a control is designed while pointing
    # at nothing. Unfalsifiable, and worse than an honest not_designed.
    "claims designed with no supporting artifact": lambda r: (
        r["criteria"][0].__setitem__("operating_status", "designed_not_operating"),
        r["criteria"][0].__setitem__("supporting_repository_artifacts", []),
    ),
}


@pytest.mark.parametrize("description", sorted(MUTATIONS))
def test_the_validator_rejects(checker, register, description):
    mutated = _mutate(register, MUTATIONS[description])
    assert checker.findings(mutated), description


def test_the_validator_returns_findings_rather_than_raising(checker):
    """A validator that raises on the first problem hides the rest."""
    assert checker.findings(
        {}
    ), "an empty register must produce findings, not an exception"


# ---------------------------------------------------------------------------
# What the validator may not do.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forbidden",
    [
        "write_text(",
        "write_bytes(",
        "mkdir(",
        "unlink(",
        "os.remove",
        "shutil",
        "setattr(",
    ],
)
def test_the_validator_cannot_write(forbidden):
    """Phase 7's crosswalk test does exactly this, for exactly this reason."""
    assert forbidden not in CHECKER.read_text(), forbidden


@pytest.mark.parametrize("field", ["owner", "reviewer", "operating_status", "cadence"])
def test_the_validator_cannot_assign_a_human_owned_value(field):
    """A process that can set an owner can manufacture accountability.

    Matched as an assignment specifically: `== ` is a comparison and is exactly
    what a validator is supposed to do, so a bare substring check would forbid
    the reading it exists to perform.
    """
    import re

    source = CHECKER.read_text()
    patterns = [
        rf'\[["\']{field}["\']\]\s*=(?!=)',  # row["owner"] = ...
        rf"\.{field}\s*=(?!=)",  # row.owner = ...
        rf'setdefault\(\s*["\']{field}["\']',  # row.setdefault("owner", ...)
    ]
    for pattern in patterns:
        assert not re.search(pattern, source), (field, pattern)


def test_the_checker_exits_zero_on_the_shipped_register(checker):
    assert checker.main([]) == 0
