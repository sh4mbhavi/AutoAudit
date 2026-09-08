"""Validate the CC1-CC9 organizational evidence register.

Phase 7 set the precedent for a GRC artifact in this repository: a versioned
JSON file, a validator that returns findings rather than raising, a test that
pins the human-owned values individually, and a ``--check`` gate in CI so drift
fails the build. A register without those is weaker than every artifact phases
7 to 9 shipped.

The validator's most important property is what it **refuses to do**. It never
writes a file, and it never assigns an owner, a reviewer or an operating status.
Those are human judgments; an engineering process that could set them could
manufacture accountability, which is precisely the failure a SOC 2 register
exists to prevent. ``tools/tests/test_phase10_register.py`` asserts that by
source inspection, the same way Phase 7's crosswalk test does.

Usage:
    python tools/ci/check_organizational_register.py            # gate
    python tools/ci/check_organizational_register.py --show     # print the register
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
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

REQUIRED_CRITERIA = tuple(f"CC{n}" for n in range(1, 10))

# Reused from backend-api/app/models/manual_evidence.py rather than invented in
# parallel: the product already has a cadence vocabulary and a second one would
# drift from it.
CADENCES = {"ad_hoc", "monthly", "quarterly", "semiannual", "annual"}

OPERATING_STATUSES = {"not_designed", "designed_not_operating", "operating"}

REQUIRED_FIELDS = (
    "criterion",
    "title",
    "configuration_coverage_classification",
    "required_organizational_evidence",
    "cadence",
    "owner",
    "owner_status",
    "reviewer",
    "reviewer_status",
    "operating_status",
    "retention_policy_version",
)


def load() -> dict:
    return json.loads(REGISTER.read_text())


def findings(register: dict) -> list[str]:
    """Every structural problem, as a list. Never raises on a bad register."""
    problems: list[str] = []

    if register.get("counted_in_automated_coverage") is not False:
        problems.append(
            "counted_in_automated_coverage must be false: organizational assurance "
            "may never enter the automated compliance or coverage arithmetic"
        )

    approval = register.get("approval") or {}
    if approval.get("approved") is not False:
        problems.append(
            "approval.approved must be false; no reviewer has been appointed"
        )
    for field in (
        "reviewer_name",
        "reviewer_role",
        "approved_at",
        "decision_reference",
    ):
        if approval.get(field) is not None:
            problems.append(f"approval.{field} must be null while approved is false")

    seen = []
    for index, row in enumerate(register.get("criteria") or []):
        label = row.get("criterion", f"row {index}")
        for field in REQUIRED_FIELDS:
            if field not in row:
                problems.append(f"{label}: missing field {field}")
        seen.append(row.get("criterion"))

        if row.get("cadence") not in CADENCES:
            problems.append(
                f"{label}: cadence {row.get('cadence')!r} is not in the vocabulary"
            )
        if row.get("operating_status") not in OPERATING_STATUSES:
            problems.append(
                f"{label}: operating_status {row.get('operating_status')!r} is not in the vocabulary"
            )
        # The central honesty check. Nothing in this repository can evidence that
        # an organizational control operated, so nothing may claim it.
        if row.get("operating_status") == "operating":
            problems.append(
                f"{label}: operating_status may not be 'operating'. No control in "
                "this program has an execution record, and an engineering change "
                "cannot create one."
            )
        # An owner is a human appointment. Either it is unassigned and null, or
        # it is assigned and named -- never one without the other.
        if (row.get("owner") is None) != (row.get("owner_status") == "unassigned"):
            problems.append(f"{label}: owner and owner_status disagree")
        if (row.get("reviewer") is None) != (
            row.get("reviewer_status") == "unassigned"
        ):
            problems.append(f"{label}: reviewer and reviewer_status disagree")

        artifacts = row.get("supporting_repository_artifacts") or []
        for artifact in artifacts:
            if not (ROOT / artifact).exists():
                problems.append(
                    f"{label}: supporting artifact {artifact} does not exist"
                )
        if artifacts and row.get("operating_status") == "not_designed":
            problems.append(
                f"{label}: names supporting artifacts but claims not_designed"
            )
        # The inverse, which is the direction that flatters and so the one that
        # matters. A criterion cannot be "designed" on the strength of nothing:
        # `designed_not_operating` means an artifact exists in this repository
        # that would evidence the control if it were run and reviewed. Without
        # the pointer the claim is unfalsifiable, and an unfalsifiable claim in
        # a SOC 2 register is worse than an honest `not_designed`. Found by the
        # review pass, which constructed exactly this register and watched it
        # pass.
        if not artifacts and row.get("operating_status") == "designed_not_operating":
            problems.append(
                f"{label}: claims designed_not_operating but names no supporting "
                "artifact; a design claim must point at something"
            )

    missing = [c for c in REQUIRED_CRITERIA if c not in seen]
    if missing:
        problems.append(f"missing criteria: {', '.join(missing)}")
    unexpected = [c for c in seen if c not in REQUIRED_CRITERIA]
    if unexpected:
        problems.append(f"unexpected criteria: {', '.join(str(c) for c in unexpected)}")
    duplicates = {c for c in seen if seen.count(c) > 1}
    if duplicates:
        problems.append(
            f"duplicate criteria: {', '.join(sorted(str(d) for d in duplicates))}"
        )

    problems.extend(_crosswalk_agreement(register))
    return problems


def _crosswalk_agreement(register: dict) -> list[str]:
    """The classification must match the reviewed crosswalk, verbatim.

    The classifications are GRC judgments transcribed from the plan's Appendix A.
    Restating them here creates a second copy, and a second copy that can drift
    is how two documents come to disagree about what a criterion covers.
    """
    if not CROSSWALK.exists():
        return ["the SOC 2 crosswalk is missing; classifications cannot be checked"]
    mapping = json.loads(CROSSWALK.read_text())
    authoritative = {
        row["criterion"]: row["configuration_coverage_classification"]
        for row in mapping.get("criteria_coverage_summary") or []
    }
    problems = []
    for row in register.get("criteria") or []:
        criterion = row.get("criterion")
        expected = authoritative.get(criterion)
        actual = row.get("configuration_coverage_classification")
        if expected is None:
            problems.append(f"{criterion}: not present in the crosswalk summary")
        elif not _equivalent(expected, actual):
            problems.append(
                f"{criterion}: classification disagrees with the crosswalk "
                f"({actual!r} vs {expected!r})"
            )
    return problems


def _equivalent(expected: str, actual: str | None) -> bool:
    """The crosswalk says 'fully mapped above'; here there is no 'above'.

    That is the only permitted divergence, and it is a wording fix rather than a
    change of meaning, so it is enumerated rather than pattern-matched.
    """
    if actual == expected:
        return True
    return actual == expected.replace(
        "fully mapped above", "fully mapped in the crosswalk"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args(argv)

    register = load()
    if args.show:
        print(json.dumps(register, indent=2, sort_keys=True))

    problems = findings(register)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        return 1

    rows = register["criteria"]
    designed = sum(1 for r in rows if r["operating_status"] == "designed_not_operating")
    print(
        f"{len(rows)} organizational criteria validated; {designed} partly designed, "
        f"0 operating, {sum(1 for r in rows if r['owner'] is None)} without an owner."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
