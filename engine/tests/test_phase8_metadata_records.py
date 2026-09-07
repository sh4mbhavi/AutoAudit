"""The three Compliance control records say exactly what is true, and no more.

Phase 8 gives CIS 3.2.1 / 3.2.2 / 3.3.1 a registered collector and a candidate
Rego policy, but does NOT make them runnable: certificate-based
``Connect-IPPSSession`` has not been validated against a licensed tenant, and two
of the three benchmark procedures put the pass decision in a human's hands.

The records therefore keep ``automation_status: "blocked"`` and
``policy_file: null``. That combination is what stops the engine dispatching them
(``worker/tasks.py`` dispatches ``ready`` only) and what keeps the candidate tree
unreachable. These tests pin it, so the next edit to this metadata cannot make
the three controls live by accident, and pin the coverage distribution that
every Phase 8 document quotes.

``test_wiring.py`` already enforces the general rules (a non-ready control's
collector must be registered; a registered collector must be referenced by some
control). What is asserted here is specific to these three records: the exact
collector ids, the exact permission, notes that survive markdown-table
rendering, and the fact that no SOC 2 rating moved.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from collectors.registry import DATA_COLLECTORS

ENGINE_ROOT = Path(__file__).resolve().parents[1]

METADATA_PATH = (
    ENGINE_ROOT
    / "policies"
    / "cis"
    / "microsoft-365-foundations"
    / "v6.0.0"
    / "metadata.json"
)
SOC2_MAPPING_PATH = (
    ENGINE_ROOT / "mappings" / "soc2" / "common-criteria" / "v1.0.0" / "mapping.json"
)

METADATA = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
CONTROLS_BY_ID = {control["control_id"]: control for control in METADATA["controls"]}

# The three records this work item owns, and the collector each one declares.
EXPECTED_COLLECTORS = {
    "3.2.1": "compliance.dlp_compliance_policy",
    "3.2.2": "compliance.dlp_compliance_policy",
    "3.3.1": "compliance.label_policy",
}
CONTROL_IDS = sorted(EXPECTED_COLLECTORS)

# The candidate Rego each note must name, so a rename of the candidate file
# cannot leave the published note pointing at a path that does not exist.
CANDIDATE_FILENAMES = {
    "3.2.1": "3.2.1_dlp_policies_enabled.rego",
    "3.2.2": "3.2.2_dlp_policies_teams.rego",
    "3.3.1": "3.3.1_sensitivity_label_policies_published.rego",
}
CANDIDATE_DIR = "engine/policies/candidate/cis/microsoft-365-foundations/v6.0.0"

# M2: Exchange.ManageAsApp is the documented app role for Connect-IPPSSession.
# Exchange.Manage (used by 3.1.1) is a different role and must not be reused here
# by analogy.
EXPECTED_PERMISSIONS = ["Exchange.ManageAsApp"]

# Pinned by D-P8-01: adding a collector id to a blocked control changes no count.
EXPECTED_STATUS_DISTRIBUTION = {
    "ready": 69,
    "blocked": 31,
    "not_started": 17,
    "deferred": 12,
    "manual": 11,
}


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_three_controls_stay_blocked_with_no_policy_file(control_id: str) -> None:
    """Neither control may become runnable while the auth blocker stands.

    ``automation_status`` is the dispatch gate and ``policy_file`` is the
    evaluation gate. Both have to stay shut: a ``ready`` status would dispatch a
    collector that cannot authenticate, and a ``policy_file`` would pull a
    candidate policy into the benchmark corpus.
    """
    control = CONTROLS_BY_ID[control_id]
    assert control["automation_status"] == "blocked", (
        f"{control_id} must stay blocked until certificate-based "
        "Connect-IPPSSession is validated; promotion runs only through "
        "tools/policies/promote_candidate.py"
    )
    assert control["policy_file"] is None, (
        f"{control_id} must keep policy_file null; its Rego lives in the "
        "unreachable candidate tree"
    )


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_three_controls_declare_registered_collectors(control_id: str) -> None:
    """The declared collector id is the expected one and actually exists."""
    control = CONTROLS_BY_ID[control_id]
    expected = EXPECTED_COLLECTORS[control_id]
    assert control["data_collector_id"] == expected
    assert expected in DATA_COLLECTORS, (
        f"{expected} is declared by {control_id} but is not a key of "
        "collectors.registry.DATA_COLLECTORS"
    )


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_three_controls_require_only_exchange_manage_as_app(control_id: str) -> None:
    """Exactly the one role Connect-IPPSSession documents, and nothing else.

    Over-declaring a permission would make scan readiness demand consent the
    control does not need; under-declaring would let a scan look ready when the
    collector cannot authenticate.
    """
    control = CONTROLS_BY_ID[control_id]
    assert control["requires_permissions"] == EXPECTED_PERMISSIONS


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_notes_are_table_safe(control_id: str) -> None:
    """The note renders into one markdown table cell and names its own escapes.

    ``tools/docs/generate_control_status.py`` puts each note in a single cell of
    the implementation-notes table. A newline would break the table outright, and
    while the generator escapes a pipe, a note that needs escaping is a note that
    reads badly in the published document, so pipes are banned at the source.
    The note must also name the candidate path and the promotion tool, because
    those are the only two facts that tell a reader where the work went and how
    it is allowed to land.
    """
    note = CONTROLS_BY_ID[control_id]["notes"]
    assert isinstance(note, str) and note.strip(), f"{control_id} has no note"
    assert "|" not in note, f"{control_id} note contains a table-breaking pipe"
    assert (
        "\n" not in note and "\r" not in note
    ), f"{control_id} note contains a newline"
    expected_path = f"{CANDIDATE_DIR}/{CANDIDATE_FILENAMES[control_id]}"
    assert (
        expected_path in note
    ), f"{control_id} note must name its candidate policy at {expected_path}"
    assert (
        "tools/policies/promote_candidate.py" in note
    ), f"{control_id} note must name the promotion tool"


def test_status_distribution_is_unchanged() -> None:
    """Phase 8 adds coverage work without moving a single coverage number.

    Every Phase 8 document quotes this distribution. Giving a blocked control a
    collector id must not change it; if this fails, something promoted a control
    that the licensed source or the auth blocker says is not promotable.
    """
    counts = Counter(control["automation_status"] for control in METADATA["controls"])
    assert len(METADATA["controls"]) == 140
    assert dict(counts) == EXPECTED_STATUS_DISTRIBUTION


def test_no_soc2_mapping_change() -> None:
    """No rating moved, and the three controls entered no crosswalk row.

    ``worker/crosswalk.py`` hard-errors CONTROL_NOT_READY for a mapping row that
    names a non-ready control, so mapping these three would break the crosswalk;
    more importantly, a Phase 8 code path that added them would be inferring a
    SOC 2 rating, which no engineering process may do.
    """
    mapping = json.loads(SOC2_MAPPING_PATH.read_text(encoding="utf-8"))
    assert mapping["approval"]["approved"] is False

    mapped: set[str] = set()
    for point in mapping["points_of_focus"]:
        mapped.update(point["cis_control_ids"])
    leaked = sorted(mapped & set(CONTROL_IDS))
    assert not leaked, (
        f"{leaked} are blocked controls and must not appear in any "
        "cis_control_ids list"
    )
