"""Promotion of a candidate policy is refused until it is earned.

``tools/policies/promote_candidate.py`` is the mechanism behind plan section
16.6's "do not promote _pending collectors without live-tenant validation". These
tests pin both halves:

  * ``--check`` verifies that ``candidates.json`` still describes the tree it
    claims to describe -- including a promotion delta RECOMPUTED from live
    metadata, so the recorded instructions cannot go stale while promotion has
    not happened.
  * ``--apply`` refuses on every unmet gate, and only succeeds here inside a
    throwaway copy of the tree with every gate flipped resolved. The repository
    itself is never mutated by any test in this file, which an autouse fixture
    verifies by digesting the tree before and after each test.
"""

from __future__ import annotations

import hashlib
import importlib.util
import difflib
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "policies" / "promote_candidate.py"

POLICIES = "engine/policies"
GENERATOR = "tools/docs/generate_control_status.py"
MANIFEST = "engine/policies/candidate/candidates.json"
V6_METADATA = "engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json"
V6_DIR = "engine/policies/cis/microsoft-365-foundations/v6.0.0"
CANDIDATE_DIR = "engine/policies/candidate/cis/microsoft-365-foundations/v6.0.0"

CANDIDATE_CONTROL = "3.2.2"
CANDIDATE_FILE = "3.2.2_dlp_policies_teams.rego"

# D-P8-01: 69 ready today, so promoting exactly one candidate makes 70.
READY_BEFORE = 69
READY_AFTER_ONE_PROMOTION = 70

EXPECTED_GATES = [
    "live_tenant_validation",
    "licensed_v6_procedure",
    "grc_rationale_review",
    "worker_client_wiring",
    "readiness_call_site_wiring",
    "policy_review_reason_code",
]


def _load_tool():
    spec = importlib.util.spec_from_file_location("promote_candidate", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


promoter = _load_tool()


def _tree_digest(*relatives: str) -> str:
    """Content digest of the real repository paths these tests read."""
    digest = hashlib.sha256()
    for relative in relatives:
        base = ROOT / relative
        paths = sorted(base.rglob("*")) if base.is_dir() else [base]
        for path in paths:
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


@pytest.fixture(autouse=True)
def repository_is_never_mutated():
    """No test here may write into the worktree, not even the ones that pass."""
    before = _tree_digest(POLICIES, "docs/engine/policies")
    yield
    assert (
        _tree_digest(POLICIES, "docs/engine/policies") == before
    ), "a promotion test mutated the repository tree"


@pytest.fixture
def temp_repo(tmp_path, monkeypatch):
    """A throwaway copy of everything the tool reads and writes.

    ``ROOT``/``MANIFEST_PATH``/``GENERATOR`` are module globals read at call time,
    so redirecting the three of them moves the whole tool into ``tmp_path``. The
    generator is copied too, because it derives its own root from ``__file__``.
    """
    shutil.copytree(
        ROOT / POLICIES,
        tmp_path / POLICIES,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    (tmp_path / "tools" / "docs").mkdir(parents=True)
    shutil.copy2(ROOT / GENERATOR, tmp_path / GENERATOR)

    # The committed metadata.json keeps short arrays on one line, which is not
    # json.dumps output, so the tool's canonical-form guard refuses to rewrite it
    # (see the report note). Normalising the COPY is what lets the success path be
    # exercised at all; it is a property of this fixture, not of the repository.
    metadata_path = tmp_path / V6_METADATA
    metadata_path.write_text(
        json.dumps(
            json.loads(metadata_path.read_text(encoding="utf-8")),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(promoter, "ROOT", tmp_path)
    monkeypatch.setattr(promoter, "MANIFEST_PATH", tmp_path / MANIFEST)
    monkeypatch.setattr(promoter, "GENERATOR", tmp_path / GENERATOR)
    return tmp_path


def _manifest(root: Path) -> dict:
    return json.loads((root / MANIFEST).read_text(encoding="utf-8"))


def _write_manifest(root: Path, manifest: dict) -> None:
    (root / MANIFEST).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _metadata(root: Path) -> dict:
    return json.loads((root / V6_METADATA).read_text(encoding="utf-8"))


def _control(root: Path, control_id: str) -> dict:
    return next(
        control
        for control in _metadata(root)["controls"]
        if control["control_id"] == control_id
    )


def _resolve_every_gate(root: Path) -> None:
    manifest = _manifest(root)
    for candidate in manifest["candidates"]:
        for gate in candidate["blocking_gates"]:
            gate["resolved"] = True
    _write_manifest(root, manifest)


def _evidence(tmp_path: Path) -> Path:
    path = tmp_path / "live-validation-evidence.md"
    path.write_text(
        "Connect-IPPSSession executed against a licensed non-production tenant.\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# --check against the real tree
# ---------------------------------------------------------------------------


def test_check_passes_on_the_shipped_tree(capsys):
    assert promoter.main(["--check"]) == 0
    assert "verified and unreachable by any scan" in capsys.readouterr().out


def test_usage_errors_exit_two():
    for argv in ([], ["--apply"], ["--check", "--apply", CANDIDATE_CONTROL]):
        with pytest.raises(SystemExit) as exit_info:
            promoter.main(argv)
        assert exit_info.value.code == 2, argv


# ---------------------------------------------------------------------------
# --apply refusals
# ---------------------------------------------------------------------------


def test_apply_refuses_without_evidence_flag():
    with pytest.raises(SystemExit) as exit_info:
        promoter.main(["--apply", CANDIDATE_CONTROL])
    assert exit_info.value.code == 2


def test_apply_refuses_when_evidence_file_missing(tmp_path, capsys):
    missing = tmp_path / "never-written.md"
    code = promoter.main(
        ["--apply", CANDIDATE_CONTROL, "--live-validation-evidence", str(missing)]
    )
    assert code == 1
    output = capsys.readouterr().out
    assert "live validation evidence file not found" in output
    assert str(missing) in output


def test_apply_refuses_with_an_empty_evidence_path(capsys):
    code = promoter.main(
        ["--apply", CANDIDATE_CONTROL, "--live-validation-evidence", ""]
    )
    assert code == 1
    assert (
        "REFUSED: --apply requires --live-validation-evidence <path>."
        in capsys.readouterr().out
    )


def test_apply_refuses_while_gates_unresolved(tmp_path, capsys):
    code = promoter.main(
        [
            "--apply",
            CANDIDATE_CONTROL,
            "--live-validation-evidence",
            str(_evidence(tmp_path)),
        ]
    )
    assert code == 1
    output = capsys.readouterr().out
    assert f"control {CANDIDATE_CONTROL} has unresolved blocking gates" in output
    for gate in EXPECTED_GATES:
        assert gate in output, f"{gate} was not named in the refusal"


def test_apply_refuses_unknown_control(tmp_path, capsys):
    code = promoter.main(
        [
            "--apply",
            "9.9.9",
            "--live-validation-evidence",
            str(_evidence(tmp_path)),
        ]
    )
    assert code == 1
    assert "REFUSED: control 9.9.9 is not listed in candidates.json" in (
        capsys.readouterr().out
    )


# ---------------------------------------------------------------------------
# --apply success, in a copy only
# ---------------------------------------------------------------------------


def test_apply_succeeds_only_in_a_temp_copy_with_all_gates_resolved(
    temp_repo, tmp_path, capsys
):
    _resolve_every_gate(temp_repo)
    evidence = _evidence(tmp_path)

    assert promoter.check() == []
    code = promoter.apply(CANDIDATE_CONTROL, str(evidence))
    output = capsys.readouterr().out
    assert code == 0, output

    moved = temp_repo / V6_DIR / CANDIDATE_FILE
    assert moved.is_file()
    assert not (temp_repo / CANDIDATE_DIR / CANDIDATE_FILE).exists()
    # The move is byte-identical: promotion never edits the Rego.
    assert moved.read_bytes() == (ROOT / CANDIDATE_DIR / CANDIDATE_FILE).read_bytes()

    control = _control(temp_repo, CANDIDATE_CONTROL)
    assert control["automation_status"] == "ready"
    assert control["policy_file"] == CANDIDATE_FILE

    statuses = [c["automation_status"] for c in _metadata(temp_repo)["controls"]]
    assert statuses.count("ready") == READY_AFTER_ONE_PROMOTION
    assert len(list((temp_repo / V6_DIR).glob("*.rego"))) == READY_BEFORE + 1

    # The generator ran, so the published document is regenerated, never typed.
    document = (
        temp_repo
        / "docs/engine/policies/cis/microsoft-365-foundations/v6.0.0/controls.md"
    )
    assert document.is_file()
    assert f"ready: {READY_AFTER_ONE_PROMOTION}" in output

    # The other two candidates are untouched by a single-control promotion.
    for other in ("3.2.1", "3.3.1"):
        assert _control(temp_repo, other)["automation_status"] == "blocked"
        assert _control(temp_repo, other)["policy_file"] is None


def test_apply_preserves_metadata_formatting_whatever_it_is(
    temp_repo, tmp_path, capsys
):
    """Promotion is surgical: two fields change and every other byte survives.

    Replaces an earlier test that required metadata.json to be in the tool's own
    canonical json.dumps form. The shipped file is not in that form -- it keeps
    short arrays such as "requires_permissions" on one line -- so that
    requirement refused every promotion forever. Preserving the file's existing
    formatting is both the usable behaviour and the safer one: promotion must not
    reformat the whole file as a side effect.
    """
    _resolve_every_gate(temp_repo)
    metadata_path = temp_repo / V6_METADATA
    # Deliberately NOT the tool's canonical form.
    metadata_path.write_text(
        json.dumps(json.loads(metadata_path.read_text(encoding="utf-8")), indent=4)
        + "\n",
        encoding="utf-8",
    )
    before = metadata_path.read_text(encoding="utf-8")

    code = promoter.apply(CANDIDATE_CONTROL, str(_evidence(tmp_path)))
    assert code == 0, capsys.readouterr().out

    after = metadata_path.read_text(encoding="utf-8")
    changed = [
        line
        for line in difflib.unified_diff(
            before.splitlines(), after.splitlines(), lineterm="", n=0
        )
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    # Exactly the two fields of the promoted control, and nothing else.
    assert len(changed) == 4, changed
    assert any('"automation_status": "ready"' in line for line in changed)
    assert any(CANDIDATE_FILE in line for line in changed)


def test_apply_moves_nothing_when_the_control_is_absent(temp_repo, tmp_path, capsys):
    """A refusal must never leave a half-promoted tree."""
    _resolve_every_gate(temp_repo)
    metadata_path = temp_repo / V6_METADATA
    document = json.loads(metadata_path.read_text(encoding="utf-8"))
    document["controls"] = [
        control
        for control in document["controls"]
        if control["control_id"] != CANDIDATE_CONTROL
    ]
    metadata_path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    before = metadata_path.read_bytes()

    code = promoter.apply(CANDIDATE_CONTROL, str(_evidence(tmp_path)))
    assert code == 1
    assert (temp_repo / CANDIDATE_DIR / CANDIDATE_FILE).is_file()
    assert not (temp_repo / V6_DIR / CANDIDATE_FILE).exists()
    assert metadata_path.read_bytes() == before


# ---------------------------------------------------------------------------
# --check catches drift in the manifest
# ---------------------------------------------------------------------------


def test_check_detects_stale_promotion_delta(temp_repo, capsys):
    manifest = _manifest(temp_repo)
    manifest["promotion_delta"]["automation_status"]["ready"]["after"] += 1
    _write_manifest(temp_repo, manifest)

    assert promoter.main(["--check"]) == 1
    assert (
        "REFUSED: candidates.json promotion_delta does not match live metadata"
        in capsys.readouterr().out
    )


def test_check_detects_a_stale_rego_file_count(temp_repo, capsys):
    manifest = _manifest(temp_repo)
    manifest["promotion_delta"]["target_dir_rego_files"]["before"] = 1
    _write_manifest(temp_repo, manifest)

    assert promoter.main(["--check"]) == 1
    assert "promotion_delta does not match live metadata" in capsys.readouterr().out


def test_check_detects_metadata_json_in_candidate_tree(temp_repo, capsys):
    (temp_repo / CANDIDATE_DIR / "metadata.json").write_text(
        json.dumps({"controls": []}), encoding="utf-8"
    )

    assert promoter.main(["--check"]) == 1
    assert (
        "REFUSED: metadata.json in the candidate tree would expose candidate "
        "policies to test_wiring.py" in capsys.readouterr().out
    )


def test_check_detects_permission_annotation_drift(temp_repo, capsys):
    candidate = temp_repo / CANDIDATE_DIR / CANDIDATE_FILE
    candidate.write_text(
        candidate.read_text(encoding="utf-8").replace(
            "#   - Exchange.ManageAsApp", "#   - Directory.Read.All"
        ),
        encoding="utf-8",
    )

    assert promoter.main(["--check"]) == 1
    output = capsys.readouterr().out
    assert CANDIDATE_FILE in output
    assert "Directory.Read.All" in output
    assert "Exchange.ManageAsApp" in output


def test_check_detects_a_duplicated_permission_annotation(temp_repo, capsys):
    candidate = temp_repo / CANDIDATE_DIR / CANDIDATE_FILE
    candidate.write_text(
        candidate.read_text(encoding="utf-8").replace(
            "#   - Exchange.ManageAsApp",
            "#   - Exchange.ManageAsApp\n#   - Exchange.ManageAsApp",
        ),
        encoding="utf-8",
    )

    assert promoter.main(["--check"]) == 1
    assert "annotates a duplicate permission" in capsys.readouterr().out


def test_check_detects_an_undeclared_candidate_file(temp_repo, capsys):
    shutil.copy2(
        temp_repo / CANDIDATE_DIR / CANDIDATE_FILE,
        temp_repo / CANDIDATE_DIR / "9.9.9_smuggled.rego",
    )

    assert promoter.main(["--check"]) == 1
    assert (
        "REFUSED: 9.9.9_smuggled.rego is in the candidate directory but not declared"
        in capsys.readouterr().out
    )


def test_check_detects_a_package_that_does_not_match_the_control(temp_repo, capsys):
    candidate = temp_repo / CANDIDATE_DIR / CANDIDATE_FILE
    candidate.write_text(
        candidate.read_text(encoding="utf-8").replace(
            "package cis.microsoft_365_foundations.v6_0_0.control_3_2_2",
            "package cis.microsoft_365_foundations.v6_0_0.control_1_1_1",
        ),
        encoding="utf-8",
    )

    assert promoter.main(["--check"]) == 1
    assert "declares package" in capsys.readouterr().out


def test_check_detects_a_control_already_promoted_by_hand(temp_repo, capsys):
    metadata = _metadata(temp_repo)
    for control in metadata["controls"]:
        if control["control_id"] == CANDIDATE_CONTROL:
            control["automation_status"] = "ready"
    (temp_repo / V6_METADATA).write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    assert promoter.main(["--check"]) == 1
    assert (
        f"REFUSED: control {CANDIDATE_CONTROL} already has "
        "automation_status='ready' in metadata.json" in capsys.readouterr().out
    )


def test_check_detects_a_gate_outside_the_vocabulary(temp_repo, capsys):
    manifest = _manifest(temp_repo)
    manifest["candidates"][0]["blocking_gates"][0]["gate"] = "vibes"
    _write_manifest(temp_repo, manifest)

    assert promoter.main(["--check"]) == 1
    assert "which is not in gate_vocabulary" in capsys.readouterr().out


def test_check_detects_a_claim_that_the_licensed_procedure_is_confirmed(
    temp_repo, capsys
):
    """Phase 0 D07 is asserted on every run, not remembered."""
    manifest = _manifest(temp_repo)
    manifest["candidates"][0]["procedure_source"]["licensed_v6_0_0_confirmed"] = True
    _write_manifest(temp_repo, manifest)

    assert promoter.main(["--check"]) == 1
    assert "claims the licensed v6.0.0 procedure is confirmed" in (
        capsys.readouterr().out
    )


def test_check_rejects_an_unknown_schema_version(temp_repo, capsys):
    manifest = _manifest(temp_repo)
    manifest["schema_version"] = 2
    _write_manifest(temp_repo, manifest)

    assert promoter.main(["--check"]) == 1
    assert "schema_version is 2" in capsys.readouterr().out


def test_tool_imports_nothing_from_the_engine():
    """Stdlib only: the promotion tool must run without the engine environment."""
    source = TOOL_PATH.read_text(encoding="utf-8")
    forbidden = ("import worker", "from worker", "import collectors", "from collectors")
    assert not [needle for needle in forbidden if needle in source]
