#!/usr/bin/env python3
"""Promote a candidate Rego policy into a benchmark, or refuse and say why.

``engine/policies/candidate/`` holds policy that has been written, strictly
checked and unit-tested but is deliberately unreachable by any scan: it lives in
a sibling tree that the benchmark's non-recursive ``*.rego`` globs never see, and
the controls it targets stay ``automation_status: "blocked"`` with
``policy_file: null``.

Phase 8's plan says candidates must not be promoted without live-tenant
validation. Prose cannot enforce that. This tool does: ``--apply`` refuses unless
EVERY blocking gate recorded in ``candidates.json`` is resolved AND an existing
live-validation evidence file is named on the command line. ``--check`` verifies
the manifest still describes the tree it claims to describe, including a
promotion delta that is recomputed from the live metadata rather than trusted, so
the recorded instructions cannot rot while promotion has not happened.

The tool is stdlib only, imports nothing from the engine, is deterministic, never
edits a test file and never touches a SOC 2 mapping. Promotion changes engine
state (which control the scan evaluates); it never creates, promotes, infers or
alters a rating.

Usage:
    python tools/policies/promote_candidate.py --check
    python tools/policies/promote_candidate.py --apply 3.2.2 \\
        --live-validation-evidence path/to/evidence

Exit codes: 0 success, 1 refusal or drift, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The repository this tool ships in. ROOT is redirected at a temporary copy by
# tests; SOURCE_ROOT is not, so source documents resolve against the real tree.
SOURCE_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_EXTRACT = SOURCE_ROOT / "docs/engine/Framework/CIS_M365_Benchmarks.json"
MANIFEST_PATH = ROOT / "engine/policies/candidate/candidates.json"
GENERATOR = ROOT / "tools/docs/generate_control_status.py"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

SCHEMA_VERSION = 1

# Phase 0 D07: the only extract available self-declares a later edition than the
# benchmark version the policies target, and the licensed v6.0.0 procedure has not
# been obtained. Recording that per candidate turns a remembered caveat into an
# assertion this tool makes on every run.
#
# The expected value is READ FROM THE EXTRACT rather than pinned as a literal. A
# hand-copied edition string can drift from the document it claims to describe --
# the source declares an en dash, which an ASCII transcription silently loses --
# and a provenance field that is only as good as someone's retyping is not
# provenance at all.


def declared_edition() -> str:
    """The edition the benchmark extract declares about itself.

    Read from SOURCE_ROOT, not ROOT: this is a fact about the extract document,
    not about whichever tree is being promoted, so it stays correct when ROOT is
    redirected at a copy.
    """
    extract = json.loads(BENCHMARK_EXTRACT.read_text(encoding="utf-8"))
    return extract["document_version"]


PROCEDURE_SOURCE_KEYS = {
    "path",
    "number",
    "edition_declared",
    "licensed_v6_0_0_confirmed",
}

TARGET_AUTOMATION_STATUS = "ready"
BLOCKED_AUTOMATION_STATUS = "blocked"

_PACKAGE_RE = re.compile(r"^package\s+(\S+)", re.MULTILINE)
# The METADATA header's ``custom`` block, then the requires_permissions list
# inside it. Parsed rather than eyeballed so an annotation that drifts away from
# metadata.json blocks promotion instead of shipping a policy whose declared
# permissions differ from the ones readiness checks for.
_CUSTOM_BLOCK_RE = re.compile(r"^# custom:\n((?:#(?:  .*|)\n)+)", re.MULTILINE)
_PERMISSIONS_BLOCK_RE = re.compile(
    r"^#   requires_permissions:\n((?:#   (?:  )?- [A-Za-z0-9.-]+\n)+)",
    re.MULTILINE,
)
_PERMISSION_ITEM_RE = re.compile(r"- ([A-Za-z0-9.-]+)")


# ---------------------------------------------------------------------------
# Paths and small helpers
# ---------------------------------------------------------------------------


def _relative(path: Path) -> str:
    """Repo-relative POSIX path when possible, absolute otherwise."""
    try:
        return path.resolve().relative_to(Path(ROOT).resolve()).as_posix()
    except ValueError:
        return str(path)


def _candidate_dir(manifest: dict) -> Path:
    return Path(ROOT) / manifest["candidate_dir"]


def _target_dir(manifest: dict) -> Path:
    return Path(ROOT) / manifest["target_dir"]


def _metadata_path(manifest: dict) -> Path:
    return _target_dir(manifest) / "metadata.json"


def _candidate_tree_root() -> Path:
    """The whole candidate tree, not just this benchmark's directory."""
    return Path(MANIFEST_PATH).parent


def _expected_package(manifest: dict, control_id: str) -> str:
    """Replicate the package path worker/tasks.py builds from metadata."""
    framework = manifest["framework"].replace("-", "_")
    slug = manifest["benchmark"].replace("-", "_")
    version = manifest["version"].replace(".", "_")
    control = control_id.replace(".", "_").replace("-", "_").lower()
    return f"{framework}.{slug}.{version}.control_{control}"


def _annotated_permissions(text: str) -> list[str] | None:
    """requires_permissions declared in the policy's METADATA header, in order.

    ``None`` means the annotation is absent or malformed, which is itself a
    refusal: an unparseable declaration is not a passing one.
    """
    custom = _CUSTOM_BLOCK_RE.search(text)
    if not custom:
        return None
    permissions = _PERMISSIONS_BLOCK_RE.search(custom.group(1))
    if not permissions:
        return None
    return _PERMISSION_ITEM_RE.findall(permissions.group(1))


def _load_json(path: Path) -> tuple[dict | None, str | None]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, f"file not found: {_relative(Path(path))}"
    except (OSError, json.JSONDecodeError) as error:
        return None, f"{_relative(Path(path))} is unreadable: {error}"


def _canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _control_span(text: str, control_id: str) -> tuple[int, int]:
    """Byte span of one control's JSON object inside metadata.json."""
    marker = f'"control_id": "{control_id}"'
    at = text.find(marker)
    if at == -1:
        raise ValueError(f"control {control_id} is not present in metadata.json")
    if text.find(marker, at + 1) != -1:
        raise ValueError(
            f"control {control_id} appears more than once in metadata.json"
        )
    start = text.rfind("{", 0, at)
    if start == -1:
        raise ValueError(f"control {control_id} is not inside a JSON object")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return start, index + 1
    raise ValueError(f"control {control_id} object is unterminated")


def _promote_in_text(text: str, control_id: str, status: str, policy_file: str) -> str:
    """Set automation_status and policy_file for one control, byte-surgically."""
    start, end = _control_span(text, control_id)
    block = text[start:end]
    status_pattern = re.compile(r'("automation_status":\s*)"[a-z_]+"')
    policy_pattern = re.compile(r'("policy_file":\s*)(?:null|"[^"]*")')
    block, status_hits = status_pattern.subn(lambda m: f'{m.group(1)}"{status}"', block)
    block, policy_hits = policy_pattern.subn(
        lambda m: f'{m.group(1)}"{policy_file}"', block
    )
    if status_hits != 1:
        raise ValueError(
            f"control {control_id} has {status_hits} automation_status fields; expected 1"
        )
    if policy_hits != 1:
        raise ValueError(
            f"control {control_id} has {policy_hits} policy_file fields; expected 1"
        )
    return text[:start] + block + text[end:]


def _assert_only_this_control_changed(
    before: dict, after: dict, control_id: str, status: str, policy_file: str
) -> None:
    """Fail loudly if the surgical edit moved anything it should not have."""
    if set(before) != set(after) or len(before["controls"]) != len(after["controls"]):
        raise ValueError("metadata.json structure changed during promotion")
    for old_control, new_control in zip(before["controls"], after["controls"]):
        if old_control["control_id"] != control_id:
            if old_control != new_control:
                raise ValueError(
                    f"promotion altered control {old_control['control_id']}"
                )
            continue
        expected = dict(old_control)
        expected["automation_status"] = status
        expected["policy_file"] = policy_file
        if new_control != expected:
            raise ValueError(f"promotion altered more than two fields of {control_id}")


def _is_promoted(candidate: dict, control: dict | None, manifest: dict) -> bool:
    """True when this candidate has already been promoted, consistently.

    All four facts must agree, so a half-finished or hand-edited promotion is
    NOT mistaken for a completed one and still fails the check.
    """
    if control is None:
        return False
    target = candidate["target_policy_file"]
    return (
        control.get("automation_status") == candidate["target_automation_status"]
        and control.get("policy_file") == target
        and (_target_dir(manifest) / target).is_file()
        and not (_candidate_dir(manifest) / candidate["candidate_file"]).is_file()
    )


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def check(out=None) -> list[str]:
    """Every consistency failure between the manifest and the live tree.

    Returns the failure lines and writes them, one per line, to ``out``. An empty
    list means the manifest still describes the tree it claims to describe.
    """
    out = sys.stdout if out is None else out
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)
        out.write(message + "\n")

    # C1 -- the manifest parses and declares the schema this tool understands.
    manifest, error = _load_json(Path(MANIFEST_PATH))
    if error is not None:
        fail(f"REFUSED: candidate manifest {error}")
        return failures
    if not isinstance(manifest, dict) or manifest.get("schema_version") != (
        SCHEMA_VERSION
    ):
        fail(
            "REFUSED: candidates.json schema_version is "
            f"{manifest.get('schema_version')!r}, expected {SCHEMA_VERSION}"
        )
        return failures

    candidate_dir = _candidate_dir(manifest)
    target_dir = _target_dir(manifest)
    candidates = manifest.get("candidates") or []
    vocabulary = set(manifest.get("gate_vocabulary") or [])

    # C2 -- a metadata.json anywhere in the candidate tree would be found by the
    # RECURSIVE rglob("metadata.json") that discovers benchmarks, which would pull
    # every candidate .rego into the corpus through the non-recursive glob beside
    # it. Its absence is the whole isolation property.
    for stray in sorted(_candidate_tree_root().rglob("metadata.json")):
        fail(
            "REFUSED: metadata.json in the candidate tree would expose candidate "
            f"policies to test_wiring.py ({_relative(stray)})"
        )

    metadata, error = _load_json(_metadata_path(manifest))
    if error is not None:
        fail(f"REFUSED: benchmark metadata {error}")
        return failures
    controls = {
        control["control_id"]: control for control in metadata.get("controls", [])
    }

    # A candidate this tool has ALREADY promoted is a satisfied candidate, not
    # drift: its file is in the benchmark directory, its control is ready and
    # names it. Without this the tool is single-use -- promoting the first
    # candidate would make --check and every later promotion refuse forever.
    promoted = {
        candidate["control_id"]
        for candidate in candidates
        if _is_promoted(candidate, controls.get(candidate["control_id"]), manifest)
    }
    pending = [c for c in candidates if c["control_id"] not in promoted]

    # C3 -- the manifest lists exactly the files that are there, counting only
    # candidates that have not been promoted yet.
    on_disk = {path.name for path in candidate_dir.glob("*.rego")}
    declared = {candidate["candidate_file"] for candidate in pending}
    if on_disk != declared:
        for name in sorted(on_disk - declared):
            fail(f"REFUSED: {name} is in the candidate directory but not declared")
        for name in sorted(declared - on_disk):
            fail(f"REFUSED: declared candidate file {name} is missing from disk")

    for candidate in candidates:
        control_id = candidate["control_id"]
        control = controls.get(control_id)

        if control_id in promoted:
            # Already promoted by this tool and consistent; nothing to verify
            # against the candidate tree because the file is no longer there.
            continue

        # C4 -- promotion has not already happened by hand.
        if control is None:
            fail(f"REFUSED: control {control_id} is not in metadata.json")
        else:
            status = control.get("automation_status")
            if status != BLOCKED_AUTOMATION_STATUS:
                fail(
                    f"REFUSED: control {control_id} already has "
                    f"automation_status={status!r} in metadata.json"
                )
            if control.get("policy_file") is not None:
                fail(
                    f"REFUSED: control {control_id} already has "
                    f"policy_file={control.get('policy_file')!r} in metadata.json"
                )

        candidate_path = candidate_dir / candidate["candidate_file"]
        text = (
            candidate_path.read_text(encoding="utf-8")
            if candidate_path.is_file()
            else None
        )

        if text is None:
            # C3 already reported the missing file; nothing further is checkable.
            continue

        # C5 -- the package the engine would ask OPA for is the package the file
        # declares, so promotion is a byte-identical move with no edit.
        package = _PACKAGE_RE.search(text)
        expected_package = _expected_package(manifest, control_id)
        if package is None or package.group(1) != expected_package:
            fail(
                f"REFUSED: {candidate['candidate_file']} declares package "
                f"{None if package is None else package.group(1)!r}, expected "
                f"{expected_package!r}"
            )

        # C6 -- the policy's own permission annotation, the manifest and the
        # benchmark metadata agree, with no duplicates hiding a disagreement.
        annotated = _annotated_permissions(text)
        manifest_permissions = candidate.get("requires_permissions") or []
        metadata_permissions = (control or {}).get("requires_permissions") or []
        if annotated is None:
            fail(
                f"REFUSED: {candidate['candidate_file']} has no parseable "
                "requires_permissions annotation"
            )
        elif len(annotated) != len(set(annotated)):
            fail(
                f"REFUSED: {candidate['candidate_file']} annotates a duplicate "
                f"permission: {annotated}"
            )
        elif set(annotated) != set(manifest_permissions) or set(annotated) != set(
            metadata_permissions
        ):
            fail(
                f"REFUSED: {candidate['candidate_file']} annotates "
                f"{sorted(set(annotated))}, candidates.json declares "
                f"{sorted(set(manifest_permissions))}, metadata.json declares "
                f"{sorted(set(metadata_permissions))}"
            )

        # C7 -- gates are named from a closed vocabulary and the promotion target
        # is the status this design decided on (never a status whose collector
        # would then never run).
        gates = candidate.get("blocking_gates") or []
        if not gates:
            fail(f"REFUSED: control {control_id} declares no blocking gates")
        for gate in gates:
            if gate.get("gate") not in vocabulary:
                fail(
                    f"REFUSED: control {control_id} names gate "
                    f"{gate.get('gate')!r}, which is not in gate_vocabulary"
                )
        target_status = candidate.get("target_automation_status")
        if target_status != TARGET_AUTOMATION_STATUS:
            fail(
                f"REFUSED: control {control_id} targets automation_status "
                f"{target_status!r}, expected {TARGET_AUTOMATION_STATUS!r}"
            )

        # C8 -- the source edition caveat is asserted, not remembered.
        source = candidate.get("procedure_source")
        if not isinstance(source, dict) or set(source) != PROCEDURE_SOURCE_KEYS:
            fail(
                f"REFUSED: control {control_id} procedure_source keys are "
                f"{sorted(source) if isinstance(source, dict) else source!r}, "
                f"expected {sorted(PROCEDURE_SOURCE_KEYS)}"
            )
        else:
            if source["number"] != control_id:
                fail(
                    f"REFUSED: control {control_id} procedure_source.number is "
                    f"{source['number']!r}"
                )
            expected_edition = declared_edition()
            if source["edition_declared"] != expected_edition:
                fail(
                    f"REFUSED: control {control_id} procedure_source."
                    f"edition_declared is {source['edition_declared']!r}, expected "
                    f"{expected_edition!r}"
                )
            if source["licensed_v6_0_0_confirmed"] is not False:
                fail(
                    f"REFUSED: control {control_id} claims the licensed v6.0.0 "
                    "procedure is confirmed; it has not been obtained"
                )

    # C9 -- the recorded delta is recomputed from the live artifacts. A recorded
    # number that no longer matches is drift in the instructions themselves.
    if not _delta_matches(manifest, metadata, target_dir, len(promoted)):
        fail("REFUSED: candidates.json promotion_delta does not match live metadata")

    return failures


def _projected_counts(
    metadata: dict, pending: int, already: int
) -> tuple[Counter, Counter]:
    """(before, after) automation_status counts for the WHOLE promotion.

    ``before`` is the state the manifest was written against, reconstructed from
    the live counts and the number of candidates already promoted, so the
    recorded delta stays checkable part-way through a promotion sequence instead
    of going stale the moment the first candidate lands.
    """
    live = Counter(
        control["automation_status"] for control in metadata.get("controls", [])
    )
    before = Counter(live)
    before[BLOCKED_AUTOMATION_STATUS] += already
    before[TARGET_AUTOMATION_STATUS] -= already
    after = Counter(before)
    after[BLOCKED_AUTOMATION_STATUS] -= already + pending
    after[TARGET_AUTOMATION_STATUS] += already + pending
    return before, after


def _delta_matches(
    manifest: dict, metadata: dict, target_dir: Path, already: int = 0
) -> bool:
    recorded = manifest.get("promotion_delta")
    if not isinstance(recorded, dict):
        return False
    pending = len(manifest.get("candidates") or []) - already
    before, after = _projected_counts(metadata, pending, already)

    statuses = recorded.get("automation_status")
    if not isinstance(statuses, dict):
        return False
    # Every status the promotion moves must be recorded, and every recorded
    # status must match; a recorded status that does not move is allowed as long
    # as its numbers are right.
    if not {BLOCKED_AUTOMATION_STATUS, TARGET_AUTOMATION_STATUS} <= set(statuses):
        return False
    for status, counts in statuses.items():
        if not isinstance(counts, dict):
            return False
        if (
            counts.get("before") != before[status]
            or counts.get("after") != (after[status])
        ):
            return False

    files = recorded.get("target_dir_rego_files")
    if not isinstance(files, dict):
        return False
    # Same reconstruction: the recorded 'before' is the original file count, so
    # subtract the candidates already moved into the benchmark directory.
    on_disk = len(list(target_dir.glob("*.rego"))) - already
    return (
        files.get("before") == on_disk
        and files.get("after") == on_disk + already + pending
    )


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------


def apply(control_id: str, evidence_path: str, out=None) -> int:
    """Promote one candidate, or refuse with the reason. Returns an exit code."""
    out = sys.stdout if out is None else out

    # A1 -- every consistency failure first. Promotion on top of a manifest that
    # no longer describes the tree would be promotion of something unreviewed.
    if check(out):
        return EXIT_REFUSED

    manifest = json.loads(Path(MANIFEST_PATH).read_text(encoding="utf-8"))
    candidates = {item["control_id"]: item for item in manifest["candidates"]}

    # A2
    candidate = candidates.get(control_id)
    if candidate is None:
        out.write(f"REFUSED: control {control_id} is not listed in candidates.json\n")
        return EXIT_REFUSED

    # A3 -- argparse enforces that the flag is present; this covers an empty value.
    if not evidence_path:
        out.write("REFUSED: --apply requires --live-validation-evidence <path>.\n")
        return EXIT_REFUSED

    # A4
    if not Path(evidence_path).is_file():
        out.write(
            f"REFUSED: live validation evidence file not found: {evidence_path}\n"
        )
        return EXIT_REFUSED

    # A5
    unresolved = [
        gate["gate"] for gate in candidate["blocking_gates"] if not gate.get("resolved")
    ]
    if unresolved:
        out.write(
            f"REFUSED: control {control_id} has unresolved blocking gates: "
            f"{', '.join(unresolved)}\n"
        )
        return EXIT_REFUSED

    metadata_path = _metadata_path(manifest)
    original_text = metadata_path.read_text(encoding="utf-8")
    metadata = json.loads(original_text)
    # The promotion edit is SURGICAL: only the two fields of the promoted control
    # change, and every other byte of metadata.json is preserved. Rewriting the
    # file from a parsed dict would reformat the whole thing as a side effect of
    # promotion -- the shipped file keeps short arrays such as
    # "requires_permissions" on one line, which json.dumps cannot reproduce, so a
    # canonical-form requirement would refuse every promotion forever.
    try:
        updated_text = _promote_in_text(
            original_text,
            control_id,
            candidate["target_automation_status"],
            candidate["target_policy_file"],
        )
    except ValueError as error:
        out.write(f"REFUSED: {error}\n")
        return EXIT_REFUSED

    candidate_path = _candidate_dir(manifest) / candidate["candidate_file"]
    target_path = _target_dir(manifest) / candidate["target_policy_file"]

    # (a) Move the file. git mv keeps the rename in the index so review sees a
    # rename rather than a delete plus an unexplained new policy.
    moved_with = "git mv"
    moved = subprocess.run(
        ["git", "mv", str(candidate_path), str(target_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if moved.returncode != 0:
        shutil.move(str(candidate_path), str(target_path))
        moved_with = "shutil.move"
    out.write(
        f"moved {_relative(candidate_path)} -> {_relative(target_path)} "
        f"({moved_with})\n"
    )

    # (b) Flip the control. Nothing else in metadata.json is touched, and that is
    # verified by comparing the parsed documents rather than trusted.
    _assert_only_this_control_changed(
        metadata,
        json.loads(updated_text),
        control_id,
        candidate["target_automation_status"],
        candidate["target_policy_file"],
    )
    metadata_path.write_text(updated_text, encoding="utf-8")
    metadata = json.loads(updated_text)
    out.write(
        f"updated {_relative(metadata_path)}: {control_id} -> "
        f"automation_status={candidate['target_automation_status']!r}, "
        f"policy_file={candidate['target_policy_file']!r}\n"
    )

    # (c) The control status document is generated, never hand-edited.
    subprocess.run([sys.executable, str(GENERATOR)], cwd=str(ROOT), check=True)

    # (d) Post-promotion census, so the operator can update the pinned counts.
    counts = Counter(control["automation_status"] for control in metadata["controls"])
    rego_files = len(list(_target_dir(manifest).glob("*.rego")))
    out.write("post-promotion counts (update the pinned census tests):\n")
    for status in sorted(counts):
        out.write(f"  {status}: {counts[status]}\n")
    out.write(f"  {_relative(_target_dir(manifest))}/*.rego: {rego_files}\n")
    out.write(
        f"  live validation evidence: {evidence_path}\n"
        "  This tool changed engine state only. No SOC 2 rating was created, "
        "promoted, inferred or altered.\n"
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promote_candidate.py",
        description=(
            "Verify the candidate policy manifest, or promote one candidate once "
            "every blocking gate is resolved and live-tenant validation evidence "
            "exists."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the manifest against the live tree. Writes nothing.",
    )
    parser.add_argument(
        "--apply",
        metavar="CONTROL_ID",
        help="Promote this candidate control.",
    )
    parser.add_argument(
        "--live-validation-evidence",
        metavar="PATH",
        help="Existing file recording live-tenant validation of the collector.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check and args.apply:
        parser.error("--check and --apply are mutually exclusive.")
    if not args.check and not args.apply:
        parser.error("one of --check or --apply CONTROL_ID is required.")

    if args.check:
        failures = check()
        if failures:
            print(
                f"{len(failures)} candidate manifest check(s) failed.",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        manifest = json.loads(Path(MANIFEST_PATH).read_text(encoding="utf-8"))
        print(
            f"{len(manifest['candidates'])} candidate policy file(s) verified and "
            "unreachable by any scan."
        )
        return EXIT_OK

    if args.live_validation_evidence is None:
        parser.error("--apply requires --live-validation-evidence <path>.")
    return apply(args.apply, args.live_validation_evidence)


if __name__ == "__main__":
    sys.exit(main())
