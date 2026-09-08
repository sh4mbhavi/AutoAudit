"""Every ready policy's real output must satisfy the result contract.

``engine/tests/test_result_contract.py`` validates hand-written dictionaries
against ``OPAResult``. That proves the model rejects what it should; it does not
prove a single policy in the tree produces something it accepts, and that gap is
where the defect lived. ``OPAResult`` is ``strict=True, extra="forbid"`` with a
required ``affected_resources: list[Any]`` and no default, so a policy that omits
the key -- from its ``default result`` or from every path -- produces output the
worker rejects. ``tasks.py`` turns that rejection into ``evaluation_error``, so
the control is recorded as an engine failure rather than as a tenant finding, and
the tenant sees an error where their evidence should have been assessed.

Phase 11 counted 18 such controls by reading the source. Executing the policies
against a battery of inputs found 24, which is the argument for this file
existing rather than for a more careful reading.

Coverage is every control any selectable benchmark marks ``ready`` -- v6.0.0,
the two older CIS versions ``benchmark_reader.list_benchmarks`` still offers, and
Essential Eight -- because the contract applies to whatever a tenant can select,
not to the 44 controls Appendix B happens to crosswalk.

The inputs below are deliberately hostile and deliberately generic: they are the
shapes a policy meets when a collector returns nothing, errors, or hands back
something of the wrong type. A policy is free to answer ``compliant: null`` for
any of them -- indeterminate is the correct answer to evidence that was never
asserted -- but it is not free to answer with a document the worker cannot parse.
Valid-evidence coverage is the crosswalk semantics fixture's job.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 # controlled OPA invocation
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from worker.result_contract import OPAResult

ENGINE = Path(__file__).resolve().parents[1]
POLICIES = ENGINE / "policies"

# The checked-in crosswalk semantics fixture carries a valid `pass` and `fail`
# input for each control it covers. Those inputs are the shape a policy meets
# when a collector succeeds, and they drive the `assessed_result` path the
# INPUT_SHAPES below never reach. Twenty controls satisfied the contract on
# every absent-or-malformed shape and still omitted `affected_resources` on the
# assessed path, so the worker rejected a healthy tenant's finding: a false
# pass in the collector became an evaluation_error at the contract. This gate
# does not see that until it feeds valid evidence, which is what these cases do.
HEALTHY_FIXTURE = ENGINE / "tests" / "fixtures" / "crosswalk_semantics.json"

# The shapes a policy actually meets when evidence is absent or wrong. Named,
# because a failure should say which one.
INPUT_SHAPES = {
    "no_evidence": {},
    "collector_error": {"collector_error": "graph returned 503"},
    "nested_error": {"error": "authentication failed"},
    "unrelated_evidence": {"unexpected_key": True},
    "null": None,
    "string_instead_of_object": "oops",
    "array_instead_of_object": [],
}


def _ready_controls() -> list[tuple[str, str, str]]:
    """(benchmark, control_id, rego package) for every selectable ready control.

    ``candidate/`` is excluded on purpose: those policies are not selectable and
    have no metadata entry promising a tenant anything.
    """
    found: list[tuple[str, str, str]] = []
    for metadata_path in sorted(POLICIES.glob("*/*/*/metadata.json")):
        if "candidate" in metadata_path.parts:
            continue
        metadata = json.loads(metadata_path.read_text())
        benchmark = "{framework}/{slug}/{version}".format(**metadata)
        for control in metadata["controls"]:
            if control.get("automation_status") != "ready":
                continue
            policy_file = control.get("policy_file")
            assert (
                policy_file
            ), f"{benchmark} {control['control_id']} is ready with no policy_file"
            source = (metadata_path.parent / policy_file).read_text()
            package = re.search(r"^package\s+([\w.]+)", source, re.MULTILINE)
            assert package, f"{policy_file} declares no package"
            found.append((benchmark, control["control_id"], package.group(1)))
    assert found, "no ready controls found; the glob above is wrong"
    return found


READY = _ready_controls()


@pytest.fixture(scope="module")
def evaluated() -> dict[str, dict]:
    """The whole policy tree evaluated once per input shape.

    One `opa eval` per shape rather than one per policy: the query is the `data`
    root, so a single evaluation carries every package's `result`.
    """
    binary = os.environ.get("OPA_BINARY") or shutil.which("opa")
    assert binary, (
        "Install the pinned OPA binary or set OPA_BINARY; the result contract "
        "cannot be checked against policies that were never executed"
    )
    outputs: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="autoaudit-contract-") as raw:
        document = Path(raw) / "input.json"
        for shape, value in INPUT_SHAPES.items():
            document.write_text(json.dumps(value))
            completed = subprocess.run(  # nosec B603 # fixed argv, no shell
                [
                    binary,
                    "eval",
                    "-d",
                    str(POLICIES),
                    "-i",
                    str(document),
                    "-f",
                    "json",
                    "data",
                ],
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            assert completed.returncode == 0, completed.stderr or completed.stdout
            outputs[shape] = json.loads(completed.stdout)["result"][0]["expressions"][
                0
            ]["value"]
    return outputs


def _walk(tree: dict, package: str):
    node = tree
    for segment in package.split("."):
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node


@pytest.mark.parametrize(
    "benchmark,control_id,package", READY, ids=[f"{b} {c}" for b, c, _ in READY]
)
def test_ready_policy_output_satisfies_the_result_contract(
    benchmark, control_id, package, evaluated
):
    problems: list[str] = []
    for shape in INPUT_SHAPES:
        node = _walk(evaluated[shape], package)
        if node is None:
            problems.append(f"{shape}: package {package} produced no document")
            continue
        if "result" not in node:
            problems.append(
                f"{shape}: no `result` rule; the worker reads "
                f"data.{package}.result and would find nothing"
            )
            continue
        try:
            OPAResult.model_validate(node["result"])
        except ValidationError as error:
            detail = "; ".join(
                f"{'.'.join(str(part) for part in item['loc'])}: {item['type']}"
                for item in error.errors()
            )
            problems.append(f"{shape}: {detail}")
    assert not problems, (
        f"{benchmark} {control_id} produces output the worker rejects. The "
        "worker validates every policy result against OPAResult and records a "
        "rejection as evaluation_error, so this control cannot report a finding "
        "for the inputs listed:\n  " + "\n  ".join(problems)
    )


def test_every_ready_control_is_covered():
    """The population is derived, so a new benchmark cannot arrive uncovered."""
    versions = {benchmark for benchmark, _, _ in READY}
    assert versions == {
        "cis/microsoft-365-foundations/v3.1.0",
        "cis/microsoft-365-foundations/v4.0.0",
        "cis/microsoft-365-foundations/v6.0.0",
        "essential-eight/asd-essential-eight/v2025",
    }, (
        "A selectable benchmark appeared or disappeared. Either it is offered to "
        "tenants, in which case its ready controls belong under this gate, or it "
        "is not, in which case it should not be marked ready."
    )
    assert len(READY) == 76, (
        f"{len(READY)} ready controls; update this count deliberately so that "
        "adding a control is a decision rather than an accident"
    )


@pytest.mark.parametrize(
    "benchmark,control_id,package", READY, ids=[f"{b} {c}" for b, c, _ in READY]
)
def test_ready_policy_has_a_direct_rego_test(benchmark, control_id, package):
    """Every ready control must be exercised directly by at least one Rego test.

    test_crosswalk_semantic_coverage.py is pinned to the 44-control Appendix B
    population by design, which left 25 selectable controls with no direct
    assertion of any kind -- and eight of the nine controls that could never
    produce a valid result were among them. This closes that hole without
    widening the crosswalk, which is a reviewed artifact and not a coverage
    ledger.
    """
    needle = f"data.{package}.result"
    for path in sorted(Path(__file__).parent.glob("*.rego")):
        if needle in path.read_text():
            return
    pytest.fail(
        f"{benchmark} {control_id} is offered to tenants as ready and no Rego "
        f"test evaluates {needle}. Add direct cases -- at minimum a pass, a "
        "fail, and evidence that is absent, of the wrong type and carrying a "
        "collector error."
    )


def test_the_rego_annotation_agrees_with_the_benchmark_metadata():
    """A control described two ways is described wrong in one of them.

    Every policy carries a `# METADATA` block naming the service it assesses,
    and `metadata.json` names it again. Thirteen controls disagreed -- the whole
    of CIS section 2.1 plus 2.4.4, annotated `Exchange` while the metadata said
    `Defender`. metadata.json is what the UI, the documentation generator and
    the crosswalk all read, so the annotation was the copy that had drifted, and
    a reader of the policy source was told something different from a reader of
    the product.
    """
    mismatched: list[str] = []
    for metadata_path in sorted(POLICIES.glob("*/*/*/metadata.json")):
        if "candidate" in metadata_path.parts:
            continue
        metadata = json.loads(metadata_path.read_text())
        for control in metadata["controls"]:
            policy_file = control.get("policy_file")
            if not policy_file:
                continue
            source = (metadata_path.parent / policy_file).read_text()
            annotated = re.search(r"^#\s+service:\s*(\S+)\s*$", source, re.MULTILINE)
            if annotated is None:
                continue
            if annotated.group(1) != control.get("service"):
                mismatched.append(
                    f"{policy_file}: annotated {annotated.group(1)!r}, "
                    f"metadata.json says {control.get('service')!r}"
                )
    assert not mismatched, "\n  ".join(["service annotations disagree:", *mismatched])


def _healthy_cases() -> list[tuple[str, str, str, dict, bool]]:
    """(control_id, package, case, input, expected_compliant) for valid evidence.

    Only ``pass`` and ``fail`` cases are taken: their ``expected`` is a bool, so
    the assessment is determinate and the assessed path is the one under test.
    ``missing``/``malformed``/``boundary`` carry ``expected: null`` and belong to
    the INPUT_SHAPES gate above, not here.
    """
    if not HEALTHY_FIXTURE.exists():
        return []
    fixture = json.loads(HEALTHY_FIXTURE.read_text())["phase4_crosswalk"]
    package_of = {control_id: package for _, control_id, package in READY}
    cases: list[tuple[str, str, str, dict, bool]] = []
    for control_id, spec in fixture["controls"].items():
        package = package_of.get(control_id)
        if package is None:
            continue
        for case in ("pass", "fail"):
            block = spec.get("cases", {}).get(case)
            if block is None or not isinstance(block.get("expected"), bool):
                continue
            cases.append(
                (control_id, package, case, block["input"], block["expected"])
            )
    return cases


HEALTHY = _healthy_cases()


def _evaluate(document: dict) -> dict:
    """Evaluate the whole policy tree against one concrete input document."""
    binary = os.environ.get("OPA_BINARY") or shutil.which("opa")
    assert binary, (
        "Install the pinned OPA binary or set OPA_BINARY; the healthy-evidence "
        "contract cannot be checked against policies that were never executed"
    )
    with tempfile.TemporaryDirectory(prefix="autoaudit-healthy-") as raw:
        path = Path(raw) / "input.json"
        path.write_text(json.dumps(document))
        completed = subprocess.run(  # nosec B603 # fixed argv, no shell
            [
                binary,
                "eval",
                "-d",
                str(POLICIES),
                "-i",
                str(path),
                "-f",
                "json",
                "data",
            ],
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]


def test_the_crosswalk_carries_healthy_evidence():
    """A regression guard: if the fixture stops carrying valid cases, this gate
    silently tests nothing, which is the failure mode it exists to prevent."""
    assert len(HEALTHY) >= 80, (
        f"{len(HEALTHY)} determinate healthy cases resolved to a ready control; "
        "the crosswalk fixture used to carry a pass and a fail for 44 controls. "
        "A shrunk population means the assessed path is going untested again."
    )


@pytest.mark.parametrize(
    "control_id,package,case,document,expected",
    HEALTHY,
    ids=[f"{c} {case}" for c, _, case, _, _ in HEALTHY],
)
def test_ready_policy_satisfies_the_contract_on_healthy_evidence(
    control_id, package, case, document, expected
):
    """Valid evidence must produce a document the worker accepts, and the verdict
    must be the one the evidence supports -- not merely a parseable object.

    This is the healthy half of GRC-D04/GRC-D06: a passing control emits a
    schema-valid ``affected_resources`` (``[]`` where nothing applies), and the
    assessment reflects the evidence rather than defaulting to indeterminate.
    """
    node = _walk(_evaluate(document), package)
    assert node is not None, f"package {package} produced no document for {case}"
    assert "result" in node, (
        f"{control_id} {case}: no `result` rule; the worker reads "
        f"data.{package}.result and would find nothing"
    )
    result = node["result"]
    try:
        model = OPAResult.model_validate(result)
    except ValidationError as error:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['type']}"
            for item in error.errors()
        )
        pytest.fail(
            f"{control_id} {case} produces output the worker rejects on valid "
            f"evidence, so a real tenant finding becomes an evaluation_error: "
            f"{detail}"
        )
    assert model.compliant is expected, (
        f"{control_id} {case}: evidence asserts compliant={expected}, policy "
        f"returned compliant={model.compliant!r}. The assessed path must reflect "
        "the evidence, not default to indeterminate."
    )
