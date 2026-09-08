"""DOC-02: control status documents are generated from metadata, never hand-typed."""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

spec = importlib.util.spec_from_file_location(
    "generate_control_status",
    Path(__file__).resolve().parents[1] / "docs" / "generate_control_status.py",
)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

GENERATOR = ROOT / "tools" / "docs" / "generate_control_status.py"
V6_METADATA = (
    ROOT / "engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json"
)
V6_DOCUMENT = (
    ROOT / "docs/engine/policies/cis/microsoft-365-foundations/v6.0.0/controls.md"
)

# The pre-generator hand-written page carried these rows. None of them agreed
# with metadata.json, so none of them may survive regeneration.
STALE_ROWS = [
    "| Automated | 47 |",
    "| Deferred | 12 |",
    "| Blocked | 21 |",
    "| Manual | 14 |",
    "| Not Started | 46 |",
    "| **CIS Automated** | 117 |",
    "| **CIS Manual** | 23 |",
    "*Last Updated: 2025-12-21*",
]


def metadata_files():
    return generator.discover_metadata_files(ROOT)


def metadata_ids():
    return [
        path.resolve().relative_to(ROOT).as_posix()
        for path in generator.discover_metadata_files(ROOT)
    ]


def copy_tree(destination):
    """A minimal repo copy: policy metadata plus the documents generated from it."""
    for relative in ("engine/policies", "docs/engine/policies"):
        shutil.copytree(ROOT / relative, destination / relative)
    return destination


def v6_metadata(root):
    return root / "engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json"


def synthetic(**overrides):
    """A minimal valid control record for negative-path rendering tests."""
    control = {
        "control_id": "1.1.1",
        "title": "Ensure something",
        "automation_status": "ready",
        "benchmark_audit_type": "Automated",
        "is_manual": False,
        "severity": "low",
        "service": "EntraID",
        "level": "L1",
        "policy_file": None,
        "data_collector_id": None,
    }
    control.update(overrides)
    return control


def v6_document(root):
    return (
        root / "docs/engine/policies/cis/microsoft-365-foundations/v6.0.0/controls.md"
    )


def run_generator(root, *arguments, seed=None):
    environment = {**os.environ}
    if seed is not None:
        environment["PYTHONHASHSEED"] = seed
    return subprocess.run(
        [sys.executable, str(GENERATOR), "--root", str(root), *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def run_check(root):
    return run_generator(root, "--check")


@pytest.mark.parametrize("metadata_path", metadata_files(), ids=metadata_ids())
def test_generation_introduces_no_date_of_its_own(metadata_path):
    """A date that moves with the calendar would make the --check gate useless."""
    document = generator.render_document(metadata_path, ROOT)
    source = metadata_path.read_text(encoding="utf-8")
    dates = re.compile(r"\d{4}-\d{2}-\d{2}")
    assert set(dates.findall(document)) <= set(dates.findall(source))
    assert json.loads(source)["release_date"] in dates.findall(document)


def test_generation_is_deterministic_across_processes(tmp_path):
    """Two fresh interpreters with different hash seeds must agree byte for byte."""
    first = copy_tree(tmp_path / "first")
    second = copy_tree(tmp_path / "second")
    assert run_generator(first, seed="0").returncode == 0
    assert run_generator(second, seed="12345").returncode == 0

    for metadata_path in metadata_files():
        relative = generator.document_path(metadata_path, ROOT).relative_to(ROOT)
        assert (first / relative).read_bytes() == (second / relative).read_bytes()
        assert (first / relative).read_bytes() == (ROOT / relative).read_bytes()


@pytest.mark.parametrize("metadata_path", metadata_files(), ids=metadata_ids())
def test_every_benchmark_has_a_committed_document(metadata_path):
    document = generator.document_path(metadata_path, ROOT)
    assert document.exists(), f"{document} is missing"
    assert document.read_text(encoding="utf-8") == generator.render_document(
        metadata_path, ROOT
    )


def test_check_accepts_the_committed_documents():
    result = run_check(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "match metadata" in result.stdout


def test_check_rejects_metadata_drift(tmp_path):
    copy_tree(tmp_path)
    mutated = v6_metadata(tmp_path)
    payload = json.loads(mutated.read_text(encoding="utf-8"))
    payload["controls"][0]["automation_status"] = "not_started"
    mutated.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    result = run_check(tmp_path)

    assert result.returncode != 0
    assert "disagree with metadata" in result.stderr
    assert (
        "--- docs/engine/policies/cis/microsoft-365-foundations/v6.0.0/controls.md"
        in result.stdout
    )
    assert "-| `ready` | 69 |" in result.stdout
    assert "+| `ready` | 68 |" in result.stdout


def test_check_rejects_a_hand_edited_document(tmp_path):
    copy_tree(tmp_path)
    document = v6_document(tmp_path)
    document.write_text(
        document.read_text(encoding="utf-8").replace("| 140 |", "| 141 |"),
        encoding="utf-8",
    )

    result = run_check(tmp_path)

    assert result.returncode != 0
    assert "@@" in result.stdout


def test_write_mode_restores_a_hand_edited_document(tmp_path):
    copy_tree(tmp_path)
    document = v6_document(tmp_path)
    expected = document.read_text(encoding="utf-8")
    document.write_text("hand edited\n", encoding="utf-8")

    assert generator.main(["--root", str(tmp_path)]) == 0

    assert document.read_text(encoding="utf-8") == expected
    assert run_check(tmp_path).returncode == 0


@pytest.mark.parametrize(
    ("status", "count"),
    [
        ("ready", 69),
        ("blocked", 31),
        ("not_started", 17),
        ("deferred", 12),
        ("manual", 11),
    ],
)
def test_v6_automation_status_totals_come_from_metadata(status, count):
    controls = json.loads(V6_METADATA.read_text(encoding="utf-8"))["controls"]
    assert sum(1 for c in controls if c["automation_status"] == status) == count
    assert f"| `{status}` | {count} |" in V6_DOCUMENT.read_text(encoding="utf-8")


def test_v6_total_control_count():
    controls = json.loads(V6_METADATA.read_text(encoding="utf-8"))["controls"]
    assert len(controls) == 140
    assert "| Controls described | 140 |" in V6_DOCUMENT.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("field", "predicate", "count"),
    [
        ("is_manual", lambda value: value is True, 24),
        ("benchmark_audit_type", lambda value: value == "Manual", 23),
        ("automation_status", lambda value: value == "manual", 11),
    ],
)
def test_v6_keeps_the_three_manual_questions_apart(field, predicate, count):
    controls = json.loads(V6_METADATA.read_text(encoding="utf-8"))["controls"]
    assert sum(1 for c in controls if predicate(c[field])) == count
    document = V6_DOCUMENT.read_text(encoding="utf-8")
    assert "Three questions this document keeps separate" in document
    assert f"{count} (`{field}`" in document


@pytest.mark.parametrize("row", STALE_ROWS)
def test_no_stale_handwritten_total_survives(row):
    assert row not in V6_DOCUMENT.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("2.1.9", "2.1.10"),
        ("2.1.10", "2.1.11"),
        ("2.1.15", "2.2.1"),
        ("4.2", "5.1.2.1"),
        ("5.2.2.9", "5.2.2.10"),
        ("7.2.9", "7.2.10"),
        ("9.1.9", "9.1.10"),
    ],
)
def test_control_ids_sort_numerically_not_lexicographically(earlier, later):
    assert generator._natural_key(earlier) < generator._natural_key(later)
    document = V6_DOCUMENT.read_text(encoding="utf-8")
    assert document.index(f"\n| {earlier} | ") < document.index(f"\n| {later} | ")


def test_natural_key_orders_double_digit_sections_and_essential_eight_ids():
    ordered = sorted(
        ["10.1.1", "9.1.1", "1.10.1", "1.9.1", "E8-MAC-1.10", "E8-MAC-1.2"],
        key=generator._natural_key,
    )
    assert ordered == [
        "1.9.1",
        "1.10.1",
        "9.1.1",
        "10.1.1",
        "E8-MAC-1.2",
        "E8-MAC-1.10",
    ]


def test_natural_key_sorts_a_prefix_id_before_its_children():
    assert sorted(["1.1.2", "1.1", "1.1.1", "1.10"], key=generator._natural_key) == [
        "1.1",
        "1.1.1",
        "1.1.2",
        "1.10",
    ]


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("A | pipe", "A \\| pipe"),
        ("A \\| pre-escaped pipe", "A \\\\\\| pre-escaped pipe"),
        ("A\nnewline", "A newline"),
    ],
)
def test_metadata_text_cannot_break_the_table(title, expected):
    document = generator.render_markdown(
        {
            "benchmark": "Synthetic",
            "version": "v0",
            "controls": [synthetic(title=title)],
        },
        "engine/policies/synthetic/metadata.json",
        "0" * 64,
    )
    assert expected in document
    rows = [line for line in document.splitlines() if line.startswith("| 1.1.1 |")]
    assert len(rows) == 1
    assert rows[0].count(" | ") == 9


def test_a_service_name_containing_a_pipe_cannot_break_the_summary_table():
    document = generator.render_markdown(
        {
            "benchmark": "Synthetic",
            "version": "v0",
            "controls": [synthetic(service="Teams | Exchange")],
        },
        "engine/policies/synthetic/metadata.json",
        "0" * 64,
    )
    assert "| `Teams \\| Exchange` | 1 | 100.0% |" in document


def test_a_backslash_is_not_doubled_inside_a_code_span():
    document = generator.render_markdown(
        {
            "benchmark": "Synthetic",
            "version": "v0",
            "controls": [synthetic(service="A\\B", data_collector_id="x.y\\z")],
        },
        "engine/policies/synthetic/metadata.json",
        "0" * 64,
    )
    # Backslashes are literal inside backticks, so escaping them would corrupt
    # the rendered value.
    assert "| `A\\B` | 1 | 100.0% |" in document
    assert "`x.y\\z`" in document


@pytest.mark.parametrize(
    "controls",
    [
        [synthetic(), synthetic()],
        [synthetic(control_id=None)],
        [{"title": "no id"}],
    ],
    ids=["duplicate-id", "null-id", "missing-id"],
)
def test_malformed_control_identity_is_refused(controls):
    with pytest.raises(generator.MetadataError):
        generator.render_markdown(
            {"benchmark": "Synthetic", "version": "v0", "controls": controls},
            "engine/policies/synthetic/metadata.json",
            "0" * 64,
        )


def test_malformed_metadata_fails_the_gate_without_a_traceback(tmp_path):
    copy_tree(tmp_path)
    metadata = v6_metadata(tmp_path)
    payload = json.loads(metadata.read_text(encoding="utf-8"))
    payload["controls"][1]["control_id"] = payload["controls"][0]["control_id"]
    metadata.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "duplicate control_id 1.1.1" in result.stderr
    assert "Traceback" not in result.stderr


def test_a_non_boolean_is_manual_is_not_reported_as_an_answer():
    document = generator.render_markdown(
        {
            "benchmark": "Synthetic",
            "version": "v0",
            "controls": [synthetic(is_manual=None), synthetic(control_id="1.1.2")],
        },
        "engine/policies/synthetic/metadata.json",
        "0" * 64,
    )
    assert "| *(not set)* | 1 | 50.0% |" in document
    assert "| `false` | 1 | 50.0% |" in document
    # A missing flag is not a "false" answer, and it is never counted as "true".
    assert "0 (`is_manual` == `true`)" in document


def test_line_ending_drift_is_detected(tmp_path):
    copy_tree(tmp_path)
    document = v6_document(tmp_path)
    document.write_bytes(document.read_bytes().replace(b"\n", b"\r\n"))

    result = run_check(tmp_path)

    assert result.returncode != 0
    assert "controls.md" in result.stdout


def test_an_orphaned_document_is_reported(tmp_path):
    copy_tree(tmp_path)
    orphan = tmp_path / "docs/engine/policies/cis/microsoft-365-foundations/v9.9.9"
    orphan.mkdir(parents=True)
    (orphan / "controls.md").write_text("stale\n", encoding="utf-8")

    result = run_check(tmp_path)

    assert result.returncode != 0
    assert (
        "v9.9.9/controls.md: no metadata.json generates this document" in result.stdout
    )
