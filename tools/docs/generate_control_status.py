#!/usr/bin/env python3
"""Generate benchmark control-status documents from engine policy metadata.

DOC-02: the control status pages under ``docs/engine/policies`` used to be
hand-maintained, so their totals drifted away from the ``metadata.json`` files
that the engine actually reads. This generator makes ``metadata.json`` the only
source of truth and gives CI a ``--check`` gate that fails on drift.

Output is deterministic: the same metadata bytes always render byte-identical
markdown. There is deliberately no generation timestamp, because a date that
changes on every run would make ``--check`` useless. Provenance comes from the
benchmark's own ``release_date`` plus the SHA-256 of the metadata file.

Usage:
    python tools/docs/generate_control_status.py            # write the documents
    python tools/docs/generate_control_status.py --check    # CI drift gate
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

POLICIES_DIR = Path("engine") / "policies"
DOCS_DIR = Path("docs")
DOCUMENT_NAME = "controls.md"

EMPTY_CELL = "—"

# Implementation status is engine state only. It never expresses, implies or
# promotes a SOC 2 rating.
AUTOMATION_STATUS_ORDER = ["ready", "deferred", "blocked", "manual", "not_started"]
AUTOMATION_STATUS_MEANING = {
    "ready": "Collector and policy are implemented, so the scan evaluates this control.",
    "deferred": "Collector runs, but a pass/fail decision still needs human review.",
    "blocked": "Collector exists and cannot run yet (authentication or API blocker).",
    "manual": "No programmatic source, so the control is verified by hand.",
    "not_started": "No collector or policy implemented yet.",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _natural_key(control_id: str) -> tuple:
    """Sort key that orders 1.1.9 < 1.1.10 < 1.2.1 and 9.x < 10.x.

    Digit runs compare numerically, everything else compares as text, so the
    Essential Eight ids (``E8-MAC-1.1``) order sensibly too.
    """
    key: list[tuple[int, int, str]] = []
    for part in re.split(r"(\d+)", control_id):
        if part.isdigit():
            key.append((0, int(part), ""))
        elif part:
            key.append((1, 0, part))
    # Sorts a bare prefix ("1.1") ahead of its children ("1.1.1") and breaks
    # ties between ids that share a decomposition ("01.1" and "1.1").
    key.append((-1, 0, control_id))
    return tuple(key)


def _text(value: object) -> str:
    """Collapse whitespace so no metadata value can inject markdown structure."""
    return " ".join(str(value).split())


def _cell(value: object) -> str:
    """Render one table cell, escaping anything that would break the table."""
    if value is None or value == "":
        return EMPTY_CELL
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    # Backslash first: escaping pipes first would leave "\\|" unescaped.
    return _text(value).replace("\\", "\\\\").replace("|", "\\|")


def _code_text(value: object) -> str:
    """Content for a code span.

    A pipe still needs escaping because the table is split before code spans are
    parsed, but a backslash is literal inside backticks and must not be doubled.
    """
    return _text(value).replace("|", "\\|")


def _code_cell(value: object) -> str:
    if value is None or value == "":
        return EMPTY_CELL
    return f"`{_code_text(value)}`"


def _controls(count: int) -> str:
    return f"{count} control" if count == 1 else f"{count} controls"


def _share(count: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{count / total * 100:.1f}%"


def _ordered_keys(counts: Counter, preferred: list) -> list:
    """Preferred keys first (when present), then anything else alphabetically."""
    known = [key for key in preferred if key in counts]
    rest = sorted(
        (key for key in counts if key not in preferred),
        key=lambda key: (key is None, str(key)),
    )
    return known + rest


def _label(value: object) -> str:
    """Row label for a count table."""
    if value is None or value == "":
        return "*(not set)*"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    return f"`{_code_text(value)}`"


def _count_table(
    heading: str,
    column: str,
    counts: Counter,
    keys: list[str],
    total: int,
    meanings: dict[str, str] | None = None,
) -> list[str]:
    lines = [heading, ""]
    if meanings is None:
        lines.append(f"| {column} | Controls | Share |")
        lines.append("| --- | ---: | ---: |")
    else:
        lines.append(f"| {column} | Controls | Share | What it means |")
        lines.append("| --- | ---: | ---: | --- |")
    for key in keys:
        count = counts[key]
        row = f"| {_label(key)} | {count} | {_share(count, total)} |"
        if meanings is not None:
            row += f" {meanings.get(key, EMPTY_CELL)} |"
        lines.append(row)
    row = f"| **Total** | **{total}** | **{_share(total, total)}** |"
    if meanings is not None:
        row += " |"
    lines.append(row)
    lines.append("")
    return lines


def _bool_or_none(value: object) -> bool | None:
    """Only a real boolean answers the is_manual question."""
    return value if isinstance(value, bool) else None


def _grouping_field(controls: list[dict]) -> tuple[str, str]:
    """Pick the level-like field this benchmark populates."""
    if any(control.get("maturity_level") for control in controls):
        return "maturity_level", "Maturity level"
    return "level", "Level"


class MetadataError(ValueError):
    """The metadata cannot produce an honest document."""


def _validated_controls(metadata: dict, source_rel: str) -> list[dict]:
    controls = list(metadata.get("controls") or [])
    seen: set[str] = set()
    for control in controls:
        control_id = control.get("control_id")
        if not control_id:
            raise MetadataError(f"{source_rel}: a control has no control_id")
        if control_id in seen:
            raise MetadataError(f"{source_rel}: duplicate control_id {control_id}")
        seen.add(control_id)
    return controls


def render_markdown(metadata: dict, source_rel: str, digest: str) -> str:
    """Render the full document text. Pure: same arguments, same output."""
    controls = _validated_controls(metadata, source_rel)
    total = len(controls)
    benchmark = _text(metadata.get("benchmark") or metadata.get("slug") or "Benchmark")
    version = _text(metadata.get("version") or "unversioned")

    automation = Counter(control.get("automation_status") for control in controls)
    audit_type = Counter(control.get("benchmark_audit_type") for control in controls)
    manual_flag = Counter(
        _bool_or_none(control.get("is_manual")) for control in controls
    )
    severity = Counter(control.get("severity") for control in controls)
    service = Counter(control.get("service") for control in controls)

    level_field, level_header = _grouping_field(controls)
    level = Counter(control.get(level_field) for control in controls)

    manual_true = manual_flag[True]
    audit_manual = audit_type["Manual"] if "Manual" in audit_type else 0
    status_manual = automation["manual"] if "manual" in automation else 0

    flagged_not_status = sum(
        1
        for control in controls
        if _bool_or_none(control.get("is_manual")) is True
        and control.get("automation_status") != "manual"
    )
    audit_not_status = sum(
        1
        for control in controls
        if control.get("benchmark_audit_type") == "Manual"
        and control.get("automation_status") != "manual"
    )
    status_not_audit = sum(
        1
        for control in controls
        if control.get("automation_status") == "manual"
        and control.get("benchmark_audit_type") != "Manual"
    )

    lines: list[str] = []
    lines.append(f"# {benchmark} {version} - control status")
    lines.append("")
    lines.append("<!-- GENERATED FILE - DO NOT EDIT BY HAND.")
    lines.append(f"     Source:     {source_rel}")
    lines.append("     Generator:  tools/docs/generate_control_status.py")
    lines.append("     Regenerate: python tools/docs/generate_control_status.py")
    lines.append(
        "     Verify:     python tools/docs/generate_control_status.py --check"
    )
    lines.append("-->")
    lines.append("")
    lines.append(
        "Every number below is counted from the source metadata, never typed by hand. "
        "The document carries no generation timestamp, so regenerating it without a "
        "metadata change produces byte-identical output and CI can diff it."
    )
    lines.append("")

    lines.append("## Provenance")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Framework | {_code_cell(metadata.get('framework'))} |")
    lines.append(f"| Benchmark | {_cell(metadata.get('benchmark'))} |")
    lines.append(f"| Benchmark version | {_code_cell(version)} |")
    lines.append(f"| Benchmark release date | {_cell(metadata.get('release_date'))} |")
    lines.append(f"| Platform | {_code_cell(metadata.get('platform'))} |")
    lines.append(f"| Upstream source | {_cell(metadata.get('source_url'))} |")
    lines.append(f"| Source metadata | `{source_rel}` |")
    lines.append(f"| Source metadata SHA-256 | `{digest}` |")
    lines.append(f"| Controls described | {total} |")
    lines.append("")
    lines.append(
        '"Controls described" counts the controls present in that metadata file, '
        "which may be a subset of the published benchmark."
    )
    lines.append("")

    lines.append("## Three questions this document keeps separate")
    lines.append("")
    lines.append(
        "Hand-written versions of this page blended three different facts into a "
        'single "manual" number. They answer different questions:'
    )
    lines.append("")
    lines.append("1. `automation_status` - what AutoAudit does with the control today.")
    lines.append(
        "2. `benchmark_audit_type` - how the published benchmark classifies the audit."
    )
    lines.append(
        "3. `is_manual` - whether the control has any programmatic source at all."
    )
    lines.append("")
    lines.append(
        f"For {version} the answers are {status_manual} "
        f"(`automation_status` == `manual`), {audit_manual} "
        f"(`benchmark_audit_type` == `Manual`) and {manual_true} "
        f'(`is_manual` == `true`). Quoting any one of them as "the manual count" '
        "misstates the other two."
    )
    lines.append("")
    lines.append(
        f"- `is_manual` true while `automation_status` is not `manual`: "
        f"{_controls(flagged_not_status)}."
    )
    lines.append(
        f"- `benchmark_audit_type` Manual while `automation_status` is not `manual`: "
        f"{_controls(audit_not_status)}."
    )
    lines.append(
        f"- `automation_status` manual while `benchmark_audit_type` is not Manual: "
        f"{_controls(status_not_audit)}."
    )
    lines.append("")

    lines.extend(
        _count_table(
            "### Implementation status (`automation_status`)",
            "Status",
            automation,
            _ordered_keys(automation, AUTOMATION_STATUS_ORDER),
            total,
            AUTOMATION_STATUS_MEANING,
        )
    )
    lines.extend(
        _count_table(
            "### Benchmark audit type (`benchmark_audit_type`)",
            "Audit type",
            audit_type,
            _ordered_keys(audit_type, []),
            total,
        )
    )
    lines.extend(
        _count_table(
            "### No programmatic source (`is_manual`)",
            "`is_manual`",
            manual_flag,
            _ordered_keys(manual_flag, [True, False]),
            total,
        )
    )

    lines.append("## Distribution")
    lines.append("")
    lines.extend(
        _count_table(
            "### Severity",
            "Severity",
            severity,
            _ordered_keys(severity, SEVERITY_ORDER),
            total,
        )
    )
    lines.extend(
        _count_table(
            f"### {level_header}",
            level_header,
            level,
            _ordered_keys(level, []),
            total,
        )
    )
    lines.extend(
        _count_table(
            "### Service",
            "Service",
            service,
            _ordered_keys(service, []),
            total,
        )
    )

    lines.append("## Controls")
    lines.append("")
    lines.append(
        "Sorted by control id numerically, so `1.1.10` follows `1.1.9` rather than "
        "`1.1.1`."
    )
    lines.append("")
    lines.append(
        f"| Control ID | Title | `automation_status` | `benchmark_audit_type` | "
        f"`is_manual` | Severity | Service | {level_header} | Policy file | "
        f"Data collector ID |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    ordered = sorted(
        controls, key=lambda control: _natural_key(str(control.get("control_id", "")))
    )
    for control in ordered:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(control.get("control_id")),
                    _cell(control.get("title")),
                    _code_cell(control.get("automation_status")),
                    _cell(control.get("benchmark_audit_type")),
                    _cell(_bool_or_none(control.get("is_manual"))),
                    _cell(control.get("severity")),
                    _cell(control.get("service")),
                    _cell(control.get(level_field)),
                    _code_cell(control.get("policy_file")),
                    _code_cell(control.get("data_collector_id")),
                ]
            )
            + " |"
        )
    lines.append("")

    annotated = [control for control in ordered if control.get("notes")]
    if annotated:
        lines.append("## Implementation notes")
        lines.append("")
        lines.append(
            f"{_controls(len(annotated))} carry a note in the metadata. The note is "
            "the reason the control sits at its current `automation_status`."
        )
        lines.append("")
        lines.append("| Control ID | Note |")
        lines.append("| --- | --- |")
        for control in annotated:
            lines.append(
                f"| {_cell(control.get('control_id'))} | {_cell(control.get('notes'))} |"
            )
        lines.append("")

    lines.append("## Changing this document")
    lines.append("")
    lines.append(f"1. Edit `{source_rel}`.")
    lines.append("2. Run `python tools/docs/generate_control_status.py`.")
    lines.append("3. Commit the metadata change and the regenerated document together.")
    lines.append("")
    lines.append(
        "CI runs `python tools/docs/generate_control_status.py --check` and fails if "
        "this file and its metadata disagree."
    )
    lines.append("")

    return "\n".join(lines)


def render_document(metadata_path: Path, root: Path = ROOT) -> str:
    """Read one metadata.json and return the complete document text."""
    raw = metadata_path.read_bytes()
    metadata = json.loads(raw.decode("utf-8"))
    source_rel = metadata_path.resolve().relative_to(root.resolve()).as_posix()
    digest = hashlib.sha256(raw).hexdigest()
    return render_markdown(metadata, source_rel, digest)


def discover_metadata_files(root: Path = ROOT) -> list[Path]:
    """Every benchmark metadata.json under engine/policies, in stable order."""
    return sorted((root / POLICIES_DIR).rglob("metadata.json"))


def document_path(metadata_path: Path, root: Path = ROOT) -> Path:
    """Mirror engine/policies/<...>/metadata.json into docs/engine/policies/<...>."""
    relative = metadata_path.resolve().relative_to(root.resolve()).parent
    return root / DOCS_DIR / relative / DOCUMENT_NAME


def orphan_documents(root: Path = ROOT) -> list[Path]:
    """Generated documents whose metadata no longer exists."""
    base = root / DOCS_DIR / POLICIES_DIR
    if not base.exists():
        return []
    generated = {
        document_path(metadata_path, root).resolve()
        for metadata_path in discover_metadata_files(root)
    }
    return sorted(
        path for path in base.rglob(DOCUMENT_NAME) if path.resolve() not in generated
    )


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def write_documents(root: Path = ROOT) -> list[tuple[Path, bool]]:
    """Write every document. Returns (path, changed) per benchmark."""
    results: list[tuple[Path, bool]] = []
    for metadata_path in discover_metadata_files(root):
        target = document_path(metadata_path, root)
        expected = render_document(metadata_path, root).encode("utf-8")
        current = target.read_bytes() if target.exists() else None
        if current != expected:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Bytes, not text: write_text would emit platform newlines.
            target.write_bytes(expected)
            results.append((target, True))
        else:
            results.append((target, False))
    return results


def check_documents(root: Path = ROOT, stream=None) -> int:
    """Diff generated output against the committed files. Returns drift count."""
    out = sys.stdout if stream is None else stream
    drifted = 0
    for metadata_path in discover_metadata_files(root):
        target = document_path(metadata_path, root)
        expected = render_document(metadata_path, root)
        current_bytes = target.read_bytes() if target.exists() else b""
        if current_bytes == expected.encode("utf-8"):
            continue
        drifted += 1
        relative = _relative(target, root)
        current = current_bytes.decode("utf-8", errors="replace")
        diff = "".join(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=f"{relative} (on disk)",
                tofile=f"{relative} (generated)",
            )
        )
        if not diff:
            # Same lines, different bytes: line endings or a missing final newline.
            diff = f"--- {relative} (on disk)\n+++ {relative} (generated)\n"
        if not diff.endswith("\n"):
            diff += "\n"
        out.write(diff)
    for orphan in orphan_documents(root):
        drifted += 1
        out.write(
            f"{_relative(orphan, root)}: no metadata.json generates this document.\n"
        )
    return drifted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate benchmark control status documents from policy metadata."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write. Diff the committed documents against metadata and "
        "exit non-zero on drift.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="Repository root to read metadata from and write documents into.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    metadata_files = discover_metadata_files(root)
    if not metadata_files:
        print(f"No metadata.json found under {root / POLICIES_DIR}", file=sys.stderr)
        return 1

    try:
        if args.check:
            drifted = check_documents(root)
        else:
            written = write_documents(root)
    except MetadataError as error:
        print(error, file=sys.stderr)
        return 1

    if args.check:
        if drifted:
            print(
                f"{drifted} control status document(s) disagree with metadata. "
                "Run: python tools/docs/generate_control_status.py",
                file=sys.stderr,
            )
            return 1
        print(f"{len(metadata_files)} control status document(s) match metadata.")
        return 0

    for target, changed in written:
        print(f"{'wrote' if changed else 'unchanged'} {_relative(target, root)}")
    for orphan in orphan_documents(root):
        print(
            f"orphan {_relative(orphan, root)}: no metadata.json generates this "
            "document; delete it.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
