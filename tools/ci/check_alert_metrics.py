"""Fail the build when an alert rule references a metric nothing produces.

This is the gate that Phase 10 exists to install. Before it, every one of the
six alert-rule files in ``infrastructure/monitoring/alerts/`` referenced metric
names that appeared nowhere else in the repository -- eleven of them -- so the
whole directory was, in the plan's words, "conceptual monitoring YAML" being
treated as proof that monitoring operates.

A metric named by an alert must be one of two things:

**Emitted.** Declared in ``backend-api/app/core/metrics.py`` or
``engine/worker/metrics.py``. Those declarations are read out of the source, so
deleting an emitter breaks the alert that reads it, in CI, immediately.

**External.** Declared in ``tools/ci/external_metrics.json`` with the exporter
that provides it and a note on what has to be deployed for it to exist. That
file is the honest inventory of what the monitoring stack depends on and does
not itself supply.

Anything else fails. Running it with no arguments IS the gate: it exits non-zero
on any unresolved metric and prints a one-line summary otherwise. Pass
``--show`` to print the resolved inventory as JSON.

The check is deliberately syntactic. It does not evaluate PromQL, and it cannot
tell whether a threshold is sensible -- only whether the series can exist at all.
That is the failure mode that was actually present.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALERTS = ROOT / "infrastructure" / "monitoring" / "alerts"
EXTERNAL = Path(__file__).resolve().parent / "external_metrics.json"

EMITTERS = (
    ROOT / "backend-api" / "app" / "core" / "metrics.py",
    ROOT / "engine" / "worker" / "metrics.py",
)

# PromQL function and keyword names that appear where a metric name would.
RESERVED = {
    "abs",
    "absent",
    "absent_over_time",
    "avg",
    "avg_over_time",
    "bool",
    "by",
    "ceil",
    "changes",
    "clamp",
    "clamp_max",
    "clamp_min",
    "count",
    "count_over_time",
    "count_values",
    "day_of_month",
    "day_of_week",
    "day_of_year",
    "days_in_month",
    "delta",
    "deriv",
    "exp",
    "floor",
    "group",
    "group_left",
    "group_right",
    "histogram_quantile",
    "hour",
    "idelta",
    "ignoring",
    "increase",
    "irate",
    "label_join",
    "label_replace",
    "last_over_time",
    "ln",
    "log2",
    "log10",
    "max",
    "max_over_time",
    "min",
    "min_over_time",
    "minute",
    "month",
    "offset",
    "on",
    "predict_linear",
    "present_over_time",
    "quantile",
    "quantile_over_time",
    "rate",
    "resets",
    "round",
    "scalar",
    "sgn",
    "sort",
    "sort_desc",
    "sqrt",
    "stddev",
    "stddev_over_time",
    "stdvar",
    "sum",
    "sum_over_time",
    "time",
    "timestamp",
    "topk",
    "bottomk",
    "unless",
    "vector",
    "without",
    "year",
    "and",
    "or",
    "le",
    "inf",
    "nan",
}

# Suffixes Prometheus derives from a single declared metric.
DERIVED_SUFFIXES = ("_bucket", "_sum", "_count", "_total", "_created")

_METRIC = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DECLARED = re.compile(
    r'^\s*(?:\w+\s*=\s*)?(?:Counter|Gauge|Histogram|Summary|Info|Enum)\(\s*\n?\s*"([a-z_][a-z0-9_]*)"',
    re.M,
)


def declared_metrics() -> dict[str, str]:
    """Metric names declared by the application, mapped to the file declaring them."""
    found: dict[str, str] = {}
    for path in EMITTERS:
        if not path.exists():
            continue
        for name in _DECLARED.findall(path.read_text()):
            found[name] = str(path.relative_to(ROOT))
    return found


def external_metrics() -> dict[str, dict]:
    payload = json.loads(EXTERNAL.read_text())
    return {entry["metric"]: entry for entry in payload["metrics"]}


def _expressions(path: Path):
    """Every (alert name, expr) in a rule file.

    Deliberately not YAML: neither project environment installs PyYAML, and
    adding a dependency to both locked environments to run one CI check is a
    worse trade than reading the two constructs these files actually use --
    ``expr: <inline>`` and ``expr: |`` followed by an indented block.

    ``promtool check rules`` in ci.validate-alerts.yml is what proves the files
    are valid YAML and valid PromQL; this function only has to find the
    expressions inside files that have already been proven well-formed.
    Anything it cannot parse is reported, never skipped.

    Rule entries are located by their list-item boundary rather than by reading
    ``alert:`` first and ``expr:`` after it. YAML mapping keys have no required
    order, so a rule written

        - expr: made_up_total > 0
          alert: SomethingFired

    used to have its expression dropped entirely: the previous implementation
    only yielded an ``expr:`` once it had already seen an ``alert:``, and it
    never reset the name between entries, so an expression could also be
    attributed to the previous rule. Either way the metric went unchecked.
    An entry with an expression and no name is still yielded, under a
    placeholder, because the expression is the part this gate exists to read.
    """
    lines = path.read_text().splitlines()
    entries: list[dict] = []
    current: dict | None = None
    index = 0
    while index < len(lines):
        line = lines[index]

        # A new list item ends the previous rule entry, whatever it contained.
        item = re.match(r"(\s*)-\s+(\S.*)$", line)
        if item:
            if current is not None:
                entries.append(current)
            current = {"name": None, "expr": None}
            # Re-read the remainder of the line as an ordinary mapping key at
            # the item's key indent, so `- alert: X` and `- expr: |` both work.
            line = item.group(1) + "  " + item.group(2)

        if current is None:
            index += 1
            continue

        name = re.match(r"\s*(?:alert|record):\s*(\S.*)$", line)
        if name:
            current["name"] = name.group(1).strip().strip("\"'")
            index += 1
            continue

        expr = re.match(r"(\s*)expr:\s*(.*)$", line)
        if expr:
            indent, inline = expr.group(1), expr.group(2).strip()
            if inline and inline not in {"|", ">", "|-", ">-"}:
                # A quoted scalar IS the expression; the quotes are YAML, not
                # PromQL. Leaving them on made the whole expression look like a
                # string literal to the stripper below, which erased it.
                if len(inline) >= 2 and inline[0] == inline[-1] and inline[0] in "\"'":
                    inline = inline[1:-1]
                current["expr"] = inline
                index += 1
                continue
            # Block scalar: consume every line indented past the `expr:` key.
            block: list[str] = []
            index += 1
            while index < len(lines):
                following = lines[index]
                if following.strip() and not following.startswith(indent + " "):
                    break
                block.append(following)
                index += 1
            current["expr"] = "\n".join(block)
            continue

        index += 1

    if current is not None:
        entries.append(current)

    for entry in entries:
        if entry["expr"] is None:
            continue
        yield entry["name"] or f"<unnamed rule in {path.name}>", entry["expr"]


def referenced_metrics() -> dict[str, list[tuple[str, str]]]:
    """Metric name -> [(rule file, alert name)] across every rule file."""
    references: dict[str, list[tuple[str, str]]] = {}
    for path in sorted(ALERTS.glob("*.yaml")):
        if path.name == "alertmanager.yaml":
            continue
        for alert, expr in _expressions(path):
            # Strip everything that is syntactically not a metric name before
            # tokenising. Each of these produced a false positive on the real
            # rule set: a label matcher's VALUE, a range duration's unit letter
            # ("5m" tokenises to "m"), and an aggregation's grouping labels are
            # all bare words in metric position.
            #
            # ORDER MATTERS, and getting it wrong was a silent gate bypass.
            # Label matchers are stripped FIRST, because stripping string
            # literals first would eat the entire expression of a rule written
            # as `expr: "made_up_total > 0"` -- the whole thing is one quoted
            # string -- and the gate would report no metrics at all rather than
            # an unresolved one. Found by the review pass.
            stripped = re.sub(r"\{[^}]*\}", " ", expr)  # label matchers
            stripped = re.sub(r"'[^']*'", " ", stripped)  # remaining literals
            stripped = re.sub(r"\[[^\]]*\]", " ", stripped)  # range durations
            stripped = re.sub(
                r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
                " ",
                stripped,
            )  # grouping labels
            stripped = re.sub(r"\boffset\s+\S+", " ", stripped)
            for token in _METRIC.findall(stripped):
                if token in RESERVED or token.isdigit():
                    continue
                references.setdefault(token, []).append((path.name, alert))
    return references


def base_names(name: str) -> list[str]:
    """A metric name plus the declared name it could be derived from."""
    candidates = [name]
    for suffix in DERIVED_SUFFIXES:
        if name.endswith(suffix):
            candidates.append(name[: -len(suffix)])
    return candidates


def analyse() -> tuple[dict, list[str]]:
    emitted = declared_metrics()
    external = external_metrics()
    references = referenced_metrics()

    problems: list[str] = []
    inventory = {"emitted": {}, "external": {}, "unresolved": {}}

    for metric, users in sorted(references.items()):
        resolved = None
        for candidate in base_names(metric):
            if candidate in emitted:
                resolved = ("emitted", emitted[candidate])
                break
            if candidate in external:
                resolved = ("external", external[candidate]["exporter"])
                break
        where = sorted({f"{f}:{a}" for f, a in users})
        if resolved is None:
            inventory["unresolved"][metric] = where
            problems.append(
                f"{metric} is referenced by {', '.join(where)} but is neither "
                f"declared in an emitter nor listed in {EXTERNAL.name}"
            )
        else:
            inventory[resolved[0]][metric] = {"source": resolved[1], "used_by": where}

    # The reverse direction: an external declaration nothing uses is stale, and a
    # stale entry is exactly how a metric name sneaks back in unnoticed.
    for metric in sorted(external):
        if not any(metric in base_names(name) for name in references):
            problems.append(
                f"{metric} is declared external in {EXTERNAL.name} but no alert "
                f"references it; remove the declaration"
            )
    return inventory, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--show", action="store_true", help="print the resolved inventory"
    )
    args = parser.parse_args(argv)

    inventory, problems = analyse()

    if args.show:
        print(json.dumps(inventory, indent=2, sort_keys=True))

    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        return 1

    print(
        f"{len(inventory['emitted'])} alert metric(s) emitted by the application, "
        f"{len(inventory['external'])} declared external."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
