"""The alert-metric gate, and the alert set it guards.

A gate that has never been shown to fail is not a gate. Most of this module
mutates a copy of the rule set and asserts the checker rejects it -- the same
shape as Phase 7's crosswalk mutation table.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ALERTS = ROOT / "infrastructure" / "monitoring" / "alerts"
CHECKER = ROOT / "tools" / "ci" / "check_alert_metrics.py"


def _load(monkeypatch, alerts_dir: Path | None = None, external: Path | None = None):
    """Import the checker fresh, optionally pointed at a mutated copy."""
    spec = importlib.util.spec_from_file_location(
        f"check_alert_metrics_{id(alerts_dir)}", CHECKER
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if alerts_dir is not None:
        monkeypatch.setattr(module, "ALERTS", alerts_dir)
    if external is not None:
        monkeypatch.setattr(module, "EXTERNAL", external)
    return module


def _copy_rules(tmp_path: Path) -> Path:
    target = tmp_path / "alerts"
    target.mkdir()
    for path in ALERTS.glob("*.yaml"):
        (target / path.name).write_text(path.read_text())
    return target


# ---------------------------------------------------------------------------
# The gate passes on the real rule set.
# ---------------------------------------------------------------------------


def test_every_alert_metric_resolves(monkeypatch):
    module = _load(monkeypatch)
    inventory, problems = module.analyse()
    assert problems == [], problems
    assert inventory["unresolved"] == {}
    # Both halves are real: the API emits some, the dispatcher emits others.
    sources = {entry["source"] for entry in inventory["emitted"].values()}
    assert "backend-api/app/core/metrics.py" in sources
    assert "engine/worker/metrics.py" in sources


def test_the_checker_exits_zero_on_the_real_rule_set(monkeypatch, capsys):
    module = _load(monkeypatch)
    assert module.main([]) == 0


# ---------------------------------------------------------------------------
# The gate fails when it should.
# ---------------------------------------------------------------------------


def test_an_alert_on_an_unemitted_metric_is_rejected(monkeypatch, tmp_path):
    """The exact defect Phase 10 found: eleven metrics nothing produced."""
    rules = _copy_rules(tmp_path)
    (rules / "invented.yaml").write_text(
        "groups:\n"
        "- name: invented\n"
        "  rules:\n"
        "  - alert: SomethingNobodyEmits\n"
        "    expr: |\n"
        "      increase(compliance_audit_failures_total[30m]) > 5\n"
    )
    module = _load(monkeypatch, alerts_dir=rules)
    _, problems = module.analyse()
    assert any("compliance_audit_failures_total" in p for p in problems), problems


def test_an_inline_expression_is_read_too(monkeypatch, tmp_path):
    """Both YAML forms in use must be parsed; a missed one is a silent bypass."""
    rules = _copy_rules(tmp_path)
    (rules / "inline.yaml").write_text(
        "groups:\n"
        "- name: inline\n"
        "  rules:\n"
        "  - alert: InlineForm\n"
        "    expr: made_up_series_total > 0\n"
    )
    module = _load(monkeypatch, alerts_dir=rules)
    _, problems = module.analyse()
    assert any("made_up_series_total" in p for p in problems), problems


def test_deleting_an_emitter_breaks_the_alert_that_reads_it(monkeypatch, tmp_path):
    """The gate has to bind in both directions, not just catch new alerts."""
    module = _load(monkeypatch)
    monkeypatch.setattr(module, "EMITTERS", ())
    _, problems = module.analyse()
    assert any("autoaudit_api_errors_total" in p for p in problems), problems


def test_a_stale_external_declaration_is_rejected(monkeypatch, tmp_path):
    """An unused external entry is how a retired metric name creeps back."""
    external = tmp_path / "external.json"
    payload = json.loads((ROOT / "tools" / "ci" / "external_metrics.json").read_text())
    payload["metrics"].append(
        {
            "metric": "nothing_references_this_total",
            "exporter": "imaginary_exporter",
            "note": "stale",
        }
    )
    external.write_text(json.dumps(payload))
    module = _load(monkeypatch, external=external)
    _, problems = module.analyse()
    assert any("nothing_references_this_total" in p for p in problems), problems


def test_histogram_bucket_suffix_resolves_to_the_declared_metric(monkeypatch):
    """`_bucket` is derived by Prometheus, not declared by the application."""
    module = _load(monkeypatch)
    assert "autoaudit_api_request_duration_seconds" in module.base_names(
        "autoaudit_api_request_duration_seconds_bucket"
    )
    inventory, _ = module.analyse()
    assert "autoaudit_api_request_duration_seconds_bucket" in inventory["emitted"]


@pytest.mark.parametrize(
    "expr,expected_absent",
    [
        ('rate(autoaudit_api_requests_total{route="/v1/scans"}[5m])', {"m", "route"}),
        ("sum by (le, route) (rate(x_total[5m]))", {"le", "route", "m"}),
        ('absent(foo_total{job="bar"})', {"job", "bar"}),
    ],
)
def test_promql_syntax_is_not_mistaken_for_metric_names(
    monkeypatch, tmp_path, expr, expected_absent
):
    """Durations, grouping labels and label values are not metrics.

    Every one of these produced a false positive before the extractor stripped
    them, and a checker that cries wolf gets disabled.
    """
    rules = tmp_path / "alerts"
    rules.mkdir()
    (rules / "probe.yaml").write_text(
        f"groups:\n- name: probe\n  rules:\n  - alert: Probe\n    expr: |\n      {expr}\n"
    )
    module = _load(monkeypatch, alerts_dir=rules)
    found = set(module.referenced_metrics())
    assert not (found & expected_absent), found & expected_absent


# ---------------------------------------------------------------------------
# The rule set's own invariants.
# ---------------------------------------------------------------------------


def _rule_text() -> str:
    return "\n".join(
        path.read_text()
        for path in sorted(ALERTS.glob("*.yaml"))
        if path.name != "alertmanager.yaml"
    )


def _alert_names() -> list[str]:
    import re

    return re.findall(r"alert:\s*(\S+)", _rule_text())


def test_no_alert_name_is_defined_twice():
    """`ScanEngineFailure` was defined in two files with conflicting severity.

    Prometheus permits it and Alertmanager grouped the two into separate
    notifications for one condition, with two runbook anchors giving
    contradictory advice.
    """
    names = _alert_names()
    duplicates = {name for name in names if names.count(name) > 1}
    assert duplicates == set(), duplicates


def test_every_alert_has_a_runbook_annotation():
    """CICDPipelineFailed and CICDPipelineDurationHigh had none."""
    import re

    for path in sorted(ALERTS.glob("*.yaml")):
        if path.name == "alertmanager.yaml":
            continue
        blocks = re.split(r"(?=^\s*-\s*alert:)", path.read_text(), flags=re.M)
        for block in blocks:
            match = re.search(r"alert:\s*(\S+)", block)
            if match:
                assert "runbook:" in block, f"{path.name}:{match.group(1)}"


def test_every_runbook_anchor_resolves():
    import re

    runbooks = (ALERTS / "runbooks" / "RUNBOOKS.md").read_text()
    anchors = {
        re.sub(r"[^a-z0-9]", "", heading.lower())
        for heading in re.findall(r"^## (.+)$", runbooks, re.M)
    }
    for target in re.findall(r'runbook:\s*"[^"#]*#([^"]+)"', _rule_text()):
        assert target in anchors, target


def test_every_runbook_section_belongs_to_a_live_alert():
    """Three runbooks described CI/CD alerts that did not exist."""
    import re

    runbooks = (ALERTS / "runbooks" / "RUNBOOKS.md").read_text()
    referenced = {
        target for target in re.findall(r'runbook:\s*"[^"#]*#([^"]+)"', _rule_text())
    }
    for heading in re.findall(r"^## (.+)$", runbooks, re.M):
        anchor = re.sub(r"[^a-z0-9]", "", heading.lower())
        assert anchor in referenced, heading


@pytest.mark.parametrize(
    "retired",
    [
        "FailedAuditChecks",
        "MissingControlsDetected",
        "SuspiciousPrivilegeEscalation",
        "UnauthorisedAccessAttempt",
        "CICDPipelineFailed",
        "CICDPipelineDurationHigh",
        "VulnerabilityScanFailure",
        "MissingComplianceScans",
        "ScanEngineFailure",
    ],
)
def test_retired_alerts_stay_retired(retired):
    """Each of these was removed for a reason recorded in RETIRED-ALERTS.md.

    Reinstating one means answering that reason, not re-adding the YAML.
    """
    assert retired not in _alert_names()
    assert retired in (ALERTS / "RETIRED-ALERTS.md").read_text()


def test_alertmanager_holds_no_inline_credential():
    """The old config carried a literal 'REPLACE_WITH_REAL_PASSWORD'."""
    config = (ALERTS / "alertmanager.yaml").read_text()
    assert "REPLACE_WITH_REAL_PASSWORD" not in config
    assert "pragma: allowlist secret" not in config


@pytest.mark.parametrize(
    "form,body,expected",
    [
        ("double-quoted", 'expr: "quoted_made_up_total > 0"', "quoted_made_up_total"),
        ("single-quoted", "expr: 'single_made_up_total > 0'", "single_made_up_total"),
        ("folded", "expr: >\n      folded_made_up_total > 0", "folded_made_up_total"),
        ("block", "expr: |\n      block_made_up_total > 0", "block_made_up_total"),
    ],
)
def test_every_yaml_expression_form_is_read(
    monkeypatch, tmp_path, form, body, expected
):
    """A missed expression is a silently bypassed gate.

    A double-quoted expr was erased entirely before the gate saw it: the literal
    stripper ran first and the whole expression is one quoted string, so the
    checker reported no metrics rather than an unresolved one. Found by the
    review pass.
    """
    rules = tmp_path / "alerts"
    rules.mkdir()
    (rules / "probe.yaml").write_text(
        f"groups:\n- name: probe\n  rules:\n  - alert: Probe\n    {body}\n"
    )
    module = _load(monkeypatch, alerts_dir=rules)
    assert expected in module.referenced_metrics(), form
