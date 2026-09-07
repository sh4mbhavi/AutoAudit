"""Read-only Phase 0 structural snapshot; run from the repository root.

uv run --project engine --extra dev python docs/compliance/phase-0/verify_baseline.py
This validates repository wiring, not policy semantics or SOC 2 compliance.
"""

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "engine"))
from collectors.registry import DATA_COLLECTORS  # noqa: E402


def digest(value):
    return hashlib.sha256(value).hexdigest()


plan_path = ROOT / "docs/compliance/SOC2_EXECUTION_PLAN.md"
plan = plan_path.read_text()
appendix_a = plan.split("## Appendix A —", 1)[1].split("## Appendix B —", 1)[0]
appendix_b = plan.split("## Appendix B —", 1)[1].split("## Appendix C —", 1)[0]
rows = re.findall(r"^\| ([\d.]+) \| `([^`]+)` \| `([^`]+)` \|$", appendix_b, re.M)
assert len(rows) == 44 and len({r[0] for r in rows}) == 44, "Appendix B inventory drift"
version_dir = ROOT / "engine/policies/cis/microsoft-365-foundations/v6.0.0"
metadata_path = version_dir / "metadata.json"
metadata = json.loads(metadata_path.read_text())
assert metadata["version"] == "v6.0.0"
controls = metadata["controls"]
assert len({c["control_id"] for c in controls}) == len(controls), "Duplicate control IDs"
by_id = {c["control_id"]: c for c in controls}
registry_path = ROOT / "engine/collectors/registry.py"
tree = ast.parse(registry_path.read_text())
registry_dicts = [n.value for n in tree.body if isinstance(n, ast.AnnAssign)
                  and isinstance(n.target, ast.Name) and n.target.id == "DATA_COLLECTORS"]
assert len(registry_dicts) == 1 and isinstance(registry_dicts[0], ast.Dict)
registry_keys = [ast.literal_eval(k) for k in registry_dicts[0].keys]
assert len(registry_keys) == len(set(registry_keys)), "Duplicate registry keys"
resolution = []
for control_id, policy_file, collector_id in rows:
    control = by_id[control_id]
    assert control["automation_status"] == "ready", control_id
    assert control["policy_file"] == policy_file, control_id
    assert control["data_collector_id"] == collector_id, control_id
    assert registry_keys.count(collector_id) == 1 and collector_id in DATA_COLLECTORS, control_id
    policy_path = version_dir / policy_file
    policy = policy_path.read_text()
    expected_package = "cis.microsoft_365_foundations.v6_0_0.control_" + control_id.replace(".", "_")
    assert re.findall(r"^package\s+(\S+)", policy, re.M) == [expected_package], control_id
    collector = DATA_COLLECTORS[collector_id]
    resolution.append({"control_id": control_id, "policy_file": policy_file,
                       "policy_sha256": digest(policy_path.read_bytes()),
                       "collector_id": collector_id,
                       "collector_class": collector.__module__ + "." + collector.__name__})
ratings = Counter()
explicit_ids = set()
for line in appendix_a.splitlines():
    if not re.match(r"^\| CC[67]\.\d+ \|", line):
        continue
    cells = [c.strip() for c in line.split("|")[1:-1]]
    assert cells[2] in {"Yes", "Partial", "No"}
    ratings[cells[2]] += 1
    explicit_ids.update(re.findall(r"\b\d+(?:\.\d+)+\b", cells[3]))
assert explicit_ids == {r[0] for r in rows}, "Appendix A/B explicit control mismatch"
assert sum(ratings.values()) == 47, "Appendix A row count drift"
source_paths = [
    "README.md", "backend-api/README.md", "engine/collectors/README.md",
    "engine/policies/README.md", "docs/engine/sharepoint-control-development.md",
    "docs/engine/sharepoint-local-runtime.md", "docs/engine/manual-collector-testing.md",
    "docs/features/pre-scan/prescan-readiness.md", "docs/DevSecOps/workflow-documentation.md",
    "docs/compliance/manual_control_classification.md",
    "docs/compliance/Risk_Impact_Prioritisation_Matrix.md",
    "docs/engine/Framework/CIS_M365_Benchmarks.json",
]
ready = [c for c in controls if c["automation_status"] == "ready"]
snapshot = {
    "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "upstream_main": subprocess.check_output(["git", "rev-parse", "upstream/main"], cwd=ROOT, text=True).strip(),
    "metadata_sha256": digest(metadata_path.read_bytes()),
    "registry_sha256": digest(registry_path.read_bytes()),
    "appendix_a_sha256": digest(appendix_a.encode()),
    "appendix_b_sha256": digest(appendix_b.encode()),
    "metadata_total": len(controls),
    "status_totals": dict(sorted(Counter(c["automation_status"] for c in controls).items())),
    "ready_unique_collectors": len({c["data_collector_id"] for c in ready}),
    "explicit_crosswalk_controls": len(rows),
    "explicit_crosswalk_unique_collectors": len({r[2] for r in rows}),
    "ratings": dict(sorted(ratings.items())),
    "benchmark_extract_version": json.loads((ROOT / source_paths[-1]).read_text())["document_version"],
    "source_sha256": {p: digest((ROOT / p).read_bytes()) for p in source_paths},
    "resolution": resolution,
}
print(json.dumps(snapshot, indent=2))
