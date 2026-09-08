# Candidate policies

`MANIFEST_NAME = candidates.json`

This tree holds Rego that has been written and tested but is **not wired to any scan**. A
candidate policy is never loaded by the worker, never named by `metadata.json`, and never
contributes to a control's automation status. It exists so that the policy can be reviewed,
strict-checked and semantically tested *before* anything is promised to an auditor.

Today it holds the three Microsoft Purview / Security & Compliance controls whose collection path
(certificate-authenticated `Connect-IPPSSession`) has not yet been executed against a live tenant:
CIS 3.2.1, 3.2.2 and 3.3.1.

## Why this is a sibling of `cis/`, not a subdirectory of it

Every mechanism that discovers policy files walks down from a `metadata.json` with a
**non-recursive** glob:

- `engine/tests/test_wiring.py:124-132` `_all_rego_files()` uses `meta_path.parent.glob("*.rego")`,
  so `test_no_orphaned_rego_files` only ever sees the benchmark's own directory.
- `engine/worker/crosswalk.py:311` `policy_corpus_digest` uses `sorted(directory.glob("*.rego"))`,
  so the provenance digest of the executable corpus is unchanged by anything in here.

The parents themselves are found with `POLICIES_DIR.rglob("metadata.json")`
(`test_wiring.py:65-71`, and `tools/docs/generate_control_status.py:443` for the docs gate), which
**is** recursive. That is the structural rule for this tree:

> **There must never be a `metadata.json` anywhere under `engine/policies/candidate/`.**

A `metadata.json` here would make this directory a benchmark version directory, pull these files
into `test_no_orphaned_rego_files`, and generate a phantom controls document. The manifest is
called `candidates.json` for exactly that reason, and
`engine/tests/test_phase8_candidate_manifest.py::test_no_metadata_json_in_candidate_tree` fails if
one ever appears.

Placing the files *inside* `engine/policies/cis/microsoft-365-foundations/v6.0.0/` would instead
have made them orphaned .rego files and changed the pinned corpus digest and the pinned file count
of 69.

## What does cover these files

`opa check --strict engine/policies` and `opa test engine/policies engine/tests` both take the whole
`engine/policies` tree, so candidate policies get full strict checking and full semantic and
never-pass property testing (`engine/tests/test_phase8_candidate_*.rego`) while remaining
unreachable by any scan. That is deliberate: unreviewable dead code would be worse than no code.

`engine/tests/test_phase8_candidate_manifest.py` additionally pins the package names to the names
they must have *after* promotion, so promotion is a byte-identical `git mv` with no edit to the
Rego itself.

## Promotion

Promotion is performed **only** by `tools/policies/promote_candidate.py`. Do not hand-move a file.
The tool refuses `--apply` unless every blocking gate recorded for that candidate in
`candidates.json` is resolved **and** `--live-validation-evidence <path>` names an existing file.

`candidates.json` records, per candidate: the collector and permissions it will declare, the
automation status it will be given, whether it can ever return `compliant: true`, the procedure
source (including the fact that the extract in `docs/engine/Framework/CIS_M365_Benchmarks.json`
self-declares edition `v6.0.1 - 2-26-2026` while the licensed v6.0.0 procedure has not been
obtained), and the named, currently unresolved gates that block promotion.
