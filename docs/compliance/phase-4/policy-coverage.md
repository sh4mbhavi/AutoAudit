# Phase 4 policy semantic coverage

Engineering implementation for review; GRC and release acceptance remain pending.
No earlier worktree was changed and no commit, push, merge or tenant operation was performed.

## Coverage and executable oracle

All **44 Appendix B controls** have direct Rego assertions against their public
`result` decision. The new suite contains **346 semantic cases**: pass, fail,
missing, malformed, partial, boundary and collector-error cases for each control,
plus 38 targeted regressions. Assertions require the exact boolean/null outcome
and a typed result/message; undefined decisions, runtime conflicts and omitted
cases cannot count as success.

- `engine/tests/test_crosswalk_semantics.rego`: self-contained direct cases; the
  ordinary `opa test engine/policies engine/tests` command discovers every case.
- `engine/tests/fixtures/crosswalk_semantics.json`: machine-readable, fixed input
  and expected-output oracle with exact policy/collector resolution and boundary
  rationale. Tests do not derive expected decisions from the implementation.
- `engine/tests/test_crosswalk_semantic_coverage.py`: **133 Python tests** verify
  the exact 44-control inventory, metadata wiring, matching literal Rego
  assertions, execution of every case by real OPA, and **44 real collector to
  captured-policy evaluations** across all 30 collectors. These use synthetic
  Graph/PowerShell transport responses and the actual normalized collector
  outputs. The single-admin/public-group fixtures intentionally fail their
  controls; the remaining complete fixtures pass. OPA is mandatory, never a skip.

The direct tests include valid records mixed with incomplete objects, nested
collector errors, fractional/impossible/inconsistent counts, both endpoints of
the two-to-four admin interval, the 350/351 anti-phishing target limit, both sides
of attachment coverage, disabled enforcement rules, missing and duplicate audit
actions, and empty mailbox populations. Empty policy populations can fail when a
successful complete collection proves required configuration absent; an empty
population that cannot establish applicability remains indeterminate.

## Changes exposed by failing tests

The first new executable suite had 156 failures and three evaluation conflicts
before implementation changes. Additional targeted tests reproduced defects
before their fixes. The five Phase 2 hardened crosswalk policies are preserved;
39 other v6 policy modules now require typed, complete evidence and reject
collector-error envelopes before issuing an assessed result. Each guard remains
inside its policy source so the Phase 3 captured-source evaluator needs no
unrecorded shared library.

Deterministic corrections include:

- 2.1.2: disjoint true/false/null branches avoid an evaluation conflict.
- 2.1.3: default-policy fallback no longer overlaps the empty-list branch;
  notification destinations must have the expected string type.
- 2.1.4: missing built-in configuration has a defined failed result after a
  successful policy-list collection; missing properties remain indeterminate.
- 2.1.6: monitoring branches no longer conflict; recipients require arrays and
  blank recipients cannot satisfy enabled notifications.
- 2.1.7: the previously inverted noncompliance branch no longer passes a
  misconfigured policy; missing assignments and malformed targets cannot pass.
- 1.1.3, 5.3.1, 5.3.2, 6.1.3 and 6.2.1: inconsistent population/summary evidence
  cannot produce a pass. MFA population counts reject impossible/fractional data.
- 6.1.2: empty and incomplete mailbox evidence returns null while the existing
  expected action sets remain unchanged.
- 5.1.6.1: missing/inconsistent partner/default-access evidence returns null while
  the existing valid-input heuristic remains unchanged.
- The v4 legacy-auth policy replaces two unused argument names with `_`, allowing
  `opa check --strict engine/policies` to check the complete policy corpus.

PR #345 was inspected locally. Its meaningful global-admin cardinality cases
(two/three/four passing, zero/one/five failing) informed the new tests. Its cases
that accepted an empty/missing admin list alongside a claimed valid count were
not adopted: those now assert indeterminate. No PR was merged or represented as
GRC approval.

## Verification

Run from this worktree:

```sh
export OPA_BINARY=/tmp/autoaudit-phase-2-tools/opa
"$OPA_BINARY" check --strict engine/policies
"$OPA_BINARY" test engine/policies engine/tests
uv run --project engine --extra dev pytest engine/tests/test_crosswalk_semantic_coverage.py -q
uv run --project engine --extra dev ruff check engine/tests/test_crosswalk_semantic_coverage.py
git diff --check
```

Verified with OPA **1.20.2**: whole-corpus strict check passed; **550/550 OPA
cases passed** (204 inherited plus 346 new); **133/133 crosswalk Python tests
passed**; scoped Ruff and whitespace checks passed. The inherited Pydantic
class-config deprecation warning remains. The main Phase 4 handoff records the
final full-engine/backend/frontend counts after all concurrent edits stabilize.
A fresh local full engine run without a database URL passed **1,053 tests** with
13 skips (12 database-dependent plus the inherited skip); the parent run with
the disposable database passed **1,065 tests** with the one inherited skip.

## Independent review and remaining limits

Reciprocal policy/collector review checked contract and plan requirements before
code quality. It found incomplete group and transport records could disappear
while filtering, plus collector error envelopes that could be discarded. The
collector owner added regressions and rejects those inputs before returning a
safe-looking empty population. Review also enriched successful transport
fixtures and led to the 44 real collector-to-OPA checks above. Final review also tightened malformed transport states/SCL values and error-bearing
Graph list records. Reciprocal review reported no remaining actionable policy or
collector findings in this scope. GRC acceptance remains separate.

Semantic coverage is executable evidence of the repository's current control
interpretations, not independent validation against the licensed CIS benchmark.
D03 mailbox applicability and D09 collaboration-source/mapping decisions remain
open. In particular, 5.1.6.1 still uses partner/default-inbound configuration as
its prior heuristic, and 6.1.2 retains its prior expected audit-action sets.
Other existing criteria (such as any qualifying Safe Links policy, role-query
classification and number-matching-only fatigue protection) are tested as
implemented; this phase does not certify their complete benchmark interpretation.
No live Microsoft tenant or actual PowerShell service was used. Newly incomplete
responses can now be indeterminate/error and therefore reduce automated coverage
instead of producing false confidence.

## Per-control direct case inventory

| Control | Direct cases | Boundary or retained interpretation |
|---|---:|---|
| 1.1.1 | 8 | An empty administrator population provides no evidence. |
| 1.1.3 | 12 | Both endpoints of the permitted two-to-four range pass. |
| 1.1.4 | 8 | An empty administrator population provides no evidence. |
| 1.2.1 | 8 | Private groups do not violate the public-group check. |
| 1.3.1 | 8 | Only the exact never-expire sentinel passes. |
| 1.3.4 | 8 | Both modern settings must be disabled. |
| 2.1.1 | 8 | A successfully collected empty policy population is a failed configuration. |
| 2.1.2 | 7 | The raw default-policy fallback is supported. |
| 2.1.3 | 10 | Enabled notifications still need a destination. |
| 2.1.4 | 9 | Enabled monitoring does not satisfy blocking. |
| 2.1.5 | 7 | Allowing unsafe documents independently violates the control. |
| 2.1.6 | 8 | Enabled notifications without recipients fail. |
| 2.1.7 | 12 | The existing 350-target maximum is inclusive. |
| 2.1.11 | 8 | Coverage rounds up to the first whole extension count meeting 90 percent. |
| 2.4.4 | 7 | The raw policy fallback is supported. |
| 4.2 | 7 | No restriction configurations cannot block personal enrollment. |
| 5.1.2.2 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 5.1.5.1 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 5.1.5.2 | 7 | Current control checks workflow enablement; reviewer requirements need benchmark interpretation. |
| 5.1.6.1 | 8 | Preserves the existing partner/default-inbound heuristic; D09 mapping remains open. |
| 5.1.6.2 | 7 | Both limited and restricted guest roles satisfy the existing interpretation. |
| 5.1.6.3 | 7 | Allowing all members to invite fails. |
| 5.2.2.3 | 8 | Report-only policies do not enforce blocking. |
| 5.2.3.1 | 7 | Preserves current number-matching criterion; additional context does not change it. |
| 5.2.3.2 | 7 | Current benchmark mapping assesses enablement; list content is descriptive. |
| 5.2.3.3 | 7 | Preserves current on-premises enablement criterion. |
| 5.2.3.4 | 9 | An empty user population is not evidence that all members are MFA capable. |
| 5.2.3.5 | 7 | Either weak authentication method independently fails. |
| 5.2.3.6 | 7 | A default value is not explicit enabled evidence. |
| 5.2.3.7 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 5.3.1 | 8 | More than one role policy still establishes the existing PIM-presence check. |
| 5.3.2 | 8 | Unrelated non-guest reviews do not negate an existing guest review. |
| 5.3.3 | 7 | A successfully collected empty review population fails. |
| 5.3.4 | 7 | The activation-duration setting is independent of required approval. |
| 5.3.5 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 6.1.1 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 6.1.2 | 11 | Empty mailbox populations are indeterminate; existing action sets and D03 applicability remain unchanged. |
| 6.1.3 | 8 | An explicit null setting is unknown, including when false is the secure value. |
| 6.2.1 | 9 | Disabled forwarding rules do not forward mail. |
| 6.2.2 | 9 | Disabled whitelist rules do not bypass spam checks. |
| 6.2.3 | 7 | Preserves enablement criterion; exceptions remain visible in policy details. |
| 6.5.1 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 6.5.4 | 7 | An explicit null setting is unknown, including when false is the secure value. |
| 6.5.5 | 7 | An explicit null setting is unknown, including when false is the secure value. |
