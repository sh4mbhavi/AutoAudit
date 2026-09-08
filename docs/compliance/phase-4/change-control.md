# Required checks and scanner operations

This is a maintainer handoff, not an applied repository configuration.

The public branch API reported `main` protected on 2026-09-05. Reading its exact
protection settings returned HTTP 401; the public ruleset list was empty. A
protected flag alone does not prove which checks/reviews are required or whether
administrators can bypass them. No settings were changed in this session.

## Proposed merge requirements

After a reviewed Phase 1–4 stack is committed, rebased onto current main, pushed,
and all hosted workflows are green, an authorized repository maintainer should
review [branch-protection-proposal.json](branch-protection-proposal.json). It is a
**desired minimum**, not a command to replace existing protection. Export and
preserve current settings and additional required checks before combining them.

Require these real jobs (not `Report PR status` comment jobs):

- `Engine tests and policy semantics`
- `Backend tests and migrations`
- `Frontend typecheck tests and build`
- `Linting frontend`
- `API and worker container startup`
- `Scan dependencies for vulnerabilities`
- `secret-examples`

All these workflows trigger on every pull request targeting main and every push
to main. Removing their path restrictions ensures root configuration, Compose,
security, schema and workflow edits cannot omit a required check. The engine and
backend jobs require actual disposable PostgreSQL and pinned OPA. Missing
integration prerequisites are an error, not a skip.

The proposed minimum is one approving reviewer, required CODEOWNERS review,
stale-review dismissal after new commits, up-to-date required checks, resolved
conversations, no ordinary administrator bypass, no force pushes and no branch
deletion. The existing `@Hardhat-Enterprises/autoaudit-reviewers` team remains the
owner; explicit policy, collector, security, migration, workflow and CI-tool paths
make the scope visible. Confirm team write access and staffing before activation.
The repository owner may require more reviewers; engineering has not authorized
a new team or relaxed any existing rule.

Record the hosted check-run URLs and settings export. Then use a maintainer-owned
synthetic PR containing a deliberately failing test to verify the normal merge
path is blocked. Restore the test and verify green checks plus fresh required
reviews allow the normal path. No deliberately failing PR was opened here.

GitHub documents unique job names, review settings, stale-review dismissal and
administrator enforcement in [About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

## Grype threshold, suppressions and emergencies

Reuse merged PR #326's **critical** threshold; do not silently raise it or set
`fail-build: false`. Grype 0.118.0 is explicit. The vulnerability database updates
normally so newly disclosed issues are detected. A scanner execution or database
error also fails the scan. SARIF upload runs after scanning and does not convert
a failed scanner result to success. The required check is the scanner job itself.
No suppression was added in this patch.

For a proposed false-positive suppression, the security owner must review an
issue documenting the exact vulnerability identifier, package name/version,
source/image, evidence supporting non-applicability, reviewer, expiry date and
remediation owner. Add a narrowly scoped Grype ignore rule or supported VEX
statement through a reviewed PR, retain the unsuppressed report in restricted
security records, and confirm unrelated critical canaries still fail. Never
blanket-ignore a severity, ecosystem, directory, or all findings for a package.
Remove expired exceptions through a follow-up PR and rerun the scan. Do not
commit credential-bearing scanner reports or raw tenant evidence.

For an urgent operational incident, prefer reverting the offending dependency or
shipping the last verified artifact. An emergency exception requires the
repository/platform owner and security owner to record the incident, justification,
exact commit/artifact, time limit, rollback path and retrospective review. If a
platform override is necessary, those owners perform and record it; this patch
provides no bypass switch and does not disable checks or protection. The ordinary
merge path must continue to require its checks. Restore any time-limited owner
change immediately and retain the platform audit event.

See the [Anchore scan action](https://github.com/anchore/scan-action) for threshold,
version and report options, and [Grype filtering](https://oss.anchore.com/docs/guides/vulnerability/filter-results/) for supported exception mechanisms.
