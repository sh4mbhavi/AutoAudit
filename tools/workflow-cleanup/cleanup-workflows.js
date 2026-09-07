// Delete workflow runs older than the configured retention period.
//
// Phase 10 rewrote the selection rule. The previous version:
//
//   * never read RETENTION_DAYS, even though ops.workflow-cleanup.yml exports it
//     and documents it as "Delete runs older than this many days";
//   * decided by run DURATION instead -- under 10s delete, 10s to 2min delete,
//     2min or more keep -- so fast-passing gates were deleted regardless of age
//     while slow ones were kept forever;
//   * read only the newest 20 runs with no pagination, so it could never see the
//     old runs it was supposed to be deleting;
//   * caught its own errors and returned without a non-zero exit, so a failed
//     cleanup was indistinguishable from a successful one.
//
// The consequence for this program specifically: CI workflow-run history could
// not be cited as retained SOC 2 evidence, because what was retained was
// decided by how long a job happened to take.

import { Octokit } from "@octokit/rest";

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = process.env.REPO_OWNER;
const REPO_NAME = process.env.REPO_NAME;
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS ?? "90");

const args = process.argv.slice(2);
const isDryRun = args.includes("--dryRun=true");

if (!GITHUB_TOKEN || !REPO_OWNER || !REPO_NAME) {
  console.error("Missing environment variables (GITHUB_TOKEN, REPO_OWNER, REPO_NAME)");
  process.exit(1);
}

if (!Number.isFinite(RETENTION_DAYS) || RETENTION_DAYS < 1) {
  // Fail rather than fall back to a default. A malformed retention value that
  // silently became "delete everything" is exactly the failure worth refusing.
  console.error(`RETENTION_DAYS must be a positive number; got ${process.env.RETENTION_DAYS}`);
  process.exit(1);
}

const octokit = new Octokit({ auth: GITHUB_TOKEN });

async function cleanupWorkflows() {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);
  console.log(
    `Checking workflow runs for ${REPO_OWNER}/${REPO_NAME}; ` +
      `retention ${RETENTION_DAYS} day(s), cutoff ${cutoff.toISOString()}`
  );

  let examined = 0;
  let deleted = 0;
  let kept = 0;
  let failed = 0;

  // Paginate FIRST, collect, and only then delete.
  //
  // Deleting during pagination is the subtle bug: the API pages by offset, so
  // removing a run shifts every later run one position earlier and the next
  // page request skips the ones that moved across the boundary. Roughly half
  // the eligible runs survive a sweep that reports success. Collecting the full
  // list before mutating anything avoids it entirely.
  const runs = octokit.paginate.iterator(octokit.actions.listWorkflowRunsForRepo, {
    owner: REPO_OWNER,
    repo: REPO_NAME,
    per_page: 100,
  });

  const doomed = [];
  for await (const { data } of runs) {
    for (const run of data) {
      examined += 1;
      // created_at, not run duration: age is what a retention period means.
      if (new Date(run.created_at) < cutoff) {
        doomed.push(run);
      } else {
        kept += 1;
      }
    }
  }

  for (const run of doomed) {
    if (isDryRun) {
      console.log(`would delete run #${run.id} (${run.name}, created ${run.created_at})`);
      deleted += 1;
      continue;
    }
    try {
      await octokit.actions.deleteWorkflowRun({
        owner: REPO_OWNER,
        repo: REPO_NAME,
        run_id: run.id,
      });
      deleted += 1;
      console.log(`deleted run #${run.id} (${run.name}, created ${run.created_at})`);
    } catch (err) {
      // Record and continue: one undeletable run must not abandon the sweep,
      // but it must still make the job fail so the gap is visible.
      failed += 1;
      console.error(`failed to delete run #${run.id}: ${err.message}`);
    }
  }

  console.log(
    `examined ${examined}, ${isDryRun ? "would delete" : "deleted"} ${deleted}, ` +
      `kept ${kept}, failed ${failed}`
  );

  if (failed > 0) {
    // A silent partial failure was how this could report success while retaining
    // nothing it claimed to.
    process.exitCode = 1;
  }
}

cleanupWorkflows().catch((err) => {
  console.error(`cleanup failed: ${err.message}`);
  process.exitCode = 1;
});
