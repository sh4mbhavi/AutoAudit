# AutoAudit Runbooks

One section per alert. `tools/tests/test_phase10_alert_metrics.py` asserts the
correspondence in both directions: every alert's `runbook:` anchor resolves to a
section here, and every section here is referenced by a live alert. Before
Phase 10 neither held -- two alerts had no runbook at all, and three sections
described CI/CD alerts that did not exist.

**Which commands apply.** The AutoAudit application sections use `docker compose`,
because `docker-compose.production.yml` is the only deployment descriptor this
repository contains. The platform sections at the end use `kubectl`, because the
series they read come from kube-state-metrics and the kubelet, which exist only
on Kubernetes -- a platform this repository does not define and whose selection is
still open (see `docs/compliance/phase-10/deployment-platform-decision.md`).
Translate them when the platform is chosen.

---

## API/APIServerErrorRateHigh

### Summary
More than twenty 5xx responses in five minutes, from
`autoaudit_api_errors_total{class="5xx"}`. Client errors are excluded.

### Impact
The API is failing requests. Scans cannot be created and the dashboard cannot
load; this is user-visible.

### Investigation
1. Which routes: `sum by (route, status) (increase(autoaudit_api_errors_total{class="5xx"}[15m]))`.
2. Check readiness, which reports the dependencies rather than the process:
   `curl -fsS localhost:8000/readiness | jq`.
3. Look for the correlated request ids in the API log. Every request logs
   `request_id`, and the same value is echoed in the `X-Request-ID` response
   header and stored on `scan.correlation_id` for anything scan-related.
4. `docker compose -f docker-compose.production.yml logs --tail=200 backend-api`.

### Remediation
- If `/readiness` reports the database or broker unhealthy, treat that as the
  incident; the 5xx rate is a symptom.
- If errors are concentrated on one route, that route's recent change is the
  first suspect.

### Verification
The rate returns below the threshold and `/readiness` reports `ready`.

---

## API/APIClientErrorRateHigh

### Summary
A sustained 4xx rate, from `autoaudit_api_errors_total{class="4xx"}`.

### Impact
Usually none to the service. It normally means a client build is calling the API
incorrectly, or a large number of sessions have expired at once.

### Investigation
1. Split by status: a 401 spike is sessions; a 422 spike is a client sending
   payloads the schema rejects; a 403 spike is CSRF or role.
2. If it is 403 on unsafe methods, check that `FRONTEND_URL` matches the origin
   the browser actually sends -- `CSRFMiddleware` requires an exact match.

### Remediation
- Correct the client, or the `FRONTEND_URL`/CORS configuration.
- This alert is a warning on purpose. It does not warrant a wake-up.

### Verification
The rate returns below the threshold.

---

## API/APILatencyHigh

### Summary
p95 above five seconds on a route, from
`autoaudit_api_request_duration_seconds_bucket`.

### Impact
The UI feels broken. The scan detail page polls a summary endpoint that is meant
to answer a 304 in milliseconds.

### Investigation
1. Identify the route from the alert label. `/v1/evidence` upload routes are
   bounded by `EVIDENCE_PROCESSING_TIMEOUT_SECONDS` (default 120) and are
   expected to be slow; the scan poll routes are not.
2. If a scan route is slow, check the database: the summary endpoint's ETag path
   avoids the per-control query entirely, so slowness there suggests the
   conditional path is not being taken -- confirm clients are sending
   `If-None-Match`.
3. Check connection-pool saturation. Neither the API nor the worker sets an
   explicit pool size; see the known gaps in the Phase 10 handoff.

### Remediation
- Scale the API, or reduce concurrent scan load.

### Verification
p95 for the route returns below five seconds.

---

## API/StoredCredentialUnreadable

### Summary
`autoaudit_decryption_failures_total` increased: stored ciphertext that no key in
the encryption key ring can read.

### Impact
**Every affected tenant cannot be scanned.** This is almost never a code fault.

### Investigation
1. The overwhelmingly likely cause is a key rotation: a retired key was removed
   from `ENCRYPTION_KEY_DECRYPT_ONLY` before the rewrite pass finished.
2. Confirm with `tools/ops/rotate_encryption_key.py --check`. It reports rows it
   cannot read, by connection id, and never prints ciphertext or key material.
3. Confirm the API and the worker carry the *same* ring. They are configured
   independently and are updated at different times by construction.

### Remediation
- **Restore the removed key to `ENCRYPTION_KEY_DECRYPT_ONLY` first.** The data is
  recoverable only while a key that can read it exists somewhere.
- Then run `tools/ops/rotate_encryption_key.py` to completion, and only remove
  the retired key once `--check` reports nothing outstanding.
- If the key is genuinely lost, the affected connections must have their client
  secrets re-entered by their owners. There is no recovery path.

### Verification
`--check` reports zero unreadable rows and the counter stops rising.

---

## ScanLifecycle/ScanExporterDown

### Summary
`autoaudit_collector_exporter_up` is 0 or absent.

### Impact
Severe, and larger than it looks. The dispatcher is the only path by which a scan
reaches the broker: while it is down, no scan starts, nothing recovers, and every
other alert in the scan-lifecycle group is blind because its gauges are stale.

### Investigation
1. Is the process running?
   `docker compose -f docker-compose.production.yml ps dispatcher`.
2. `docker compose -f docker-compose.production.yml logs --tail=100 dispatcher`.
   The dispatcher deliberately logs `dispatcher_cycle_failed` without exception
   text, because a database URL carries credentials; correlate with the database.
3. If the process is up but the gauge is 0, the database read is failing rather
   than the process being dead.

### Remediation
- Restore database connectivity, then restart the dispatcher.
- A single recovery pass can be run by hand: `python -m worker.dispatcher --once`.
  Note that a `--once` run starts no metrics server by design.

### Verification
The gauge returns to 1 and `autoaudit_dispatch_backlog{state="due"}` starts falling.

---

## ScanLifecycle/ScanStalled

### Summary
`autoaudit_scan_oldest_progress_age_seconds` above 1800: a live scan has not
advanced in half an hour.

### Impact
The scan will be failed with `scan_deadline_exceeded` when it reaches
`SCAN_DEADLINE_SECONDS` (default 3600). This alert fires at roughly the halfway
point so there is time to intervene.

### Investigation
1. Which scan: `SELECT id, status, last_progress_at, deadline_at FROM scan
   WHERE status IN ('pending','running') ORDER BY last_progress_at LIMIT 5;`
2. Is the worker consuming? `docker compose ... logs --tail=100 worker`.
3. Is the PowerShell service reachable? Exchange collections hold a session for
   up to a 300-second batch, so a hung service stalls a scan without erroring.
4. Is the outbox draining? See ScanLifecycle/DispatchBacklogStuck.

### Remediation
- Restore whichever dependency is stuck. The outbox is durable: work resumes
  without re-creating the scan.
- Do not delete the scan to "unstick" it. The deadline path is the designed
  recovery and it records a reason code.

### Verification
The age falls, or the scan reaches a terminal state.

---

## ScanLifecycle/ScansPastDeadline

### Summary
`autoaudit_scans_past_deadline` above zero for ten minutes.

### Impact
Worse than a stalled scan. The reconciler is supposed to fail a scan the moment
its deadline passes, so a scan still past its deadline ten minutes later means
the recovery path itself is not running.

### Investigation
1. Check ScanLifecycle/ScanExporterDown first -- the same process runs both the
   reconciler and the exporter, so they usually fail together.
2. If the exporter is up, the reconcile pass is failing while `publish_due`
   continues; check the dispatcher log for `dispatcher_cycle_failed`.

### Remediation
- Restart the dispatcher and confirm a cycle completes.
- `python -m worker.dispatcher --once` exits non-zero on a failed pass, which is
  the quickest way to see whether reconcile can run at all.

### Verification
The gauge returns to zero as the overdue scans are failed.

---

## ScanLifecycle/DispatchBacklogStuck

### Summary
`autoaudit_dispatch_oldest_wait_seconds` above 900: outbox work has been due for
over fifteen minutes without being published.

### Impact
No new scan work reaches the worker. Because Phase 6 makes the outbox the only
authorisation to publish, a stuck outbox is a stopped product.

### Investigation
1. Almost always the broker. A failed publish defers the row and records
   `last_error='broker_unavailable'` rather than dropping it:
   `SELECT last_error, count(*) FROM scan_dispatch GROUP BY last_error;`
2. Check Redis. Note that `infrastructure/runtime/redis.conf` sets
   `maxmemory-policy noeviction`, so under memory pressure Redis refuses writes
   rather than dropping messages -- which is correct for an outbox and presents
   as publish failures.
3. Check the dispatcher is running at all (ScanExporterDown).

### Remediation
- Restore the broker. The backlog drains on the next cycle with no manual
  requeue: retry state lives in PostgreSQL, not in Redis.

### Verification
`autoaudit_dispatch_backlog{state="due"}` and the wait gauge both fall.

---

## ScanLifecycle/DispatchRetriesNearExhaustion

### Summary
Rows have consumed six or more of their eight delivery attempts.

### Impact
When the budget is exhausted the **whole scan** fails with
`dispatch_retry_exhausted`, not just the one task.

### Investigation
1. `SELECT id, scan_id, task_name, attempts, last_error FROM scan_dispatch
   WHERE attempts >= 6;`
2. `last_error` distinguishes a broker problem from a task that is being
   redelivered and failing.
3. A known pre-existing case: a pending control whose metadata is not `ready`
   falls back to a per-result row that `evaluate_control` refuses, so it
   exhausts. This is recorded as an unfixed finding in the Phase 9 and Phase 10
   handoffs.

### Remediation
- Fix the underlying delivery failure. Attempts are not resettable by design;
  the budget is what stops an unrecoverable scan from retrying forever.

### Verification
No rows remain at six or more attempts.

---

## ScanLifecycle/ControlErrorRateHigh

### Summary
More than twenty control results landed in `error` in thirty minutes.

### Impact
Those scans under-report coverage. Note what this is **not**: `error` means
AutoAudit could not assess the control. A `failed` control is a tenant that is
non-compliant -- a true product finding, not an operational event -- and this
alert deliberately does not fire on it.

### Investigation
1. Group by reason: `SELECT reason_code, count(*) FROM scan_result
   WHERE status='error' AND updated_at > now() - interval '1 hour'
   GROUP BY reason_code ORDER BY 2 DESC;`
2. `authentication_error` or `authorization_error` concentrated on one tenant is
   a credential or consent problem, not a system fault. If it is spread across
   tenants, see API/StoredCredentialUnreadable.
3. `evaluation_error` points at OPA; `collection_error` at Graph, Exchange or the
   PowerShell service.

### Remediation
- Address the dominant reason code. A scan can be re-run once the cause is fixed;
  results are versioned, and re-running creates new evidence rather than
  overwriting the old.

### Verification
The error count stops rising.

---

## ResourceUtilisation/ClusterStorageCapacityWarning

### Summary
Alert triggers when cluster storage capacity falls below 15% for more than 10 minutes.

### Impact
Low storage capacity can cause pod evictions, application failures, and data loss.

### Investigation Steps
1. Access Kubernetes nodes and check volume usage:
   ```bash
   kubectl describe pvc
   df -h
   ```
2. Identify pods consuming excessive storage.
3. Check for logs indicating storage pressure or eviction events.
4. Review recent deployments or jobs that may have increased storage usage.

### Remediation
- Clean up unused volumes, logs, or artifacts.
- Scale storage capacity or add new persistent volumes.
- Adjust retention policies for logs and backups.
- Notify storage team if hardware limits are reached.

### Verification
- Confirm storage usage rises above 15% threshold.
- Monitor for alert resolution in Prometheus.

---

## ResourceUtilisation/NetworkBandwidthThreshold

### Summary
Alert triggers when network bandwidth usage exceeds 1Gbps for more than 5 minutes.

### Impact
High bandwidth usage may cause network congestion, latency, or packet loss.

### Investigation Steps
1. Identify pods or services with high network traffic:
   ```bash
   kubectl top pods --namespace=<namespace>
   ```
2. Use network monitoring tools (e.g., Cilium, Calico) to trace traffic sources.
3. Check for abnormal traffic patterns or DDoS attacks.
4. Review recent deployments or batch jobs causing spikes.

### Remediation
- Throttle or limit bandwidth for noisy services.
- Scale network infrastructure or increase bandwidth.
- Block malicious traffic if detected.
- Optimise application network usage.

### Verification
- Confirm bandwidth usage returns below threshold.
- Validate alert clears in monitoring dashboards.

---

## ResourceUtilisation/CPUUsageHigh

### Summary
Alert triggers when CPU usage exceeds 85% for more than 10 minutes on any node.

### Impact
High CPU usage can degrade application performance and cause timeouts.

### Investigation Steps
1. Identify high CPU usage nodes:
   ```bash
   kubectl top nodes
   ```
2. Check pods consuming CPU on affected nodes:
   ```bash
   kubectl top pods --all-namespaces --sort-by=cpu
   ```
3. Review application logs for performance issues.
4. Check for runaway processes or infinite loops.

### Remediation
- Scale out workloads or add nodes.
- Optimise application code or resource requests.
- Restart problematic pods or nodes if necessary.

### Verification
- Confirm CPU usage drops below threshold.
- Monitor alert resolution.

---

## ResourceUtilisation/MemoryUsageHigh

### Summary
Alert triggers when available memory falls below 15% for more than 10 minutes on any node.

### Impact
Low memory can cause pod evictions, OOM kills, and degraded performance.

### Investigation Steps
1. Identify nodes with low memory:
   ```bash
   kubectl top nodes
   ```
2. Check pods with high memory usage:
   ```bash
   kubectl top pods --all-namespaces --sort-by=memory
   ```
3. Review logs for OOM kill events.
4. Check for memory leaks or misconfigured resource limits.

### Remediation
- Increase node memory or add nodes.
- Optimise application memory usage.
- Adjust resource requests and limits.
- Restart affected pods.

### Verification
- Confirm memory availability improves.
- Alert clears in monitoring.

---

## Infrastructure/NodeCPUSaturation

### Summary
Alert triggers when node CPU idle time falls below 10% for 5 minutes.

### Impact
CPU saturation can cause slowdowns and service degradation.

### Investigation Steps
1. Identify affected nodes.
2. Check running pods and CPU usage.
3. Review recent workload changes.

### Remediation
- Scale cluster or redistribute workloads.
- Optimise CPU-intensive applications.
- Restart problematic pods or nodes.

### Verification
- Confirm CPU idle time recovers.
- Alert clears after normalisation.

---

## Infrastructure/PodRestartsHigh

### Summary
Alert triggers when pod container restarts exceed 3 in 10 minutes.

### Impact
Frequent restarts indicate instability or crashes.

### Investigation Steps
1. Identify pods with high restart counts.
2. Review pod logs and events.
3. Check resource limits and health probes.

### Remediation
- Fix application crashes or bugs.
- Adjust resource requests and limits.
- Update liveness/readiness probes.

### Verification
- Confirm restart rates decrease.
- Alert clears after stability.

---

## Infrastructure/DiskSpaceLow

### Summary
Alert triggers when disk space on root filesystem falls below 15% for 15 minutes.

### Impact
Low disk space can cause system failures and data loss.

### Investigation Steps
1. Check disk usage on affected nodes.
2. Identify large files or logs consuming space.
3. Review recent deployments or backups.

### Remediation
- Clean up unnecessary files and logs.
- Increase disk capacity.
- Implement log rotation policies.

### Verification
- Confirm disk space usage improves.
- Alert clears after remediation.

---
