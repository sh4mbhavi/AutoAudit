# Alerts retired in Phase 10, and why

Phase 10's plan item is "emit the metrics currently referenced by alert rules
**or** replace those rules with actual emitted metrics". Most rules were
replaced. These seven were retired instead, because there is no honest series to
point them at. Each is recorded here rather than deleted silently, so a later
reader can see the decision rather than rediscover the gap.

The test `tools/tests/test_phase10_alert_metrics.py` asserts that none of these
alert names has come back without this file being updated.

## Retired because the metric conflates a tenant finding with a system fault

### `FailedAuditChecks`

    increase(compliance_audit_failures_total[30m]) > 5   → severity high, team compliance

A "compliance audit failure" in this product is a control whose result is
`failed`: the tenant is configured in a way the benchmark says it should not be.
That is the product working correctly and reporting a true finding. Paging an
infrastructure team because a customer has six misconfigurations is not an
operational signal, and Phase 0 decisions D01 and D02 are explicit that a
control failure and a collection failure are different things that must not be
mixed.

The operational half of this concern -- controls that could not be assessed at
all -- is now `ControlErrorRateHigh` in `scan_lifecycle.yaml`, reading
`autoaudit_control_results{status="error"}`.

### `MissingControlsDetected`

    compliance_missing_controls_total > 0   → severity medium, team compliance

Same conflation, and additionally "missing control" names nothing in the
product's vocabulary. The nearest true concept is coverage: controls that were
selected but landed in `error`, `indeterminate` or `not_assessable`. Those are
visible as `autoaudit_control_results` by status, and a coverage deficit is a
property of a *scan report*, which the product already renders, rather than of
the running system.

## Retired because the application cannot observe the event

### `SuspiciousPrivilegeEscalation`

    increase(privilege_escalation_events_total[10m]) > 0   → severity critical

No API route in AutoAudit writes `user.role`. Roles are set by the development
seed -- which `APP_ENV != dev` prohibits outright -- or out of band against the
database. The application therefore cannot observe a privilege change, because
it never performs one. Emitting a counter that is structurally always zero would
be worse than no alert: it would read as coverage.

Detecting an out-of-band role change needs database audit logging, which is a
platform control the deployment owner has to provide.

### `UnauthorisedAccessAttempt`

    sum by (instance) (rate(auditd_logins_failed_total[5m])) > 10   → severity critical

`auditd_logins_failed_total` is a **host** metric from a Linux auditd exporter:
it counts failed logins to the machine, not to AutoAudit. No such exporter is
deployed, and the description ("brute force ... credential stuffing") describes
application authentication, which this expression never measured.

Failed authentication against the API is already fully described by
`autoaudit_api_errors_total` filtered to the auth routes -- the same requests,
counted once, in the series the API already emits. Host-level login monitoring
remains a platform control.

## Retired because the data can only come from CI, and no path carries it

### `CICDPipelineFailed`, `CICDPipelineDurationHigh`

    increase(cicd_pipeline_failures_total[5m]) > 0
    histogram_quantile(0.95, sum(rate(cicd_pipeline_duration_seconds_bucket[5m])) by (le)) > 600

Both series can only be produced by the CI system, which would have to push to a
Pushgateway that is not deployed and is not part of any selected platform. Both
also alerted on five-minute rate windows over data that arrives only when
somebody pushes a commit, so even with a Pushgateway they would mostly evaluate
over an empty window.

GitHub already reports workflow failure and duration on the run itself, and
those rules had no runbook -- they were the only two alerts in the repository
without one. Workflow health is tracked where the workflows run.

### `VulnerabilityScanFailure`

    absent_over_time(vulnerability_scan_success[30m])   → for 15m, severity high

`ci.grype.yml` runs on push, on pull request, and weekly at 20:37 on Thursdays.
A 30-minute absence window against a weekly job is unsatisfiable: the metric
would be absent for essentially the whole week, so this rule fires permanently
and resolves for minutes at a time. Dependency-scan health is a CI concern,
visible on the workflow.

## Rewritten rather than retired

### `MissingComplianceScans`

    absent_over_time(compliance_scan_success[1h])   → for 10m, severity high

The intent is sound; the construction was not. Scans in AutoAudit are
user-initiated -- there is no scheduler anywhere in the product -- so "no scan
completed in the last hour" is the normal state of any real deployment, and this
rule would have paged eight times a day from the moment Prometheus was stood up.
`absent_over_time` also returns a label-free vector, so its
`{{ $labels.service }}` templating would have rendered empty.

The dispatcher now exports
`autoaudit_scan_last_completion_timestamp_seconds{status}`. An operator who
expects scans on a cadence can alert on the age of that timestamp against
whatever cadence they actually run; the repository ships no such rule, because
the repository does not know the cadence.

### `ScanEngineFailure`

    rate(scan_engine_errors_total[1m]) > 0

Defined **twice** -- identically in `application_errors.yaml` (severity medium,
team backend) and in `security_alerts.yaml` (severity high, team security).
Prometheus accepts duplicate alert names in different groups, so both fired, and
`alertmanager.yaml` groups by `['alertname','team']`, which split one condition
into two notifications with contradictory priority. Their two runbook anchors
gave contradictory advice.

Replaced by a single `ControlErrorRateHigh`, which measures the same thing --
controls the engine could not assess -- from the result rows rather than from a
counter nothing incremented.
