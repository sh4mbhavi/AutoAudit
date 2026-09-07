# AutoAudit alerting rules

## What is actually true

**Nothing here is deployed.** There is no Prometheus, no Alertmanager, no
exporter and no Grafana in this repository — the only deployment descriptors are
the `docker-compose*.yml` files at the root. These are rule and routing
definitions, validated and unit-tested, waiting for a monitoring stack that a
platform decision has not yet chosen.

This section used to say "Alerting rules are deployed via Helm charts to the AKS
cluster". There is no Helm chart, no Kubernetes manifest and no AKS cluster
anywhere in this repository, and the production platform has not been selected —
see `docs/compliance/phase-10/deployment-platform-decision.md`. Presenting this
directory to an auditor as operating monitoring would have been a false claim,
which is why Phase 10 corrected the sentence rather than the reader's
expectations.

## The rules

| File | Reads | Source |
|---|---|---|
| `application.yaml` | `autoaudit_api_*`, `autoaudit_decryption_failures_total` | The API, at `GET /metrics` (`backend-api/app/core/metrics.py`) |
| `scan_lifecycle.yaml` | `autoaudit_scans_*`, `autoaudit_dispatch_*`, `autoaudit_control_results`, `autoaudit_collector_exporter_up` | The dispatcher, on `METRICS_PORT` (`engine/worker/metrics.py`), derived from the database |
| `platform.yaml` | `node_*`, `container_*`, `kube_*`, `kubelet_*` | **Third-party exporters the deployment platform must provide.** Nothing here comes from AutoAudit. |

`RETIRED-ALERTS.md` records the seven rules Phase 10 removed and why. Each was
removed because no honest series exists to point it at, not because the concern
was unimportant.

Before Phase 10 every application-level rule in this directory referenced a
metric name that appeared nowhere else in the repository — eleven of them. Two
(`MissingComplianceScans`, `VulnerabilityScanFailure`) used `absent_over_time` on
a metric nothing emitted, so they would have fired permanently and continuously
from the moment Prometheus was first stood up.

## Why the metrics come from where they do

The API reports its own request-level series, because only it sees them.

Everything about scans is derived from the **database**, by the dispatcher,
rather than counted in the worker. Three reasons, in order of importance:

1. The database is the audit record. A metric read from the scan and result rows
   cannot disagree with the evidence an auditor reads; a parallel counter can,
   and the disagreement would surface as an alert nobody could reconcile.
2. The worker runs `--pool=prefork --concurrency=4`, so a counter in a forked
   child is invisible to a scrape of the parent.
3. A counter resets on restart. A gauge over rows does not.

The cost is stated in `engine/worker/metrics.py`: a gauge sampled on a poll
cannot measure something that starts and finishes between two samples, so there
is **no per-collection latency series**. Phase 9's outbox deletes its row at
settlement, so it cannot be recovered after the fact either. The module reports
no duration histogram rather than a misleading one.

## Testing

```sh
# Syntax, per rule file.
promtool check rules infrastructure/monitoring/alerts/application.yaml

# Semantics: does this threshold fire when it should, and stay quiet when it
# should not. Needs no running Prometheus.
promtool test rules infrastructure/monitoring/alerts/tests/rule_tests.yaml

# Provenance: is every metric an alert reads actually emitted, or declared
# external with the exporter that provides it.
python tools/ci/check_alert_metrics.py
```

All three run in `ci.validate-alerts.yml`, which installs a **checksum-verified,
pinned** promtool via `tools/ci/install_promtool.py` and — unlike before — is not
path-filtered, so deleting a metric emitter in the application fails the alert
build rather than passing silently.

`alert_simulation_test.py` was deleted. It required a live Prometheus and
Pushgateway at hardcoded localhost URLs, was referenced by no workflow, and could
not have passed: it pushed a constant gauge value and asserted `rate()` of it
exceeded 10, and the rate of a constant is zero.

## Routing

`alertmanager.yaml` routes by team and severity, with inhibition rules so a dead
exporter suppresses the derived alerts it has blinded. Every address and the SMTP
password come from the environment; no credential is written in the file.

**Acknowledgement does not exist.** Alertmanager can silence an alert; it cannot
record that a human accepted responsibility for one. That needs a paging tool
with an on-call roster, which is an organisational control with a named owner —
and no control in this program has a named owner yet. It is listed as a gap in
the Phase 10 handoff rather than implied by this configuration.

## Runbooks

`runbooks/RUNBOOKS.md` has one section per alert, and
`tools/tests/test_phase10_alert_metrics.py` asserts the correspondence in both
directions. Before Phase 10 neither direction held: two alerts had no runbook,
and three runbook sections described CI/CD alerts that did not exist.

The AutoAudit sections use `docker compose`, matching the only deployment
descriptor that exists. The platform sections still use `kubectl`, because the
series they read exist only on Kubernetes; translate them when a platform is
chosen.
