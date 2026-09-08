# CIS Microsoft 365 Foundations v3.1.0 - control status

<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Source:     engine/policies/cis/microsoft-365-foundations/v3.1.0/metadata.json
     Generator:  tools/docs/generate_control_status.py
     Regenerate: python tools/docs/generate_control_status.py
     Verify:     python tools/docs/generate_control_status.py --check
-->

Every number below is counted from the source metadata, never typed by hand. The document carries no generation timestamp, so regenerating it without a metadata change produces byte-identical output and CI can diff it.

## Provenance

| Field | Value |
| --- | --- |
| Framework | `cis` |
| Benchmark | CIS Microsoft 365 Foundations |
| Benchmark version | `v3.1.0` |
| Benchmark release date | 2024-04-29 |
| Platform | `m365` |
| Upstream source | https://www.cisecurity.org/benchmark/microsoft_365 |
| Source metadata | `engine/policies/cis/microsoft-365-foundations/v3.1.0/metadata.json` |
| Source metadata SHA-256 | `0377064c4cf9000a618c3c1239647d5cbdd9e7d96ebfcaa42cf8637fd5dc7ff5` |
| Controls described | 2 |

"Controls described" counts the controls present in that metadata file, which may be a subset of the published benchmark.

## Three questions this document keeps separate

Hand-written versions of this page blended three different facts into a single "manual" number. They answer different questions:

1. `automation_status` - what AutoAudit does with the control today.
2. `benchmark_audit_type` - how the published benchmark classifies the audit.
3. `is_manual` - whether the control has any programmatic source at all.

For v3.1.0 the answers are 0 (`automation_status` == `manual`), 0 (`benchmark_audit_type` == `Manual`) and 0 (`is_manual` == `true`). Quoting any one of them as "the manual count" misstates the other two.

- `is_manual` true while `automation_status` is not `manual`: 0 controls.
- `benchmark_audit_type` Manual while `automation_status` is not `manual`: 0 controls.
- `automation_status` manual while `benchmark_audit_type` is not Manual: 0 controls.

### Implementation status (`automation_status`)

| Status | Controls | Share | What it means |
| --- | ---: | ---: | --- |
| `ready` | 2 | 100.0% | Collector and policy are implemented, so the scan evaluates this control. |
| **Total** | **2** | **100.0%** | |

### Benchmark audit type (`benchmark_audit_type`)

| Audit type | Controls | Share |
| --- | ---: | ---: |
| `Automated` | 2 | 100.0% |
| **Total** | **2** | **100.0%** |

### No programmatic source (`is_manual`)

| `is_manual` | Controls | Share |
| --- | ---: | ---: |
| `false` | 2 | 100.0% |
| **Total** | **2** | **100.0%** |

## Distribution

### Severity

| Severity | Controls | Share |
| --- | ---: | ---: |
| `critical` | 1 | 50.0% |
| `high` | 1 | 50.0% |
| **Total** | **2** | **100.0%** |

### Level

| Level | Controls | Share |
| --- | ---: | ---: |
| `L1` | 2 | 100.0% |
| **Total** | **2** | **100.0%** |

### Service

| Service | Controls | Share |
| --- | ---: | ---: |
| `EntraID` | 2 | 100.0% |
| **Total** | **2** | **100.0%** |

## Controls

Sorted by control id numerically, so `1.1.10` follows `1.1.9` rather than `1.1.1`.

| Control ID | Title | `automation_status` | `benchmark_audit_type` | `is_manual` | Severity | Service | Level | Policy file | Data collector ID |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.1 | Ensure Administrative accounts are cloud-only | `ready` | Automated | `false` | critical | EntraID | L1 | `1.1.1_admin_cloud_only.rego` | `entra.roles.cloud_only_admins` |
| 1.1.3 | Ensure that between two and four global admins are designated | `ready` | Automated | `false` | high | EntraID | L1 | `1.1.3_global_admin_count.rego` | `entra.roles.privileged_roles` |

## Changing this document

1. Edit `engine/policies/cis/microsoft-365-foundations/v3.1.0/metadata.json`.
2. Run `python tools/docs/generate_control_status.py`.
3. Commit the metadata change and the regenerated document together.

CI runs `python tools/docs/generate_control_status.py --check` and fails if this file and its metadata disagree.
