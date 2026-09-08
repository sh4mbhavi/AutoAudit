# CIS Microsoft 365 Foundations v4.0.0 - control status

<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Source:     engine/policies/cis/microsoft-365-foundations/v4.0.0/metadata.json
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
| Benchmark version | `v4.0.0` |
| Benchmark release date | 2024-10-31 |
| Platform | `m365` |
| Upstream source | https://www.cisecurity.org/benchmark/microsoft_365 |
| Source metadata | `engine/policies/cis/microsoft-365-foundations/v4.0.0/metadata.json` |
| Source metadata SHA-256 | `70b1b1a5cd8bebeed44f20fd98889b1dbe4f6f276eb8d718196707eac3aed9c6` |
| Controls described | 2 |

"Controls described" counts the controls present in that metadata file, which may be a subset of the published benchmark.

## Three questions this document keeps separate

Hand-written versions of this page blended three different facts into a single "manual" number. They answer different questions:

1. `automation_status` - what AutoAudit does with the control today.
2. `benchmark_audit_type` - how the published benchmark classifies the audit.
3. `is_manual` - whether the control has any programmatic source at all.

For v4.0.0 the answers are 0 (`automation_status` == `manual`), 0 (`benchmark_audit_type` == `Manual`) and 0 (`is_manual` == `true`). Quoting any one of them as "the manual count" misstates the other two.

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
| `high` | 1 | 50.0% |
| `medium` | 1 | 50.0% |
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
| 1.3.1 | Ensure the 'Password expiration policy' is set to 'Set passwords to never expire' | `ready` | Automated | `false` | medium | EntraID | L1 | `1.3.1_password_expiration.rego` | `entra.domains.password_policy` |
| 5.2.2.3 | Ensure Conditional Access policies are configured to block legacy authentication | `ready` | Automated | `false` | high | EntraID | L1 | `5.2.2.3_block_legacy_auth.rego` | `entra.conditional_access.legacy_auth_block` |

## Changing this document

1. Edit `engine/policies/cis/microsoft-365-foundations/v4.0.0/metadata.json`.
2. Run `python tools/docs/generate_control_status.py`.
3. Commit the metadata change and the regenerated document together.

CI runs `python tools/docs/generate_control_status.py --check` and fails if this file and its metadata disagree.
