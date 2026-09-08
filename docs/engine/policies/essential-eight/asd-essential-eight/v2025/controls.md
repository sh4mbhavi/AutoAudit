# ASD Essential Eight v2025 - control status

<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Source:     engine/policies/essential-eight/asd-essential-eight/v2025/metadata.json
     Generator:  tools/docs/generate_control_status.py
     Regenerate: python tools/docs/generate_control_status.py
     Verify:     python tools/docs/generate_control_status.py --check
-->

Every number below is counted from the source metadata, never typed by hand. The document carries no generation timestamp, so regenerating it without a metadata change produces byte-identical output and CI can diff it.

## Provenance

| Field | Value |
| --- | --- |
| Framework | `essential-eight` |
| Benchmark | ASD Essential Eight |
| Benchmark version | `v2025` |
| Benchmark release date | 2025-11-01 |
| Platform | `m365` |
| Upstream source | https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model |
| Source metadata | `engine/policies/essential-eight/asd-essential-eight/v2025/metadata.json` |
| Source metadata SHA-256 | `337dbdd1222469e0605dd0aa964d976175fecd527119a9af079025c56374dff8` |
| Controls described | 14 |

"Controls described" counts the controls present in that metadata file, which may be a subset of the published benchmark.

## Three questions this document keeps separate

Hand-written versions of this page blended three different facts into a single "manual" number. They answer different questions:

1. `automation_status` - what AutoAudit does with the control today.
2. `benchmark_audit_type` - how the published benchmark classifies the audit.
3. `is_manual` - whether the control has any programmatic source at all.

For v2025 the answers are 3 (`automation_status` == `manual`), 3 (`benchmark_audit_type` == `Manual`) and 3 (`is_manual` == `true`). Quoting any one of them as "the manual count" misstates the other two.

- `is_manual` true while `automation_status` is not `manual`: 0 controls.
- `benchmark_audit_type` Manual while `automation_status` is not `manual`: 0 controls.
- `automation_status` manual while `benchmark_audit_type` is not Manual: 0 controls.

### Implementation status (`automation_status`)

| Status | Controls | Share | What it means |
| --- | ---: | ---: | --- |
| `ready` | 3 | 21.4% | Collector and policy are implemented, so the scan evaluates this control. |
| `manual` | 3 | 21.4% | No programmatic source, so the control is verified by hand. |
| `not_started` | 8 | 57.1% | No collector or policy implemented yet. |
| **Total** | **14** | **100.0%** | |

### Benchmark audit type (`benchmark_audit_type`)

| Audit type | Controls | Share |
| --- | ---: | ---: |
| `Automated` | 10 | 71.4% |
| `Inferred` | 1 | 7.1% |
| `Manual` | 3 | 21.4% |
| **Total** | **14** | **100.0%** |

### No programmatic source (`is_manual`)

| `is_manual` | Controls | Share |
| --- | ---: | ---: |
| `true` | 3 | 21.4% |
| `false` | 11 | 78.6% |
| **Total** | **14** | **100.0%** |

## Distribution

### Severity

| Severity | Controls | Share |
| --- | ---: | ---: |
| `critical` | 3 | 21.4% |
| `high` | 8 | 57.1% |
| `medium` | 3 | 21.4% |
| **Total** | **14** | **100.0%** |

### Maturity level

| Maturity level | Controls | Share |
| --- | ---: | ---: |
| `ML0` | 1 | 7.1% |
| `ML1` | 5 | 35.7% |
| `ML2` | 2 | 14.3% |
| `ML3` | 6 | 42.9% |
| **Total** | **14** | **100.0%** |

### Service

| Service | Controls | Share |
| --- | ---: | ---: |
| `EntraID` | 2 | 14.3% |
| `Intune` | 12 | 85.7% |
| **Total** | **14** | **100.0%** |

## Controls

Sorted by control id numerically, so `1.1.10` follows `1.1.9` rather than `1.1.1`.

| Control ID | Title | `automation_status` | `benchmark_audit_type` | `is_manual` | Severity | Service | Maturity level | Policy file | Data collector ID |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E8-MAC-0 | No macro controls implemented (ML0 baseline) | `not_started` | Inferred | `false` | critical | Intune | ML0 | — | — |
| E8-MAC-1.1 | Macros disabled for standard users | `not_started` | Automated | `false` | high | Intune | ML1 | — | `entra.devices.configuration_policies` |
| E8-MAC-1.2 | Internet-originated macros blocked (Mark of the Web) | `not_started` | Automated | `false` | high | Intune | ML1 | — | `entra.devices.configuration_policies` |
| E8-MAC-1.3 | AMSI scanning enabled for macros | `not_started` | Automated | `false` | high | Intune | ML1 | — | `entra.devices.configuration_policies` |
| E8-MAC-1.4 | Users cannot change macro settings | `not_started` | Automated | `false` | medium | Intune | ML1 | — | `entra.devices.configuration_policies` |
| E8-MAC-2.1 | Win32 API calls blocked from Office macros (ASR rule) | `ready` | Automated | `false` | high | Intune | ML2 | `e8_mac_2_1_win32_api_block.rego` | `entra.devices.asr_rules` |
| E8-MAC-3.1 | Only signed macros from trusted publishers can execute | `not_started` | Automated | `false` | high | Intune | ML3 | — | `entra.devices.configuration_policies` |
| E8-MAC-3.2 | Write access to Trusted Locations restricted to privileged users | `manual` | Manual | `true` | high | Intune | ML3 | — | — |
| E8-MAC-3.3 | Untrusted publishers blocked via Message Bar or Backstage view | `not_started` | Automated | `false` | medium | Intune | ML3 | — | `entra.devices.configuration_policies` |
| E8-MAC-3.4 | V3 macro signatures required | `not_started` | Automated | `false` | high | Intune | ML3 | — | `entra.devices.configuration_policies` |
| E8-MAC-3.5 | Pre-signing malicious code check performed | `manual` | Manual | `true` | high | Intune | ML3 | — | — |
| E8-MAC-3.6 | Annual trusted publisher list review | `manual` | Manual | `true` | medium | Intune | ML3 | — | — |
| E8-MFA-2.1 | MFA required for privileged users and Microsoft 365 services | `ready` | Automated | `false` | critical | EntraID | ML2 | `e8_mfa_2_1_ca_enforcement.rego` | `entra.conditional_access.e8_mfa_enforcement` |
| E8-PRIV-1.1 | Privileged access restricted and appropriately assigned | `ready` | Automated | `false` | critical | EntraID | ML1 | `e8_priv_1_1_restrict_admin_privileges.rego` | `entra.roles.cloud_only_admins` |

## Implementation notes

14 controls carry a note in the metadata. The note is the reason the control sits at its current `automation_status`.

| Control ID | Note |
| --- | --- |
| E8-MAC-0 | ML0 is inferred from the absence of ML1 policies. |
| E8-MAC-1.1 | Partial automation. |
| E8-MAC-1.2 | Partial automation. |
| E8-MAC-1.3 | Partial automation. |
| E8-MAC-1.4 | Partial automation. |
| E8-MAC-2.1 | Fully automatable. |
| E8-MAC-3.1 | Partial automation. |
| E8-MAC-3.2 | Not automatable. |
| E8-MAC-3.3 | Partial automation. |
| E8-MAC-3.4 | Partial automation. |
| E8-MAC-3.5 | Not automatable. |
| E8-MAC-3.6 | Not automatable. |
| E8-MFA-2.1 | Research basis: 26T1-SEC-EG-001 and 26T1-SEC-EG-003. |
| E8-PRIV-1.1 | Research basis: 26T1-SEC-EG-002 and 26T1-SEC-EG-004. |

## Changing this document

1. Edit `engine/policies/essential-eight/asd-essential-eight/v2025/metadata.json`.
2. Run `python tools/docs/generate_control_status.py`.
3. Commit the metadata change and the regenerated document together.

CI runs `python tools/docs/generate_control_status.py --check` and fails if this file and its metadata disagree.
