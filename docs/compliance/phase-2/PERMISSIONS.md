# POL-05 — Permission reconciliation

Verified against Microsoft documentation on 2026-09-05. These are application
permissions for the collector's existing read operations. No tenant grants,
credentials, endpoints or authentication behavior were changed. Passing the
consistency tests proves declaration agreement, not successful tenant access.

| CIS v6.0.0 controls | Resolution | Microsoft source |
|---|---|---|
| 1.2.2 | Metadata now uses `Exchange.ManageAsApp`, matching the policy and mailbox collector. Exchange RBAC role assignment and app-only authentication are also required; this permission alone does not impose read-only execution. | [Exchange app-only authentication](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps) |
| 2.1.8, 2.1.10 | Policy annotations now use `Domain.Read.All`, matching metadata and the Graph domain enumeration performed before public DNS lookups. The service remains Exchange because that labels the audited workload. | [List domains](https://learn.microsoft.com/en-us/graph/api/domain-list?view=graph-rest-1.0) |
| 4.2 | Metadata now uses `DeviceManagementServiceConfig.Read.All`, matching the enrollment configuration endpoint, policy and collector documentation. An active Intune license is required. | [List deviceEnrollmentConfigurations](https://learn.microsoft.com/en-us/graph/api/intune-shared-deviceenrollmentconfiguration-list?view=graph-rest-beta) |
| 5.1.4.1 | Metadata now uses `Policy.Read.DeviceConfiguration`. The current application permission table does not list `Policy.Read.All` as an alternative, although the delegated table does. | [Get deviceRegistrationPolicy](https://learn.microsoft.com/en-us/graph/api/deviceregistrationpolicy-get?view=graph-rest-beta) |
| 5.1.4.5 | Moved the existing annotation fields under OPA's `custom` key. `Policy.Read.DeviceConfiguration` is unchanged; the previous top-level annotation was invisible to OPA custom metadata consumers. | [Get deviceRegistrationPolicy](https://learn.microsoft.com/en-us/graph/api/deviceregistrationpolicy-get?view=graph-rest-beta) |
| 5.2.3.2, 5.2.3.3 | Metadata, policy annotations and collector documentation now use the documented least-privileged `GroupSettings.Read.All` for tenant-wide `/beta/settings`. `Directory.Read.All` remains a documented higher-privileged alternative; the previous metadata `Policy.Read.All` is not listed. Password-rule template visibility still needs tenant validation. | [List tenant-wide settings](https://learn.microsoft.com/en-us/graph/api/group-list-settings?tabs=http&view=graph-rest-beta) |
| 5.3.1, 5.3.4, 5.3.5 | Policy annotations and collector documentation now match metadata's `RoleManagement.Read.Directory`. This single read permission is documented for policy enumeration, policy rules **and** the collector's role-definition lookup. Replacing metadata with the narrower policy-only permission would leave that lookup unauthorized. | [List roleManagementPolicies](https://learn.microsoft.com/en-us/graph/api/policyroot-list-rolemanagementpolicies?view=graph-rest-beta), [List policy rules](https://learn.microsoft.com/en-us/graph/api/unifiedrolemanagementpolicy-list-rules?view=graph-rest-beta), [List directory roleDefinitions](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roledefinitions?view=graph-rest-beta) |

`engine/tests/test_policy_permissions.py` checks all ready v6 policy permission
blocks against metadata and independently pins the reviewed collector permission
sets. It enforces the documented annotation block-list format; OPA `inspect -a`
provides a separate native annotation check during this handoff.

The shared `metadata.json` edits affect only the five listed permission arrays.
Other owners' ready controls and all automation statuses remain unchanged.
Existing `Exchange.Manage` declarations on other controls, readiness probes,
collector completeness, and beta API support are outside this mismatch hotfix.
The Graph beta APIs retain their documented support limitations. Verify the
changed permissions in a non-production licensed tenant before deployment;
readiness warnings or a successful declaration test are not evidence of consent,
licensing, or collection completeness.
