# Phase 4 collector contract coverage

The Appendix B inventory resolves 44 controls to 30 unique collectors: 17 Graph and 13 PowerShell. `engine/tests/test_phase4_collector_contracts.py` asserts the inventory against current v6 metadata and exercises real collectors with mocked API transports or cmdlet results. No tenant access is required.

All 30 collectors have success, empty, malformed, 403, 429, and partial-property response cases. Graph pagination tests follow every collection route in each fixture, including nested role members, user licenses, PIM rules, and the previously single-page B2B/password/PIM paths. Singleton Graph endpoints and PowerShell cmdlets have no Graph continuation contract.

| Collector | Success / empty / malformed / 403 / 429 / partial | Paginated collection routes |
|---|---|---|
| `entra.roles.cloud_only_admins` | Covered | `/directoryRoles`; `/directoryRoles/role/members` |
| `entra.roles.privileged_roles` | Covered | `/directoryRoles`; `/directoryRoles/role/members` |
| `entra.roles.admin_license_footprint` | Covered | `/directoryRoles`; `/directoryRoles/role/members`; `/users/user/licenseDetails` |
| `entra.groups.groups` | Covered | `/groups` |
| `entra.domains.password_policy` | Covered | `/domains` |
| `entra.applications.apps_and_services_settings` | Covered | Not applicable |
| `entra.devices.enrollment_restrictions` | Covered | `/deviceManagement/deviceEnrollmentConfigurations` |
| `entra.policies.authorization_policy` | Covered | Not applicable |
| `entra.policies.admin_consent_request_policy` | Covered | Not applicable |
| `entra.policies.b2b_policy` | Covered | `/policies/crossTenantAccessPolicy/partners` |
| `entra.conditional_access.legacy_auth_block` | Covered | `/identity/conditionalAccess/policies` |
| `entra.authentication.mfa_fatigue_protection` | Covered | Not applicable |
| `entra.authentication.password_protection` | Covered | `/settings` |
| `entra.authentication.mfa_registration_report` | Covered | `/reports/authenticationMethods/userRegistrationDetails` |
| `entra.authentication.authentication_methods` | Covered | Not applicable |
| `entra.governance.pim_role_policies` | Covered | `/policies/roleManagementPolicies`; `/roleManagement/directory/roleDefinitions`; `/policies/roleManagementPolicies/pim/rules` |
| `entra.governance.access_reviews` | Covered | `/identityGovernance/accessReviews/definitions` |
| `exchange.protection.safe_links_policy` | Covered | Not applicable |
| `exchange.protection.malware_filter_policy` | Covered | Not applicable |
| `exchange.protection.safe_attachment_policy` | Covered | Not applicable |
| `exchange.protection.atp_policy_o365` | Covered | Not applicable |
| `exchange.protection.hosted_outbound_spam_filter` | Covered | Not applicable |
| `exchange.protection.anti_phish_policy` | Covered | Not applicable |
| `exchange.protection.teams_protection_policy` | Covered | Not applicable |
| `exchange.organization.organization_config` | Covered | Not applicable |
| `exchange.organization.transport_config` | Covered | Not applicable |
| `exchange.mailbox.mailbox_audit` | Covered | Not applicable |
| `exchange.mailbox.mailbox_audit_actions` | Covered | Not applicable |
| `exchange.transport.transport_rules` | Covered | Not applicable |
| `exchange.transport.external_in_outlook` | Covered | Not applicable |

## Regression evidence

Seven test-first rounds observed the targeted failures before implementation: **33**, **27**, **12**, **8**, **13**, **20**, and **5** failing cases respectively. Tests then passed after each fix. The final collector-only run is **296 passed**, with the existing Pydantic class-config warning.

```sh
uv run --project engine --extra dev pytest engine/tests/test_phase4_collector_contracts.py -q
```

Regression fixes reject malformed Graph response objects and collection pages, reject unexpected continuation origins/API versions, and fail collection at the page cap instead of returning partial data. B2B partners, password settings, and PIM policies/rules now collect all pages. Nested/later query failures propagate without a partial assessment. PowerShell collectors normalize zero/single/multiple results with shape checks; singleton absence stays empty. The PowerShell HTTP client requires boolean success and an explicit data field, and rejects partial error envelopes.

Unknown sync state, unknown authentication method state, and unknown domain authentication type remain null. Incomplete license plans or role member identities fail collection instead of disappearing or becoming low-footprint/cloud-only evidence. MFA counts require actual booleans. Disabled Authenticator cannot produce an affirmative number-matching signal. Legacy-auth user/group/role/application exclusions invalidate claims of universal scope; absent exclusion arrays preserve unknown scope. Anti-phish rules are now collected because the assignment policy requires them.

Enrollment classification now recognizes the Graph type. The derived default-enrollment signal requires an explicitly identified default platform configuration and all five platform boolean properties (Android, iOS, Windows, macOS, Windows Mobile). Missing/default scope or platform evidence yields null; a complete configuration with any false flag yields false. Graph documents the [default platform configuration and configuration-type enum](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentplatformrestrictionsconfiguration?view=graph-rest-beta). Priority alone is not treated as proof of default scope.

The final independent boundary review found and fixed filtered-population gaps: group visibility and transport forwarding/whitelist classification now require complete source properties before filtering, so an incomplete record cannot silently become a safe empty result. Graph error envelopes and PowerShell error records are rejected before normalization.

## Limits

- These contracts establish mocked response behavior, not live M365 permission/tenant/API availability or audit applicability.
- A successful empty collection is distinct from a transport failure. Whether a complete empty population passes, fails, or is indeterminate is governed by each policy; collectors preserve that evidence.
- The Graph page cap is bounded and fails closed. There is no new throttling retry/backoff; 429 remains an execution error for the worker retry path.
- A remote PowerShell service that incorrectly reports success with silently truncated data and no error cannot be detected by response shape validation alone. PowerShell runtime/error-stream completeness and tenant acceptance remain required.
- PIM policy presence remains the existing control signal and does not prove eligible assignment usage; no new claim of broader PIM enforcement is made.
- Default enrollment configurations lacking the explicit beta configuration-type marker or any required platform property remain indeterminate. Live/API-version applicability review may justify expanding recognized shapes later.
- The parent handoff records the final full-engine/OPA/integration counts. An intermediate full-engine run passed 881 tests with 13 skips without a migration database configured, before the final 39 collector cases were added.
