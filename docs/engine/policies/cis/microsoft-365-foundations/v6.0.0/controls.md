# CIS Microsoft 365 Foundations v6.0.0 - control status

<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Source:     engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json
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
| Benchmark version | `v6.0.0` |
| Benchmark release date | 2025-03-18 |
| Platform | `m365` |
| Upstream source | https://www.cisecurity.org/benchmark/microsoft_365 |
| Source metadata | `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json` |
| Source metadata SHA-256 | `719d767241152b4c01e18b1feceddf291a15de360d0bc08b18f5b94eda096a04` |
| Controls described | 140 |

"Controls described" counts the controls present in that metadata file, which may be a subset of the published benchmark.

## Three questions this document keeps separate

Hand-written versions of this page blended three different facts into a single "manual" number. They answer different questions:

1. `automation_status` - what AutoAudit does with the control today.
2. `benchmark_audit_type` - how the published benchmark classifies the audit.
3. `is_manual` - whether the control has any programmatic source at all.

For v6.0.0 the answers are 11 (`automation_status` == `manual`), 23 (`benchmark_audit_type` == `Manual`) and 24 (`is_manual` == `true`). Quoting any one of them as "the manual count" misstates the other two.

- `is_manual` true while `automation_status` is not `manual`: 13 controls.
- `benchmark_audit_type` Manual while `automation_status` is not `manual`: 13 controls.
- `automation_status` manual while `benchmark_audit_type` is not Manual: 1 control.

### Implementation status (`automation_status`)

| Status | Controls | Share | What it means |
| --- | ---: | ---: | --- |
| `ready` | 69 | 49.3% | Collector and policy are implemented, so the scan evaluates this control. |
| `deferred` | 12 | 8.6% | Collector runs, but a pass/fail decision still needs human review. |
| `blocked` | 31 | 22.1% | Collector exists and cannot run yet (authentication or API blocker). |
| `manual` | 11 | 7.9% | No programmatic source, so the control is verified by hand. |
| `not_started` | 17 | 12.1% | No collector or policy implemented yet. |
| **Total** | **140** | **100.0%** | |

### Benchmark audit type (`benchmark_audit_type`)

| Audit type | Controls | Share |
| --- | ---: | ---: |
| `Automated` | 117 | 83.6% |
| `Manual` | 23 | 16.4% |
| **Total** | **140** | **100.0%** |

### No programmatic source (`is_manual`)

| `is_manual` | Controls | Share |
| --- | ---: | ---: |
| `true` | 24 | 17.1% |
| `false` | 116 | 82.9% |
| **Total** | **140** | **100.0%** |

## Distribution

### Severity

| Severity | Controls | Share |
| --- | ---: | ---: |
| `critical` | 5 | 3.6% |
| `high` | 33 | 23.6% |
| `medium` | 97 | 69.3% |
| `low` | 5 | 3.6% |
| **Total** | **140** | **100.0%** |

### Level

| Level | Controls | Share |
| --- | ---: | ---: |
| `L1` | 97 | 69.3% |
| `L2` | 43 | 30.7% |
| **Total** | **140** | **100.0%** |

### Service

| Service | Controls | Share |
| --- | ---: | ---: |
| `Bookings` | 1 | 0.7% |
| `Compliance` | 4 | 2.9% |
| `Defender` | 16 | 11.4% |
| `EntraID` | 55 | 39.3% |
| `Exchange` | 18 | 12.9% |
| `Fabric` | 12 | 8.6% |
| `Forms` | 1 | 0.7% |
| `Intune` | 2 | 1.4% |
| `SharePoint` | 13 | 9.3% |
| `Sway` | 1 | 0.7% |
| `Teams` | 17 | 12.1% |
| **Total** | **140** | **100.0%** |

## Controls

Sorted by control id numerically, so `1.1.10` follows `1.1.9` rather than `1.1.1`.

| Control ID | Title | `automation_status` | `benchmark_audit_type` | `is_manual` | Severity | Service | Level | Policy file | Data collector ID |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.1 | Ensure Administrative accounts are cloud-only | `ready` | Automated | `false` | critical | EntraID | L1 | `1.1.1_admin_cloud_only.rego` | `entra.roles.cloud_only_admins` |
| 1.1.2 | Ensure two emergency access accounts have been defined | `manual` | Manual | `true` | high | EntraID | L1 | — | — |
| 1.1.3 | Ensure that between two and four global admins are designated | `ready` | Automated | `false` | high | EntraID | L1 | `1.1.3_global_admin_count.rego` | `entra.roles.privileged_roles` |
| 1.1.4 | Ensure administrative accounts use licenses with a reduced application footprint | `ready` | Automated | `false` | medium | EntraID | L1 | `1.1.4_admin_license_footprint.rego` | `entra.roles.admin_license_footprint` |
| 1.2.1 | Ensure that only organizationally managed/approved public groups exist | `ready` | Automated | `false` | medium | EntraID | L2 | `1.2.1_no_unmanaged_public_groups.rego` | `entra.groups.groups` |
| 1.2.2 | Ensure sign-in to shared mailboxes is blocked | `ready` | Automated | `false` | medium | Exchange | L1 | `1.2.2_shared_mailbox_signin_blocked.rego` | `exchange.mailbox.mailboxes` |
| 1.3.1 | Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)' | `ready` | Automated | `false` | medium | EntraID | L1 | `1.3.1_password_expiration.rego` | `entra.domains.password_policy` |
| 1.3.2 | Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices | `deferred` | Automated | `false` | medium | EntraID | L2 | — | `entra.conditional_access.policies` |
| 1.3.3 | Ensure 'External sharing' of calendars is not available | `not_started` | Automated | `false` | medium | Exchange | L2 | — | `exchange.organization.sharing_policy` |
| 1.3.4 | Ensure 'User owned apps and services' is restricted | `ready` | Automated | `false` | medium | EntraID | L1 | `1.3.4_user_owned_apps_restricted.rego` | `entra.applications.apps_and_services_settings` |
| 1.3.5 | Ensure internal phishing protection for Forms is enabled | `ready` | Automated | `false` | medium | Forms | L1 | `1.3.5_forms_internal_phishing_protection.rego` | `entra.applications.forms_settings` |
| 1.3.6 | Ensure the customer lockbox feature is enabled | `not_started` | Automated | `false` | medium | Exchange | L2 | — | `exchange.organization.organization_config` |
| 1.3.7 | Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web' | `ready` | Automated | `false` | medium | EntraID | L2 | `1.3.7_third_party_storage_services.rego` | `entra.applications.third_party_storage_services` |
| 1.3.8 | Ensure that Sways cannot be shared with people outside of your organization | `manual` | Manual | `true` | medium | Sway | L2 | — | — |
| 1.3.9 | Ensure shared bookings pages are restricted to select users | `not_started` | Automated | `false` | medium | Bookings | L1 | — | — |
| 2.1.1 | Ensure Safe Links for Office Applications is Enabled | `ready` | Automated | `false` | high | Defender | L2 | `2.1.1_SafeLinks_OfficeApplications_Enabled.rego` | `exchange.protection.safe_links_policy` |
| 2.1.2 | Ensure the Common Attachment Types Filter is enabled | `ready` | Automated | `false` | high | Defender | L1 | `2.1.2_Common_AttachmentTypes_Filter_Enabled.rego` | `exchange.protection.malware_filter_policy` |
| 2.1.3 | Ensure notifications for internal users sending malware is Enabled | `ready` | Automated | `false` | medium | Defender | L1 | `2.1.3_Notifications_InternalUsers_sendingMalware_Enabled.rego` | `exchange.protection.malware_filter_policy` |
| 2.1.4 | Ensure Safe Attachments policy is enabled | `ready` | Automated | `false` | high | Defender | L2 | `2.1.4_Safe_AttachementsPolicy_Enabled.rego` | `exchange.protection.safe_attachment_policy` |
| 2.1.5 | Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled | `ready` | Automated | `false` | high | Defender | L2 | `2.1.5_Safe_Attachments_SharePoint_OneDrive_MSTeams_Enabled.rego` | `exchange.protection.atp_policy_o365` |
| 2.1.6 | Ensure Exchange Online Spam Policies are set to notify administrators | `ready` | Automated | `false` | medium | Defender | L1 | `2.1.6_Exchange_OnlineSpam_Policies_Notify_Administrators.rego` | `exchange.protection.hosted_outbound_spam_filter` |
| 2.1.7 | Ensure that an anti-phishing policy has been created | `ready` | Automated | `false` | high | Defender | L2 | `2.1.7_AntiPhishing_Policy_is_created.rego` | `exchange.protection.anti_phish_policy` |
| 2.1.8 | Ensure that SPF records are published for all Exchange Domains | `ready` | Automated | `false` | high | Exchange | L1 | `2.1.8_SPF_records_published.rego` | `exchange.dns.dns_security_records` |
| 2.1.9 | Ensure that DKIM is enabled for all Exchange Online Domains | `ready` | Automated | `false` | high | Exchange | L1 | `2.1.9_DKIM_is_enabled.rego` | `exchange.authentication.dkim_signing_config` |
| 2.1.10 | Ensure DMARC Records for all Exchange Online domains are published | `ready` | Automated | `false` | high | Exchange | L1 | `2.1.10_DMARC_records_published.rego` | `exchange.dns.dns_security_records` |
| 2.1.11 | Ensure comprehensive attachment filtering is applied | `ready` | Automated | `false` | medium | Defender | L2 | `2.1.11_Comprehensive_Attachment_Filtering_Applied.rego` | `exchange.protection.malware_filter_policy` |
| 2.1.12 | Ensure the connection filter IP allow list is not used | `ready` | Automated | `false` | medium | Defender | L1 | `2.1.12_ConnectionFilter_IPAllowList_not_used.rego` | `exchange.protection.hosted_connection_filter` |
| 2.1.13 | Ensure the connection filter safe list is off | `ready` | Automated | `false` | medium | Defender | L1 | `2.1.13_Connection_Filter_SafeList_Off.rego` | `exchange.protection.hosted_connection_filter` |
| 2.1.14 | Ensure inbound anti-spam policies do not contain allowed domains | `ready` | Automated | `false` | medium | Defender | L1 | `2.1.14_Inbound_AntiSpam_Policies_DoNot_AllowedDomains.rego` | `exchange.protection.hosted_content_filter` |
| 2.1.15 | Ensure outbound anti-spam message limits are in place | `ready` | Automated | `false` | medium | Defender | L1 | `2.1.15_Outbound_AntiSpam_MessageLimits_InPlace.rego` | `exchange.protection.hosted_outbound_spam_filter` |
| 2.2.1 | Ensure emergency access account activity is monitored | `manual` | Manual | `true` | high | EntraID | L1 | — | — |
| 2.4.1 | Ensure Priority account protection is enabled and configured | `not_started` | Automated | `false` | medium | Defender | L1 | — | — |
| 2.4.2 | Ensure Priority accounts have 'Strict protection' presets applied | `not_started` | Automated | `false` | medium | Defender | L1 | — | — |
| 2.4.3 | Ensure Microsoft Defender for Cloud Apps is enabled and configured | `manual` | Manual | `true` | medium | Defender | L2 | — | — |
| 2.4.4 | Ensure Zero-hour auto purge for Microsoft Teams is on | `ready` | Automated | `false` | medium | Defender | L1 | `2.4.4_Zero_hour_AutoPurge_MSTeams_is_On.rego` | `exchange.protection.teams_protection_policy` |
| 3.1.1 | Ensure Microsoft 365 audit log search is Enabled | `ready` | Automated | `false` | high | Compliance | L1 | `3.1.1_microsoft_365_audit_log_search_enabled.rego` | `exchange.organization.admin_audit_log_config` |
| 3.2.1 | Ensure DLP policies are enabled | `blocked` | Automated | `false` | high | Compliance | L1 | — | `compliance.dlp_compliance_policy` |
| 3.2.2 | Ensure DLP policies are enabled for Microsoft Teams | `blocked` | Automated | `false` | high | Compliance | L1 | — | `compliance.dlp_compliance_policy` |
| 3.3.1 | Ensure Information Protection sensitivity label policies are published | `blocked` | Automated | `false` | high | Compliance | L1 | — | `compliance.label_policy` |
| 4.1 | Ensure devices without a compliance policy are marked 'not compliant' | `ready` | Automated | `false` | medium | Intune | L2 | `4.1_mark_unmanaged_devices_not_compliant.rego` | `entra.devices.device_management_settings` |
| 4.2 | Ensure device enrollment for personally owned devices is blocked by default | `ready` | Automated | `false` | medium | Intune | L2 | `4.2_block_personal_device_enrollment.rego` | `entra.devices.enrollment_restrictions` |
| 5.1.2.1 | Ensure 'Per-user MFA' is disabled | `manual` | Automated | `true` | medium | EntraID | L1 | — | — |
| 5.1.2.2 | Ensure third party integrated applications are not allowed | `ready` | Automated | `false` | medium | EntraID | L2 | `5.1.2.2_block_third_party_integrated_apps.rego` | `entra.policies.authorization_policy` |
| 5.1.2.3 | Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes' | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.2.3_restrict_tenant_creation.rego` | `entra.policies.authorization_policy` |
| 5.1.2.4 | Ensure access to the Entra admin center is restricted | `manual` | Manual | `true` | medium | EntraID | L1 | — | — |
| 5.1.2.5 | Ensure the option to remain signed in is hidden | `manual` | Manual | `true` | low | EntraID | L2 | — | — |
| 5.1.2.6 | Ensure 'LinkedIn account connections' is disabled | `manual` | Manual | `true` | low | EntraID | L2 | — | — |
| 5.1.3.1 | Ensure a dynamic group for guest users is created | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.3.1_dynamic_guest_group_exists.rego` | `entra.groups.groups` |
| 5.1.3.2 | Ensure users cannot create security groups | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.3.2_block_security_group_creation.rego` | `entra.policies.authorization_policy` |
| 5.1.4.1 | Ensure the ability to join devices to Entra is restricted | `ready` | Automated | `false` | medium | EntraID | L2 | `5.1.4.1_restrict_device_join.rego` | `entra.devices.device_registration_policy` |
| 5.1.4.2 | Ensure the maximum number of devices per user is limited | `not_started` | Automated | `false` | medium | EntraID | L1 | — | `entra.devices.device_management_settings` |
| 5.1.4.3 | Ensure the GA role is not added as a local administrator during Entra join | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.4.3_disable_global_admin_local_admin.rego` | `entra.devices.device_registration_policy` |
| 5.1.4.4 | Ensure local administrator assignment is limited during Entra join | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.4.4_restrict_local_admin_assignment.rego` | `entra.devices.device_registration_policy` |
| 5.1.4.5 | Ensure Local Administrator Password Solution is enabled | `ready` | Automated | `false` | high | EntraID | L1 | `5.1.4.5_enable_laps.rego` | `entra.devices.device_registration_policy` |
| 5.1.4.6 | Ensure users are restricted from recovering BitLocker keys | `ready` | Automated | `false` | medium | EntraID | L2 | `5.1.4.6_restrict_bitlocker_key_recovery.rego` | `entra.policies.authorization_policy` |
| 5.1.5.1 | Ensure user consent to apps accessing company data on their behalf is not allowed | `ready` | Automated | `false` | high | EntraID | L2 | `5.1.5.1_block_user_app_consent.rego` | `entra.policies.authorization_policy` |
| 5.1.5.2 | Ensure the admin consent workflow is enabled | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.5.2_admin_consent_workflow_enabled.rego` | `entra.policies.admin_consent_request_policy` |
| 5.1.6.1 | Ensure that collaboration invitations are sent to allowed domains only | `ready` | Automated | `false` | medium | EntraID | L2 | `5.1.6.1_restrict_collaboration_invite_domains.rego` | `entra.policies.b2b_policy` |
| 5.1.6.2 | Ensure that guest user access is restricted | `ready` | Automated | `false` | medium | EntraID | L1 | `5.1.6.2_restrict_guest_user_access.rego` | `entra.policies.authorization_policy` |
| 5.1.6.3 | Ensure guest user invitations are limited to the Guest Inviter role | `ready` | Automated | `false` | medium | EntraID | L2 | `5.1.6.3_limit_guest_invitations.rego` | `entra.policies.authorization_policy` |
| 5.1.8.1 | Ensure that password hash sync is enabled for hybrid deployments | `manual` | Manual | `true` | high | EntraID | L1 | — | — |
| 5.2.2.1 | Ensure multifactor authentication is enabled for all users in administrative roles | `deferred` | Automated | `false` | critical | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.2 | Ensure multifactor authentication is enabled for all users | `deferred` | Automated | `false` | critical | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.3 | Enable Conditional Access policies to block legacy authentication | `ready` | Automated | `false` | high | EntraID | L1 | `5.2.2.3_block_legacy_auth.rego` | `entra.conditional_access.legacy_auth_block` |
| 5.2.2.4 | Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users | `deferred` | Automated | `false` | medium | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.5 | Ensure 'Phishing-resistant MFA strength' is required for Administrators | `deferred` | Automated | `false` | high | EntraID | L2 | — | `entra.conditional_access.policies` |
| 5.2.2.6 | Enable Identity Protection user risk policies | `deferred` | Automated | `false` | high | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.7 | Enable Identity Protection sign-in risk policies | `deferred` | Automated | `false` | high | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.8 | Ensure 'sign-in risk' is blocked for medium and high risk | `deferred` | Automated | `false` | high | EntraID | L2 | — | `entra.conditional_access.policies` |
| 5.2.2.9 | Ensure a managed device is required for authentication | `deferred` | Automated | `false` | medium | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.10 | Ensure a managed device is required to register security information | `deferred` | Automated | `false` | medium | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.11 | Ensure sign-in frequency for Intune Enrollment is set to 'Every time' | `deferred` | Automated | `false` | medium | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.2.12 | Ensure the device code sign-in flow is blocked | `deferred` | Automated | `false` | medium | EntraID | L1 | — | `entra.conditional_access.policies` |
| 5.2.3.1 | Ensure Microsoft Authenticator is configured to protect against MFA fatigue | `ready` | Automated | `false` | high | EntraID | L1 | `5.2.3.1_mfa_fatigue_protection.rego` | `entra.authentication.mfa_fatigue_protection` |
| 5.2.3.2 | Ensure custom banned passwords lists are used | `ready` | Automated | `false` | medium | EntraID | L1 | `5.2.3.2_custom_banned_passwords_enabled.rego` | `entra.authentication.password_protection` |
| 5.2.3.3 | Ensure password protection is enabled for on-prem Active Directory | `ready` | Automated | `false` | medium | EntraID | L1 | `5.2.3.3_enable_on_prem_password_protection.rego` | `entra.authentication.password_protection` |
| 5.2.3.4 | Ensure all member users are 'MFA capable' | `ready` | Automated | `false` | high | EntraID | L1 | `5.2.3.4_all_members_mfa_capable.rego` | `entra.authentication.mfa_registration_report` |
| 5.2.3.5 | Ensure weak authentication methods are disabled | `ready` | Automated | `false` | medium | EntraID | L1 | `5.2.3.5_disable_weak_auth_methods.rego` | `entra.authentication.authentication_methods` |
| 5.2.3.6 | Ensure system-preferred multifactor authentication is enabled | `ready` | Automated | `false` | medium | EntraID | L1 | `5.2.3.6_enable_system_preferred_mfa.rego` | `entra.authentication.authentication_methods` |
| 5.2.3.7 | Ensure the email OTP authentication method is disabled | `ready` | Automated | `false` | medium | EntraID | L2 | `5.2.3.7_disable_email_otp.rego` | `entra.authentication.authentication_methods` |
| 5.2.4.1 | Ensure 'Self service password reset enabled' is set to 'All' | `manual` | Manual | `true` | medium | EntraID | L1 | — | — |
| 5.3.1 | Ensure 'Privileged Identity Management' is used to manage roles | `ready` | Automated | `false` | high | EntraID | L2 | `5.3.1_pim_enabled.rego` | `entra.governance.pim_role_policies` |
| 5.3.2 | Ensure 'Access reviews' for Guest Users are configured | `ready` | Automated | `false` | medium | EntraID | L1 | `5.3.2_guest_access_reviews_configured.rego` | `entra.governance.access_reviews` |
| 5.3.3 | Ensure 'Access reviews' for privileged roles are configured | `ready` | Automated | `false` | high | EntraID | L1 | `5.3.3_privileged_role_access_reviews_configured.rego` | `entra.governance.access_reviews` |
| 5.3.4 | Ensure approval is required for Global Administrator role activation | `ready` | Automated | `false` | critical | EntraID | L1 | `5.3.4_ga_activation_requires_approval.rego` | `entra.governance.pim_role_policies` |
| 5.3.5 | Ensure approval is required for Privileged Role Administrator activation | `ready` | Automated | `false` | critical | EntraID | L1 | `5.3.5_pra_activation_requires_approval.rego` | `entra.governance.pim_role_policies` |
| 6.1.1 | Ensure 'AuditDisabled' organizationally is set to 'False' | `ready` | Automated | `false` | high | Exchange | L1 | `6.1.1_audit_disabled.rego` | `exchange.organization.organization_config` |
| 6.1.2 | Ensure mailbox audit actions are configured | `ready` | Automated | `false` | medium | Exchange | L1 | `6.1.2_mailbox_audit_actions.rego` | `exchange.mailbox.mailbox_audit_actions` |
| 6.1.3 | Ensure 'AuditBypassEnabled' is not enabled on mailboxes | `ready` | Automated | `false` | medium | Exchange | L1 | `6.1.3_audit_bypass.rego` | `exchange.mailbox.mailbox_audit` |
| 6.2.1 | Ensure all forms of mail forwarding are blocked and/or disabled | `ready` | Automated | `false` | high | Exchange | L1 | `6.2.1_mail_forwarding_blocked.rego` | `exchange.transport.transport_rules` |
| 6.2.2 | Ensure mail transport rules do not whitelist specific domains | `ready` | Automated | `false` | medium | Exchange | L1 | `6.2.2_transport_whitelist.rego` | `exchange.transport.transport_rules` |
| 6.2.3 | Ensure email from external senders is identified | `ready` | Automated | `false` | medium | Exchange | L1 | `6.2.3_external_sender_tagging.rego` | `exchange.transport.external_in_outlook` |
| 6.3.1 | Ensure users installing Outlook add-ins is not allowed | `ready` | Automated | `false` | medium | Exchange | L2 | `6.3.1_outlook_addins.rego` | `exchange.mailbox.role_assignment_policy` |
| 6.5.1 | Ensure modern authentication for Exchange Online is enabled | `ready` | Automated | `false` | high | Exchange | L1 | `6.5.1_modern_auth.rego` | `exchange.organization.organization_config` |
| 6.5.2 | Ensure MailTips are enabled for end users | `ready` | Automated | `false` | low | Exchange | L1 | `6.5.2_mailtips.rego` | `exchange.organization.organization_config` |
| 6.5.3 | Ensure additional storage providers are restricted in Outlook on the web | `ready` | Automated | `false` | medium | Exchange | L2 | `6.5.3_storage_providers.rego` | `exchange.organization.owa_mailbox_policy` |
| 6.5.4 | Ensure SMTP AUTH is disabled | `ready` | Automated | `false` | medium | Exchange | L1 | `6.5.4_smtp_auth.rego` | `exchange.organization.transport_config` |
| 6.5.5 | Ensure Direct Send submissions are rejected | `ready` | Automated | `false` | medium | Exchange | L2 | `6.5.5_direct_send.rego` | `exchange.organization.organization_config` |
| 7.2.1 | Ensure modern authentication for SharePoint applications is required | `not_started` | Automated | `false` | high | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.2.2 | Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled | `not_started` | Automated | `false` | medium | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.2.3 | Ensure external content sharing is restricted | `not_started` | Automated | `false` | medium | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.2.4 | Ensure OneDrive content sharing is restricted | `not_started` | Automated | `false` | medium | SharePoint | L2 | — | `sharepoint.spo_tenant` |
| 7.2.5 | Ensure that SharePoint guest users cannot share items they don't own | `ready` | Automated | `false` | medium | SharePoint | L2 | `7.2.5_guest_resharing.rego` | `sharepoint.pnp.tenant` |
| 7.2.6 | Ensure SharePoint external sharing is restricted | `not_started` | Automated | `false` | medium | SharePoint | L2 | — | `sharepoint.spo_tenant` |
| 7.2.7 | Ensure link sharing is restricted in SharePoint and OneDrive | `not_started` | Automated | `false` | medium | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.2.8 | Ensure external sharing is restricted by security group | `not_started` | Manual | `true` | medium | SharePoint | L2 | — | `sharepoint.spo_tenant` |
| 7.2.9 | Ensure guest access to a site or OneDrive will expire automatically | `not_started` | Automated | `false` | medium | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.2.10 | Ensure reauthentication with verification code is restricted | `not_started` | Automated | `false` | medium | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.2.11 | Ensure the SharePoint default sharing link permission is set | `not_started` | Automated | `false` | medium | SharePoint | L1 | — | `sharepoint.spo_tenant` |
| 7.3.1 | Ensure Office 365 SharePoint infected files are disallowed for download | `ready` | Automated | `false` | high | SharePoint | L2 | `7.3.1_disallow_infected_file_download.rego` | `sharepoint.pnp.tenant` |
| 7.3.2 | Ensure OneDrive sync is restricted for unmanaged devices | `not_started` | Automated | `false` | medium | SharePoint | L2 | — | `sharepoint.spo_sync_client_restriction` |
| 8.1.1 | Ensure external file sharing in Teams is enabled for only approved cloud storage services | `blocked` | Automated | `false` | medium | Teams | L2 | — | — |
| 8.1.2 | Ensure users can't send emails to a channel email address | `blocked` | Automated | `false` | low | Teams | L1 | — | — |
| 8.2.1 | Ensure external domains are restricted in the Teams admin center | `blocked` | Automated | `false` | medium | Teams | L2 | — | — |
| 8.2.2 | Ensure communication with unmanaged Teams users is disabled | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.2.3 | Ensure external Teams users cannot initiate conversations | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.2.4 | Ensure the organization cannot communicate with accounts in trial Teams tenants | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.4.1 | Ensure app permission policies are configured | `manual` | Manual | `true` | medium | Teams | L1 | — | — |
| 8.5.1 | Ensure anonymous users can't join a meeting | `blocked` | Automated | `false` | medium | Teams | L2 | — | — |
| 8.5.2 | Ensure anonymous users and dial-in callers can't start a meeting | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.5.3 | Ensure only people in my org can bypass the lobby | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.5.4 | Ensure users dialing in can't bypass the lobby | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.5.5 | Ensure meeting chat does not allow anonymous users | `blocked` | Automated | `false` | medium | Teams | L2 | — | — |
| 8.5.6 | Ensure only organizers and co-organizers can present | `blocked` | Automated | `false` | low | Teams | L2 | — | — |
| 8.5.7 | Ensure external participants can't give or request control | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 8.5.8 | Ensure external meeting chat is off | `blocked` | Automated | `false` | medium | Teams | L2 | — | — |
| 8.5.9 | Ensure meeting recording is off by default | `blocked` | Automated | `false` | medium | Teams | L2 | — | — |
| 8.6.1 | Ensure users can report security concerns in Teams | `blocked` | Automated | `false` | medium | Teams | L1 | — | — |
| 9.1.1 | Ensure guest user access is restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.2 | Ensure external user invitations are restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.3 | Ensure guest access to content is restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.4 | Ensure 'Publish to web' is restricted | `blocked` | Manual | `true` | high | Fabric | L1 | — | — |
| 9.1.5 | Ensure 'Interact with and share R and Python' visuals is 'Disabled' | `blocked` | Manual | `true` | medium | Fabric | L2 | — | — |
| 9.1.6 | Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled' | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.7 | Ensure shareable links are restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.8 | Ensure enabling of external data sharing is restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.9 | Ensure 'Block ResourceKey Authentication' is 'Enabled' | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.10 | Ensure access to APIs by service principals is restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.11 | Ensure service principals cannot create and use profiles | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |
| 9.1.12 | Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted | `blocked` | Manual | `true` | medium | Fabric | L1 | — | — |

## Implementation notes

86 controls carry a note in the metadata. The note is the reason the control sits at its current `automation_status`.

| Control ID | Note |
| --- | --- |
| 1.1.2 | Organizational policy; requires human designation of accounts |
| 1.2.1 | Collector exists but control logic not defined |
| 1.2.2 | Collector and policy implemented |
| 1.3.2 | Requires CA policy coverage verification |
| 1.3.3 | Collector exists but control logic not defined |
| 1.3.8 | No API available for Sway settings |
| 1.3.9 | Need Bookings API collector |
| 2.1.8 | DNS lookup for SPF TXT records |
| 2.1.10 | DNS lookup for DMARC TXT records |
| 2.2.1 | Organizational policy; requires defining which accounts to monitor |
| 2.4.1 | Need Priority Account Protection collector |
| 2.4.2 | Need Priority Account Protection collector |
| 2.4.3 | MCAS configuration requires portal verification |
| 3.1.1 | Check UnifiedAuditLogIngestionEnabled = True |
| 3.2.1 | Collector compliance.dlp_compliance_policy is registered and a candidate policy exists at engine/policies/candidate/cis/microsoft-365-foundations/v6.0.0/3.2.1_dlp_policies_enabled.rego. Blocked: certificate-based Connect-IPPSSession has not been validated against a licensed non-production tenant, and the benchmark audit procedure for this control is UI-only with an explicitly organizational criterion. Promotion runs only through tools/policies/promote_candidate.py. |
| 3.2.2 | Collector compliance.dlp_compliance_policy is registered and a candidate policy exists at engine/policies/candidate/cis/microsoft-365-foundations/v6.0.0/3.2.2_dlp_policies_teams.rego. Blocked: certificate-based Connect-IPPSSession has not been validated against a licensed non-production tenant. Benchmark profile is E5 Level 1 only. Promotion runs only through tools/policies/promote_candidate.py. |
| 3.3.1 | Collector compliance.label_policy is registered and a candidate policy exists at engine/policies/candidate/cis/microsoft-365-foundations/v6.0.0/3.3.1_sensitivity_label_policies_published.rego. Blocked: certificate-based Connect-IPPSSession has not been validated against a licensed non-production tenant, and the benchmark states the pass decision is open to interpretation by the auditor. Promotion runs only through tools/policies/promote_candidate.py. |
| 4.1 | Collector exists but control logic not defined |
| 5.1.2.1 | Only available in beta API; not stable |
| 5.1.2.2 | Check allowedToCreateApps |
| 5.1.2.3 | Check allowedToCreateTenants |
| 5.1.2.4 | Only available via internal Azure API |
| 5.1.2.5 | Setting not exposed via Graph API |
| 5.1.2.6 | Only available via internal Azure API |
| 5.1.3.1 | Collector exists but control logic not defined |
| 5.1.3.2 | Check allowedToCreateSecurityGroups |
| 5.1.4.4 | Collector is corrected and policy is implemented |
| 5.1.4.6 | Check allowedToReadBitlockerKeysForOwnedDevice |
| 5.1.6.2 | Check guestUserRoleId |
| 5.1.6.3 | Check allowInvitesFrom |
| 5.1.8.1 | Requires on-premises AD Connect verification |
| 5.2.2.1 | Requires verification of all 15 admin roles |
| 5.2.2.2 | Requires verification of exclusions |
| 5.2.2.4 | Requires admin role verification |
| 5.2.2.5 | Requires admin role verification |
| 5.2.2.6 | Requires policy coverage verification |
| 5.2.2.7 | Requires policy coverage verification |
| 5.2.2.8 | Requires policy coverage verification |
| 5.2.2.9 | Requires policy coverage verification |
| 5.2.2.10 | Requires policy coverage verification |
| 5.2.2.11 | Requires policy coverage verification |
| 5.2.2.12 | Requires policy coverage verification |
| 5.2.3.5 | Check SMS/Voice disabled |
| 5.2.4.1 | SSPR settings not exposed via Graph API |
| 5.3.3 | Combined with pim_role_policies |
| 6.5.1 | Check OAuth2ClientProfileEnabled |
| 7.2.1 | Collector raises NotImplementedError |
| 7.2.2 | Collector raises NotImplementedError |
| 7.2.3 | Collector raises NotImplementedError |
| 7.2.4 | Collector raises NotImplementedError |
| 7.2.6 | Collector raises NotImplementedError |
| 7.2.7 | Collector raises NotImplementedError |
| 7.2.8 | Collector raises NotImplementedError; CIS says Manual but can be automated |
| 7.2.9 | Collector raises NotImplementedError |
| 7.2.10 | Collector raises NotImplementedError |
| 7.2.11 | Collector raises NotImplementedError |
| 7.3.2 | Collector exists but control logic not defined |
| 8.1.1 | Teams module AccessTokens auth not working |
| 8.1.2 | Teams module AccessTokens auth not working |
| 8.2.1 | Teams module AccessTokens auth not working |
| 8.2.2 | Teams module AccessTokens auth not working |
| 8.2.3 | Teams module AccessTokens auth not working |
| 8.2.4 | Teams module AccessTokens auth not working |
| 8.4.1 | CIS marks as Manual; also affected by ACM migration |
| 8.5.1 | Teams module AccessTokens auth not working |
| 8.5.2 | Teams module AccessTokens auth not working |
| 8.5.3 | Teams module AccessTokens auth not working |
| 8.5.4 | Teams module AccessTokens auth not working |
| 8.5.5 | Teams module AccessTokens auth not working |
| 8.5.6 | Teams module AccessTokens auth not working |
| 8.5.7 | Teams module AccessTokens auth not working |
| 8.5.8 | Teams module AccessTokens auth not working |
| 8.5.9 | Teams module AccessTokens auth not working |
| 8.6.1 | Teams module AccessTokens auth not working |
| 9.1.1 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.2 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.3 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.4 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.5 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.6 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.7 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.8 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.9 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.10 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.11 | Fabric API auth untested; CIS says Manual but can be automated |
| 9.1.12 | Fabric API auth untested; CIS says Manual but can be automated |

## Changing this document

1. Edit `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json`.
2. Run `python tools/docs/generate_control_status.py`.
3. Commit the metadata change and the regenerated document together.

CI runs `python tools/docs/generate_control_status.py --check` and fails if this file and its metadata disagree.
