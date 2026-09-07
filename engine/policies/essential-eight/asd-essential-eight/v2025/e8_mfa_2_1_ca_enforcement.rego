# METADATA
# title: Essential Eight - MFA required for privileged users and Microsoft 365 services
# description: |
#   Checks whether Conditional Access policies exist that require Multi-Factor
#   Authentication (MFA) for privileged users and for access to Microsoft 365
#   services, as required by the Essential Eight MFA mitigation strategy.
#
#   This control addresses the enforcement gap between the CIS MFA controls
#   (which check authentication capability and configuration) and the Essential
#   Eight requirement, which requires MFA to be applied in specific access
#   scenarios.
#
#   A compliant result requires at least one enabled Conditional Access policy
#   that: (1) requires MFA as a grant control, (2) covers privileged users or
#   all users, and (3) applies to all cloud apps (covering M365 services).
#
#   Research reference: 26T1-SEC-EG-001, 26T1-SEC-EG-003
#
# related_resources:
# - ref: https://www.cyber.gov.au/resources-business-and-government/essential-cybersecurity/essential-eight
#   description: Australian Cyber Security Centre - Essential Eight
# - ref: https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
#   description: Microsoft Entra ID - Conditional Access overview
# - ref: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy
#   description: Conditional Access policies - Microsoft Graph API
# custom:
#   control_id: E8-MFA-2.1
#   framework: essential-eight
#   benchmark: asd-essential-eight
#   version: v2025
#   severity: critical
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All
#   - RoleManagement.Read.Directory

package essential_eight.asd_essential_eight.v2025.control_e8_mfa_2_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate MFA enforcement: Conditional Access policy data is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected numeric total_policies and enabled_policies_count and both policies_requiring_mfa_for_* arrays; collector errors invalidate the evidence.",
	},
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

required_counts := ["total_policies", "enabled_policies_count", "mfa_policies_count", "privileged_roles_count"]

required_lists := ["policies_requiring_mfa_for_all_users", "policies_requiring_mfa_for_privileged_roles", "all_mfa_policy_names"]

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	every field in required_counts {
		is_number(object.get(input, field, null))
	}
	every field in required_lists {
		is_array(object.get(input, field, null))
	}
}

# Policies that require MFA, cover all M365 services and target all users. This
# is the strongest form of enforcement: it covers privileged users implicitly.
mfa_all_users_all_apps := [policy |
	some policy in input.policies_requiring_mfa_for_all_users
	object.get(policy, "targets_all_apps", null) == true
]

# Policies that require MFA, cover all M365 services and target privileged
# directory roles specifically. This is the Essential Eight baseline.
mfa_privileged_roles_all_apps := [policy |
	some policy in input.policies_requiring_mfa_for_privileged_roles
	object.get(policy, "targets_all_apps", null) == true
]

qualifying_policies := array.concat(mfa_all_users_all_apps, mfa_privileged_roles_all_apps)

# Exclusions do not fail the control on their own; they are surfaced for an
# assessor to review.
policies_with_exclusions := [policy |
	some policy in qualifying_policies
	object.get(policy, "has_exclusions", null) == true
]

result := {
	"compliant": compliant,
	"message": generate_message(count(qualifying_policies), count(policies_with_exclusions)),
	"affected_resources": affected,
	"details": {
		"total_ca_policies": input.total_policies,
		"enabled_ca_policies": input.enabled_policies_count,
		"mfa_policies_count": input.mfa_policies_count,
		"qualifying_policies_count": count(qualifying_policies),
		"qualifying_policy_names": [object.get(policy, "display_name", null) | some policy in qualifying_policies],
		"policies_with_exclusions": [object.get(policy, "display_name", null) | some policy in policies_with_exclusions],
		"exclusions_detected": count(policies_with_exclusions) > 0,
		"privileged_roles_in_tenant": input.privileged_roles_count,
		"all_mfa_policy_names": input.all_mfa_policy_names,
	},
} if {
	valid_evidence
	compliant := count(qualifying_policies) > 0
	affected := ["Conditional Access: no policy enforces MFA across all Microsoft 365 services" | not compliant]
}

generate_message(qualifying, excluded) := sprintf(
	"MFA is enforced via %d Conditional Access policy(ies) covering privileged users and Microsoft 365 services with no exclusions detected",
	[qualifying],
) if {
	qualifying > 0
	excluded == 0
}

generate_message(qualifying, excluded) := sprintf(
	"MFA is enforced via %d Conditional Access policy(ies) covering privileged users and Microsoft 365 services, but %d policy(ies) contain exclusions that should be reviewed",
	[qualifying, excluded],
) if {
	qualifying > 0
	excluded > 0
}

generate_message(qualifying, _) := "No enabled Conditional Access policy found that requires MFA for privileged users or all users and covers Microsoft 365 services (all cloud apps)" if {
	qualifying == 0
}
