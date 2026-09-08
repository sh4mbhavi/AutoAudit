# METADATA
# title: Ensure user consent to apps accessing company data on their behalf is not allowed
# description: Block user consent to applications for company data.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
#   description: Configure user consent settings in Entra ID
# custom:
#   control_id: CIS-5.1.5.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine user consent settings (permissionGrantPoliciesAssigned)",
	"details": {},
}

compliant if {
	perms := input.default_user_role_permissions
	assigned := perms.permissionGrantPoliciesAssigned
	assigned == []
}

compliant_value if compliant

else := false

assigned_count := count(assigned) if {
	perms := input.default_user_role_permissions
	assigned := perms.permissionGrantPoliciesAssigned
	assigned != null
} else := null

msg := "User consent to apps is disabled (permissionGrantPoliciesAssigned is empty)" if {
	compliant
} else := sprintf(
	"User consent to apps is enabled/restricted (permissionGrantPoliciesAssigned has %d entries)",
	[assigned_count],
) if {
	perms := input.default_user_role_permissions
	assigned := perms.permissionGrantPoliciesAssigned
	assigned != null
	not compliant
} else := "Unable to determine user consent settings (permissionGrantPoliciesAssigned missing)"

# According to Graph, user consent is controlled by authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned.
# CIS intent: user consent should be disabled (empty list).
assessed_result := out if {
	perms := input.default_user_role_permissions
	assigned := perms.permissionGrantPoliciesAssigned

	out := {
		"compliant": compliant_value,
		"message": msg,
		"affected_resources": ["authorizationPolicy" | not compliant_value],
		"details": {
			"permission_grant_policies_assigned": assigned,
			"permission_grant_policies_assigned_count": assigned_count,
		},
	}
}

# Typed, complete collector evidence is required before an assessed result is emitted.
# Kept in this module so captured-source evaluation remains self-contained.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: required evidence is missing, malformed, or incomplete",
	"affected_resources": [],
	"details": {"evaluation_status": "indeterminate"},
}

result := assessed_result if evidence_complete

evidence_complete if {
	is_object(input)
	not evidence_error
	is_array(input.default_user_role_permissions.permissionGrantPoliciesAssigned)
	every value in input.default_user_role_permissions.permissionGrantPoliciesAssigned { is_string(value) }
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
