# METADATA
# title: Ensure that guest user access is restricted
# description: Restrict guest user access permissions in Entra ID.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions
#   description: Restrict guest access permissions
# custom:
#   control_id: CIS-5.1.6.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine guestUserRoleId",
	"details": {},
}

# Known guestUserRoleId values (Microsoft docs):
# - Same as members: a0b1b346-4d3e-4e8b-98f8-753987be4970 (NOT compliant)
# - Limited access (default): 10dae51f-b6af-4016-8d66-8c2a99b929b3 (compliant)
# - Most restrictive: 2af84b1e-32c8-42b7-82bc-daa82404023b (compliant)

same_as_member := "a0b1b346-4d3e-4e8b-98f8-753987be4970"
limited := "10dae51f-b6af-4016-8d66-8c2a99b929b3"
restricted := "2af84b1e-32c8-42b7-82bc-daa82404023b"

ok if input.guest_user_role_id == limited
ok if input.guest_user_role_id == restricted

compliant_value if ok

else := false

msg := "Guest user access is restricted" if ok

else := "Guest user access is NOT restricted (guests have member-like permissions)" if input.guest_user_role_id == same_as_member

else := "Unable to determine guestUserRoleId" if input.guest_user_role_id == null

else := sprintf("Guest user access is NOT restricted (guestUserRoleId=%v)", [input.guest_user_role_id])

assessed_result := out if {
	role_id := input.guest_user_role_id

	out := {
		"compliant": compliant_value,
		"message": msg,
		"details": {
			"guest_user_role_id": role_id,
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
	is_string(input.guest_user_role_id)
	trim_space(input.guest_user_role_id) != ""
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
