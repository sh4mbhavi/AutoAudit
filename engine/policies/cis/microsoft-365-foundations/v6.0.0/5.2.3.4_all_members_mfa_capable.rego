# METADATA
# title: Ensure all member users are 'MFA capable'
# description: Ensure all users have registered MFA methods.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/reportroot-list-authenticationmethods-userregistrationdetails
#   description: Authentication methods user registration details report
# custom:
#   control_id: CIS-5.2.3.4
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - AuditLog.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine MFA capability across users",
	"details": {},
}

default compliant := false

compliant if {
	input.total_users > 0
	input.mfa_capable_count == input.total_users
}

msg := "All users are MFA capable" if compliant
msg := sprintf("%d of %d users are MFA capable", [input.mfa_capable_count, input.total_users]) if not compliant

# Prefer the actual users who are not MFA capable when the registration report
# carries per-user detail; a compliant tenant yields []. Count-only evidence
# (no registration_details) yields [] because no identity is available to name.
not_mfa_capable_users := [id |
	some user in object.get(input, "registration_details", [])
	user.isMfaCapable == false
	id := object.get(user, "userPrincipalName", object.get(user, "id", null))
	id != null
]

assessed_result := output if {
	total := input.total_users
	capable := input.mfa_capable_count

	output := {
		"compliant": compliant,
		"message": msg,
		"affected_resources": not_mfa_capable_users,
		"details": {
			"total_users": total,
			"mfa_capable_count": capable,
			"mfa_registered_count": input.mfa_registered_count,
			"mfa_not_registered_count": input.mfa_not_registered_count,
			"mfa_registration_percentage": input.mfa_registration_percentage,
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
	is_number(input.total_users)
	input.total_users >= 0
	input.total_users == floor(input.total_users)
	input.total_users > 0
	is_number(input.mfa_capable_count)
	input.mfa_capable_count >= 0
	input.mfa_capable_count == floor(input.mfa_capable_count)
	input.mfa_capable_count <= input.total_users
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
