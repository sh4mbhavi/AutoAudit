# METADATA
# title: Ensure guest user invitations are limited to the Guest Inviter role
# description: Limit who can invite guest users into the tenant.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get
#   description: authorizationPolicy resource type
# custom:
#   control_id: CIS-5.1.6.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine allowInvitesFrom",
	"details": {},
}

compliant_value if input.allow_invites_from == "adminsAndGuestInviters"

else := false

msg := "Guest invitations are limited to admins and Guest Inviter role (allowInvitesFrom=adminsAndGuestInviters)" if input.allow_invites_from == "adminsAndGuestInviters"

else := sprintf("Guest invitations are not sufficiently restricted (allowInvitesFrom=%v)", [input.allow_invites_from]) if {
	input.allow_invites_from != null
	input.allow_invites_from != "adminsAndGuestInviters"
}

else := "Unable to determine allowInvitesFrom" if input.allow_invites_from == null

else := "Unable to determine allowInvitesFrom"

assessed_result := out if {
	v := input.allow_invites_from

	# Expected: only admins and Guest Inviter role can invite

	out := {
		"compliant": compliant_value,
		"message": msg,
		"affected_resources": ["authorizationPolicy" | not compliant_value],
		"details": {
			"allow_invites_from": v,
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
	is_string(input.allow_invites_from)
	trim_space(input.allow_invites_from) != ""
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
