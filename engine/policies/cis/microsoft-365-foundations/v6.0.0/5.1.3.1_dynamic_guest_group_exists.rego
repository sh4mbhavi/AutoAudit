# METADATA
# title: Ensure a dynamic group for guest users is created
# description: Create a dynamic group to manage guest users.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership
#   description: Dynamic membership rules (conceptual)
# custom:
#   control_id: CIS-5.1.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Group.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_3_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the tenant's dynamic groups are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a dynamic_groups array of group objects; collector errors invalidate the evidence.",
	},
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_array(input.dynamic_groups)
	every group in input.dynamic_groups {
		is_object(group)
	}
}

# A membership rule targeting the Guest user type, however it is spelled.
is_guest_rule(rule) if {
	is_string(rule)
	contains(lower(rule), "guest")
}

matching_groups := [group |
	some group in input.dynamic_groups
	is_guest_rule(object.get(group, "membershipRule", null))
]

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"dynamic_groups_count": count(input.dynamic_groups),
		"matching_groups": [{
			"id": object.get(group, "id", null),
			"displayName": object.get(group, "displayName", null),
			"membershipRule": object.get(group, "membershipRule", null),
		} |
			some group in matching_groups
		],
	},
} if {
	valid_evidence
	compliant := count(matching_groups) > 0
	affected := ["directory/groups" | not compliant]
}

generate_message(true) := "At least one dynamic group targets guest users"

generate_message(false) := "No dynamic guest user group exists"
