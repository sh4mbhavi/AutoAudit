# METADATA
# title: Ensure that between two and four global admins are designated
# description: |
#   Maintain between 2-4 global administrators to ensure operational continuity
#   while minimizing attack surface. Having fewer than 2 creates a single point
#   of failure, while having more than 4 unnecessarily expands the attack surface
#   and increases the risk of credential compromise.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.1.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v3.1.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - RoleManagement.Read.Directory
#   - User.Read.All

package cis.microsoft_365_foundations.v3_1_0.control_1_1_3

import rego.v1

recommended_min := 2

recommended_max := 4

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the tenant's Global Administrator count is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a numeric global_admin_count and a global_admins array; collector errors invalidate the evidence.",
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
	is_number(input.global_admin_count)
	is_array(input.global_admins)
}

result := {
	"compliant": compliant,
	"message": generate_message(input.global_admin_count),
	"affected_resources": affected,
	"details": {
		"global_admin_count": input.global_admin_count,
		"recommended_min": recommended_min,
		"recommended_max": recommended_max,
	},
} if {
	valid_evidence
	compliant := in_recommended_range
	affected := array.concat([], [account | some account in input.global_admins; not compliant])
}

default in_recommended_range := false

in_recommended_range if {
	input.global_admin_count >= recommended_min
	input.global_admin_count <= recommended_max
}

generate_message(count_value) := sprintf(
	"Only %d global admin(s) found. Minimum %d recommended for continuity.",
	[count_value, recommended_min],
) if {
	count_value < recommended_min
}

generate_message(count_value) := sprintf(
	"%d global admins found. Maximum %d recommended to minimize attack surface.",
	[count_value, recommended_max],
) if {
	count_value > recommended_max
}

generate_message(count_value) := sprintf(
	"%d global admins configured (within recommended range of %d-%d)",
	[count_value, recommended_min, recommended_max],
) if {
	count_value >= recommended_min
	count_value <= recommended_max
}
