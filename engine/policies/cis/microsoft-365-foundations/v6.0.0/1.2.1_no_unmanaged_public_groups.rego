# METADATA
# title: Ensure that only organizationally managed/approved public groups exist
# description: Public groups should be reviewed and managed by the organization.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.2.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Group.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_1_2_1

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine public group configuration",
	"details": {},
}

publics := object.get(input, "public_groups", [])

compliant_value if count(publics) == 0

else := false

msg := "No public groups exist" if compliant_value

else := sprintf("%d public group(s) exist and require organizational approval", [count(publics)])

# This is a best-effort automated check.
# We treat any Public groups as requiring review and fail the control so it remains actionable.
assessed_result := output if {
	output := {
		"compliant": compliant_value,
		"message": msg,
		"affected_resources": [g.id | some g in publics],
		"details": {
			"total_groups": input.total_groups,
			"public_groups_count": count(publics),
			"public_groups": [{"id": g.id, "displayName": g.displayName} | some g in publics],
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
	is_number(input.total_groups)
	input.total_groups >= 0
	input.total_groups == floor(input.total_groups)
	is_array(input.public_groups)
	count(input.public_groups) <= input.total_groups
	every group in input.public_groups { is_object(group); is_string(group.id); is_string(group.displayName)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
