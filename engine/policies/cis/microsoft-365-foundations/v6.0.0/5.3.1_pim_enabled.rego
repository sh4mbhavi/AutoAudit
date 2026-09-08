# METADATA
# title: Ensure 'Privileged Identity Management' is used to manage roles
# description: Use PIM for privileged role management.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
#   description: Privileged Identity Management (conceptual)
# custom:
#   control_id: CIS-5.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - RoleManagement.Read.Directory

package cis.microsoft_365_foundations.v6_0_0.control_5_3_1

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine if PIM is enabled",
	"details": {},
}

default compliant := false

compliant if input.pim_enabled == true

msg := "PIM is enabled (role management policies present)" if compliant
msg := "PIM does not appear to be enabled (no role management policies found)" if not compliant

assessed_result := output if {
	_ = input.pim_enabled

	output := {
		"compliant": compliant,
		"message": msg,
		"affected_resources": ["privilegedIdentityManagement" | not compliant],
		"details": {
			"total_policies": input.total_policies,
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
	is_boolean(input.pim_enabled)
	derived_presence := input.total_policies > 0
	input.pim_enabled == derived_presence
	is_number(input.total_policies)
	input.total_policies >= 0
	input.total_policies == floor(input.total_policies)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
