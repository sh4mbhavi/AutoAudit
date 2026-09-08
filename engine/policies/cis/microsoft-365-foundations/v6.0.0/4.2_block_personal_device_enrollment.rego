# METADATA
# title: Ensure device enrollment for personally owned devices is blocked by default
# description: Block personal device enrollment by default.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-4.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Intune
#   requires_permissions:
#   - DeviceManagementServiceConfig.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_4_2

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine personal device enrollment restriction",
	"details": {},
}

compliant_value if input.personal_devices_blocked == true

else := false

msg := "Personal device enrollment is blocked by default" if input.personal_devices_blocked == true

else := "Personal device enrollment is not blocked by default" if input.personal_devices_blocked == false

else := "Unable to determine personal device enrollment restriction"

assessed_result := output if {
	blocked := input.personal_devices_blocked

	output := {
		"compliant": compliant_value,
		"message": msg,
		"affected_resources": ["deviceEnrollmentConfiguration" | not compliant_value],
		"details": {
			"personal_devices_blocked": blocked,
			"total_configurations": input.total_configurations,
			"platform_restrictions_count": count(input.platform_restrictions),
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
	is_boolean(input.personal_devices_blocked)
	is_number(input.total_configurations)
	input.total_configurations >= 0
	input.total_configurations == floor(input.total_configurations)
	is_array(input.platform_restrictions)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
