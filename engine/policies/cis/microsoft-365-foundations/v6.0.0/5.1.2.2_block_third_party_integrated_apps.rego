# METADATA
# title: Ensure third party integrated applications are not allowed
# description: Block third-party application registration.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-5.1.2.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine allowedToCreateApps",
	"details": {},
}

compliant_value if input.allowed_to_create_apps == false

else := false

msg := "Third party integrated applications are not allowed (allowedToCreateApps=false)" if input.allowed_to_create_apps == false

else := "Third party integrated applications are allowed (allowedToCreateApps=true)" if input.allowed_to_create_apps == true

else := "Unable to determine allowedToCreateApps"

assessed_result := out if {
	value := input.allowed_to_create_apps

	out := {
		"compliant": compliant_value,
		"message": msg,
		"details": {
			"allowed_to_create_apps": value,
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
	is_boolean(input.allowed_to_create_apps)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
