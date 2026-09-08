# METADATA
# title: Ensure custom banned passwords lists are used
# description: Configure custom banned password list.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad
#   description: Password protection and banned passwords (conceptual)
# custom:
#   control_id: CIS-5.2.3.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - GroupSettings.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine custom banned password list configuration",
	"details": {},
}

compliant_value if input.banned_password_list_enabled == true

else := false

msg := "Custom banned password list is enabled" if input.banned_password_list_enabled == true

else := "Custom banned password list is not enabled" if input.banned_password_list_enabled != true

else := "Unable to determine custom banned password list configuration"

banned_list_present if {
	input.banned_password_list != null
	input.banned_password_list != ""
}

else := false

assessed_result := output if {
	enabled := input.banned_password_list_enabled
	_ = input.banned_password_list

	output := {
		"compliant": compliant_value,
		"message": msg,
		"details": {
			"banned_password_list_enabled": enabled,
			"banned_password_list_present": banned_list_present,
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
	is_boolean(input.banned_password_list_enabled)
	is_string(input.banned_password_list)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
