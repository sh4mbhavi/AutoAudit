# METADATA
# title: Ensure Win32 API calls from Office macros are blocked
# description: Ensure the Attack Surface Reduction rule blocking Win32 API calls from Office macros is enabled in Block mode.
# related_resources:
# - ref: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
#   description: ASD Essential Eight Maturity Model
# custom:
#   control_id: E8-MAC-2.1
#   framework: essential-eight
#   benchmark: asd-essential-eight
#   version: v2025
#   severity: high
#   service: Intune
#   maturity_level: ML2
#   requires_permissions:
#   - DeviceManagementConfiguration.Read.All

package essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Win32 API macro blocking rule state is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a string win32_api_rule_state from the attack surface reduction rules; collector errors invalidate the evidence.",
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
	is_string(input.win32_api_rule_state)
	input.win32_api_rule_state != ""
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant, input.win32_api_rule_state),
	"affected_resources": affected,
	"details": {
		"win32_api_rule_state": input.win32_api_rule_state,
		"win32_api_rule_found": object.get(input, "win32_api_rule_found", null),
		"source": object.get(input, "source", null),
		"policy_name": object.get(input, "policy_name", null),
	},
} if {
	valid_evidence
	compliant := lower(input.win32_api_rule_state) == "block"
	affected := [object.get(input, "policy_name", "Attack surface reduction rules") | not compliant]
}

generate_message(true, _) := "Win32 API calls from Office macros are blocked in Block mode"

generate_message(false, state) := sprintf(
	"Win32 API macro blocking is not compliant. Current state is '%s'; Essential Eight requires Block mode.",
	[state],
)
