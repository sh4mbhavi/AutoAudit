# METADATA
# title: Ensure Local Administrator Password Solution is enabled
# description: Ensure Microsoft Entra Local Administrator Password Solution (LAPS) is enabled
# custom:
#   control_id: CIS-5.1.4.5
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#     - Policy.Read.DeviceConfiguration

package cis.microsoft_365_foundations.v6_0_0.control_5_1_4_5

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the LAPS setting is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean localAdminPassword.isEnabled on the device registration policy; collector errors invalidate the evidence.",
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
	is_boolean(input.laps_enabled)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"laps_enabled": input.laps_enabled,
		"local_admin_password_settings": object.get(input, "local_admin_password_settings", null),
	},
} if {
	valid_evidence
	compliant := input.laps_enabled == true
	affected := ["deviceRegistrationPolicy" | not compliant]
}

generate_message(true) := "Microsoft Entra Local Administrator Password Solution (LAPS) is enabled"

generate_message(false) := "Microsoft Entra Local Administrator Password Solution (LAPS) is not enabled"
