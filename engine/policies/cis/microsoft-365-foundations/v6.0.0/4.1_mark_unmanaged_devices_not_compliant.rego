# METADATA
# title: Ensure devices without a compliance policy are marked 'not compliant'
# description: Mark devices without compliance policy as non-compliant.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/mem/intune/protect/actions-for-noncompliance
#   description: Intune actions for noncompliance (conceptual)
# custom:
#   control_id: CIS-4.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Intune
#   requires_permissions:
#   - DeviceManagementConfiguration.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_4_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: Intune compliance defaults are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected boolean secureByDefault and isScheduledActionEnabled on the device management settings; collector errors invalidate the evidence.",
	},
}

required_settings := {
	"secure_by_default": true,
	"is_scheduled_action_enabled": true,
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
	every field, _ in required_settings {
		is_boolean(input[field])
	}
}

# Each setting independently violates this control.
insecure_settings := [field |
	some field, expected in required_settings
	input[field] != expected
]

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"secure_by_default": input.secure_by_default,
		"is_scheduled_action_enabled": input.is_scheduled_action_enabled,
		"device_compliance_checkin_threshold_days": object.get(input, "device_compliance_on_boarded", null),
		"insecure_settings": insecure_settings,
	},
} if {
	valid_evidence
	compliant := count(insecure_settings) == 0
	affected := ["deviceManagementSettings" | not compliant]
}

generate_message(true) := "Devices without a compliance policy are treated as not compliant (secureByDefault and scheduled actions enabled)"

generate_message(false) := "Intune compliance defaults are not sufficiently strict"
