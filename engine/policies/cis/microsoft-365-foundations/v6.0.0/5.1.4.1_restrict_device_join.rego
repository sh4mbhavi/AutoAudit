# METADATA
# title: Ensure the ability to join devices to Entra is restricted
# description: Restrict device join to authorized users.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/devices/device-join
#   description: Device join settings (conceptual)
# custom:
#   control_id: CIS-5.1.4.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.DeviceConfiguration

package cis.microsoft_365_foundations.v6_0_0.control_5_1_4_1

import rego.v1

# Graph reports azureADJoin.allowedUsers as one of "all", "selected" or "none".
# The previous rule read "not all" as compliant and read *everything else*,
# including an absent setting, as non-compliant.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: device join restrictions are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a string azureADJoin.allowedUsers on the device registration policy; collector errors invalidate the evidence.",
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
	is_string(input.azure_ad_join_allowed_users)
	input.azure_ad_join_allowed_users != ""
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"allowed_users": input.azure_ad_join_allowed_users,
		"allowed_groups": object.get(input, "azure_ad_join_allowed_groups", null),
		"user_device_quota": object.get(input, "user_device_quota", null),
	},
} if {
	valid_evidence
	compliant := lower(input.azure_ad_join_allowed_users) != "all"
	affected := ["deviceRegistrationPolicy" | not compliant]
}

generate_message(true) := "Device join is restricted to selected users or groups"

generate_message(false) := "Device join is allowed to everyone (allowedUsers=all)"
