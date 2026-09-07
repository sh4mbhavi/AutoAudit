# METADATA
# title: Ensure the GA role is not added as a local administrator during Entra join
# description: Prevent Global Administrators from automatically receiving local administrator access on Entra-joined devices.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/devices/assign-local-admin
#   description: Microsoft Entra joined device local administrator management
# custom:
#   control_id: CIS-5.1.4.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.DeviceConfiguration

package cis.microsoft_365_foundations.v6_0_0.control_5_1_4_3

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: local administrator settings for Global Administrators are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean azureADJoin.localAdmins.enableGlobalAdmins on the device registration policy; collector errors invalidate the evidence.",
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
	is_boolean(input.global_admins_as_local_admin)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"enable_global_admins": input.global_admins_as_local_admin},
} if {
	valid_evidence
	compliant := input.global_admins_as_local_admin == false
	affected := ["deviceRegistrationPolicy" | not compliant]
}

generate_message(true) := "Global Administrators are not automatically added as local administrators"

generate_message(false) := "Global Administrators are automatically added as local administrators"
