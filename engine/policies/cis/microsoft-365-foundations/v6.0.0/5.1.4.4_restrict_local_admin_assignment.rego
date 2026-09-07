# METADATA
# title: Ensure local administrator assignment is limited during Entra join
# description: Ensure users registering Microsoft Entra joined devices are not automatically granted local administrator privileges.
# custom:
#   control_id: CIS-5.1.4.4
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.DeviceConfiguration

package cis.microsoft_365_foundations.v6_0_0.control_5_1_4_4

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: Entra join local administrator assignment is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected azureADJoin.localAdmins.registeringUsers['@odata.type'] to be one of the three known device registration membership types; collector errors invalidate the evidence.",
	},
}

known_membership_types := {
	"#microsoft.graph.enumeratedDeviceRegistrationMembership",
	"#microsoft.graph.noDeviceRegistrationMembership",
	"#microsoft.graph.allDeviceRegistrationMembership",
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
	input.local_admin_registering_users_type in known_membership_types
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"local_admin_registering_users_type": input.local_admin_registering_users_type,
		"global_admins_enabled": object.get(input, "enable_global_admins", null),
	},
} if {
	valid_evidence
	compliant := input.local_admin_registering_users_type != "#microsoft.graph.allDeviceRegistrationMembership"
	affected := ["deviceRegistrationPolicy" | not compliant]
}

generate_message(true) := "Local administrator assignment during Entra join is limited"

generate_message(false) := "All users registering Entra joined devices are assigned local administrator rights"
