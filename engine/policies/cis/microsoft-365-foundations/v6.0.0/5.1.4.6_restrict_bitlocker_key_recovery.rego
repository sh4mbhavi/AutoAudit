# METADATA
# title: Ensure users are restricted from recovering BitLocker keys
# description: Restrict BitLocker key recovery to admins.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-5.1.4.6
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_4_6

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: allowedToReadBitlockerKeysForOwnedDevice is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice on the authorization policy; collector errors invalidate the evidence.",
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
	is_boolean(input.allowed_to_read_bitlocker_keys_for_owned_device)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"allowed_to_read_bitlocker_keys_for_owned_device": input.allowed_to_read_bitlocker_keys_for_owned_device},
} if {
	valid_evidence
	compliant := input.allowed_to_read_bitlocker_keys_for_owned_device == false
	affected := ["authorizationPolicy" | not compliant]
}

generate_message(true) := "Users are restricted from recovering BitLocker keys (allowedToReadBitlockerKeysForOwnedDevice=false)"

generate_message(false) := "Users can recover BitLocker keys (allowedToReadBitlockerKeysForOwnedDevice=true)"
