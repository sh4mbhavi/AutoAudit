# METADATA
# title: Ensure weak authentication methods are disabled
# description: Disable SMS and voice authentication methods.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy
#   description: Authentication methods policy
# custom:
#   control_id: CIS-5.2.3.5
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine SMS/Voice authentication method status",
	"details": {},
}

default compliant := false

compliant if {
	input.sms_enabled == false
	input.voice_enabled == false
}

msg := "Weak authentication methods (SMS, Voice) are disabled" if compliant
msg := sprintf("Weak authentication methods enabled (sms=%v, voice=%v)", [input.sms_enabled, input.voice_enabled]) if not compliant

assessed_result := output if {
	sms := input.sms_enabled
	voice := input.voice_enabled

	output := {
		"compliant": compliant,
		"message": msg,
		"affected_resources": ["authenticationMethodsPolicy" | not compliant],
		"details": {
			"sms_enabled": sms,
			"voice_enabled": voice,
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
	is_boolean(input.sms_enabled)
	is_boolean(input.voice_enabled)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
