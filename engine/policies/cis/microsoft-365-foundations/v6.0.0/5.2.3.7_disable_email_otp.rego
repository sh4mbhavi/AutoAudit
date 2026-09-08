# METADATA
# title: Ensure the email OTP authentication method is disabled
# description: Disable email OTP authentication.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy
#   description: Authentication methods policy
# custom:
#   control_id: CIS-5.2.3.7
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine Email OTP authentication method status",
	"details": {},
}

default compliant := false

compliant if input.email_otp_enabled == false

msg := "Email OTP authentication method is disabled" if compliant
msg := "Email OTP authentication method is enabled" if input.email_otp_enabled == true
msg := "Unable to determine Email OTP authentication method status" if input.email_otp_enabled == null

assessed_result := output if {
	email := input.email_otp_enabled

	output := {
		"compliant": compliant,
		"message": msg,
		"details": {
			"email_otp_enabled": email,
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
	is_boolean(input.email_otp_enabled)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
