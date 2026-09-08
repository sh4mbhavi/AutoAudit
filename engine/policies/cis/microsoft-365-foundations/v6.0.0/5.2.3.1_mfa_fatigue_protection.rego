# METADATA
# title: Ensure Microsoft Authenticator is configured to protect against MFA fatigue
# description: Configure Authenticator to prevent MFA fatigue attacks.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-number-match
#   description: Number matching (conceptual)
# custom:
#   control_id: CIS-5.2.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine Microsoft Authenticator MFA fatigue protection settings",
	"details": {},
}

compliant_value if input.number_matching_enabled == true

else := false

msg := "MFA fatigue protection is enabled (number matching required)" if input.number_matching_enabled == true

else := "MFA fatigue protection is not enabled (number matching not required)" if input.number_matching_enabled != true

else := "Unable to determine Microsoft Authenticator MFA fatigue protection settings"

assessed_result := output if {
	number_matching := input.number_matching_enabled
	app_ctx := input.display_app_information_enabled
	loc_ctx := input.display_location_information_enabled

	output := {
		"compliant": compliant_value,
		"message": msg,
		"details": {
			"state": input.state,
			"number_matching_enabled": number_matching,
			"display_app_information_enabled": app_ctx,
			"display_location_information_enabled": loc_ctx,
			"include_targets_count": count(input.include_targets),
			"exclude_targets_count": count(input.exclude_targets),
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
	is_boolean(input.number_matching_enabled)
	is_array(input.include_targets)
	is_array(input.exclude_targets)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
