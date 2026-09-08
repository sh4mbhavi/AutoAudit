# METADATA
# title: Ensure modern authentication for Exchange Online is enabled
# description: |
#   Modern authentication (OAuth 2.0) provides enhanced security features
#   including MFA support and conditional access. OAuth2ClientProfileEnabled
#   must be set to True for Exchange Online.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.5.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_5_1

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

assessed_result := output if {
	oauth_enabled := input.oauth_enabled

	# Compliant when OAuth authentication is enabled
	compliant := oauth_enabled == true

	output := {
		"compliant": compliant,
		"message": generate_message(oauth_enabled),
		"affected_resources": generate_affected_resources(compliant),
		"details": {
			"oauth2_client_profile_enabled": oauth_enabled,
		},
	}
}

generate_message(oauth_enabled) := msg if {
	oauth_enabled == true
	msg := "Modern authentication (OAuth 2.0) is enabled for Exchange Online"
}

generate_message(oauth_enabled) := msg if {
	oauth_enabled == false
	msg := "Modern authentication (OAuth 2.0) is disabled for Exchange Online"
}

generate_message(oauth_enabled) := msg if {
	oauth_enabled == null
	msg := "Unable to determine modern authentication status"
}

generate_affected_resources(true) := []
generate_affected_resources(false) := ["Modern authentication is disabled"]

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
	is_boolean(input.oauth_enabled)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
