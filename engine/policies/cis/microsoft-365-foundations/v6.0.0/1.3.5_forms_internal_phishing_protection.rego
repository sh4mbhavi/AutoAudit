# METADATA
# title: Ensure internal phishing protection for Forms is enabled
# description: |
#   Internal phishing protection helps prevent misuse of Microsoft Forms for
#   phishing within the organization. Enable internal phishing protection to
#   reduce the risk of credential harvesting and social engineering attacks.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.3.5
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Forms
#   requires_permissions:
#   - OrgSettings-Forms.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_1_3_5

import rego.v1

# The previous computed result put `input.collector_error` in its details. That
# key is absent from healthy evidence, so the object literal was undefined and
# the rule never fired: this control returned its default for every input it has
# ever seen, including a perfectly compliant tenant.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: Microsoft Forms settings are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean internal_phishing_protection_enabled in the Forms settings; collector errors invalidate the evidence.",
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
	is_boolean(input.internal_phishing_protection_enabled)
}

optional_settings := [
	"external_sharing_enabled",
	"external_send_form_enabled",
	"external_share_collaborating_enabled",
	"external_share_template_enabled",
	"external_share_result_enabled",
	"bing_search_enabled",
	"record_identity_by_default_enabled",
]

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": object.union(
		{"internal_phishing_protection_enabled": input.internal_phishing_protection_enabled},
		{setting: object.get(input, setting, null) | some setting in optional_settings},
	),
} if {
	valid_evidence
	compliant := input.internal_phishing_protection_enabled == true
	affected := ["Microsoft Forms internal phishing protection" | not compliant]
}

generate_message(true) := "Microsoft Forms internal phishing protection is enabled"

generate_message(false) := "Microsoft Forms internal phishing protection is not enabled"
