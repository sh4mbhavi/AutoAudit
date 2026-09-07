# METADATA
# title: Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled
# description: |
#   Safe Attachments for SharePoint, OneDrive, and Microsoft Teams scans these services for malicious files.
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.5
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_5

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: Safe Attachments settings are unavailable or incomplete",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected an ATP policy with boolean EnableATPForSPOTeamsODB, EnableSafeDocs and AllowSafeDocsOpen values; collector errors invalidate the evidence.",
	},
}

required_settings := {
	"EnableATPForSPOTeamsODB": true,
	"EnableSafeDocs": true,
	"AllowSafeDocsOpen": false,
}

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_object(input.atp_policy)
	not has_collector_error(input.atp_policy)
	every field, _ in required_settings {
		is_boolean(input.atp_policy[field])
	}
}

# Each insecure property independently violates this control.
insecure_settings := [field |
	some field, expected in required_settings
	input.atp_policy[field] != expected
]

result := {
	"compliant": compliant,
	"message": message_text,
	"affected_resources": affected,
	"details": {
		"policies_evaluated": [input.atp_policy],
		"insecure_settings": insecure_settings,
	},
} if {
	valid_evidence
	compliant := count(insecure_settings) == 0
	message_text := generate_message(compliant)
	affected := [object.get(input.atp_policy, "Name", "AtpPolicyForO365") | count(insecure_settings) > 0]
}

generate_message(true) := "Safe Attachments for SharePoint, OneDrive, and Teams is configured securely"
generate_message(false) := "Safe Attachments for SharePoint, OneDrive, or Teams is not configured securely"

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}
