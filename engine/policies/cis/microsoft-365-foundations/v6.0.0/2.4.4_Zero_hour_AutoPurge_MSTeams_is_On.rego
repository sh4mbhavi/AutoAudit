# METADATA
# title: Ensure Zero-hour auto purge for Microsoft Teams is on
# description: |
#  Zero-hour auto purge is a protection feature that retroactively detects
#  and neutralizes malware and high-confidence phishing. When ZAP for Teams protection
#  blocks a message, the message is blocked for everyone in the chat.
#  The initial block happens right after delivery, but ZAP occurs up to 48 hours after delivery.
#  
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.4.4
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_4_4

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: Zero-hour auto purge settings for Microsoft Teams are unavailable or incomplete",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"ZeroHourAutoPurgeEnabled": null,
		"reason": "Expected a boolean zap_enabled or teams_protection_policy.ZapEnabled value; collector errors invalidate the evidence.",
	},
}

# Prefer the collector's normalized value when present, including explicit null.
zap_enabled := input.zap_enabled if {
	"zap_enabled" in object.keys(input)
} else := input.teams_protection_policy.ZapEnabled

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	not has_collector_error(object.get(input, "teams_protection_policy", {}))
	is_boolean(zap_enabled)
}

result := {
	"compliant": zap_enabled,
	"message": generate_message(zap_enabled),
	"affected_resources": generate_affected_resources(zap_enabled),
	"details": {
		"ZeroHourAutoPurgeEnabled": zap_enabled,
	},
} if {
	valid_evidence
}

generate_message(true) := "Zero-hour auto purge is enabled for Microsoft Teams"
generate_message(false) := "Zero-hour auto purge is not enabled for Microsoft Teams"

generate_affected_resources(true) := []
generate_affected_resources(false) := ["TeamsProtectionPolicy"]

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}
