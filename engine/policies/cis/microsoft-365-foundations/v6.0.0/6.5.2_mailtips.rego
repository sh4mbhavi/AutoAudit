# METADATA
# title: Ensure MailTips are enabled for end users
# description: |
#   MailTips provide informational messages to users as they compose emails,
#   helping prevent accidental data disclosure and improving email hygiene.
#   Key settings include tips for external recipients and large audiences.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.5.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: low
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_5_2

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Exchange organization configuration is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected boolean MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled and MailTipsGroupMetricsEnabled, and a numeric MailTipsLargeAudienceThreshold, on the organization configuration; collector errors invalidate the evidence.",
	},
}

required_tips := {
	"MailTipsAllTipsEnabled",
	"MailTipsExternalRecipientsTipsEnabled",
	"MailTipsGroupMetricsEnabled",
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

config := object.get(input, "organization_config", null)

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_object(config)
	every field in required_tips {
		is_boolean(object.get(config, field, null))
	}
	is_number(object.get(config, "MailTipsLargeAudienceThreshold", null))
}

disabled_tips := [field |
	some field in required_tips
	config[field] != true
]

insecure_settings := array.concat(
	disabled_tips,
	["MailTipsLargeAudienceThreshold" | config.MailTipsLargeAudienceThreshold <= 0],
)

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": [sprintf("%s is not configured for end users", [field]) | some field in insecure_settings],
	"details": {
		"mail_tips_all_tips_enabled": config.MailTipsAllTipsEnabled,
		"mail_tips_external_recipients_enabled": config.MailTipsExternalRecipientsTipsEnabled,
		"mail_tips_group_metrics_enabled": config.MailTipsGroupMetricsEnabled,
		"mail_tips_large_audience_threshold": config.MailTipsLargeAudienceThreshold,
		"insecure_settings": insecure_settings,
	},
} if {
	valid_evidence
	compliant := count(insecure_settings) == 0
}

generate_message(true) := "MailTips are properly configured for end users"

generate_message(false) := "MailTips are not fully configured for end users"
