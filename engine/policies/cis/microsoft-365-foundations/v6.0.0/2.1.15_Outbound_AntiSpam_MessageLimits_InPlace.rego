# METADATA
# title: Ensure outbound anti-spam message limits are in place
# description: |
#   The default outbound anti-spam policy in Microsoft Defender automatically applies
#   to all users and is designed to detect and limit suspicious email-sending behavior.
#   The recommended state is:
#    • External: Restrict sending to external recipients (per hour) - 500
#    • Internal: Restrict sending to internal recipients (per hour) - 1000
#    • Daily: Maximum recipient limit per day - 1000
#    • Action: Over limit action - Restrict the user from sending mail
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.15
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Defender
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_15

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Exchange outbound spam filter policy is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected the outbound spam filter's default_policy object carrying numeric recipient limits, a string ActionWhenThresholdReached and an array NotifyOutboundSpamRecipients; collector errors invalidate the evidence.",
	},
}

# CIS recommends capping the per-hour and per-day recipient limits and blocking
# the sender once the threshold is reached. The previous rule compared
# NotifyOutboundSpamRecipients for equality against a hard-coded example address,
# so every tenant with its own notification address failed; the requirement is
# that a recipient is configured at all.
recipient_limits := {
	"RecipientLimitExternalPerHour": 500,
	"RecipientLimitInternalPerHour": 1000,
	"RecipientLimitPerDay": 1000,
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

policy := object.get(input, "default_policy", null)

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_object(policy)
	every field, _ in recipient_limits {
		is_number(object.get(policy, field, null))
	}
	is_string(object.get(policy, "ActionWhenThresholdReached", null))
	is_array(object.get(policy, "NotifyOutboundSpamRecipients", null))
}

insecure_settings := array.concat(
	[field |
		some field, maximum in recipient_limits
		policy[field] > maximum
	],
	array.concat(
		["ActionWhenThresholdReached" | policy.ActionWhenThresholdReached != "BlockUser"],
		["NotifyOutboundSpamRecipients" | count(policy.NotifyOutboundSpamRecipients) == 0],
	),
)

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"RecipientLimitExternalPerHour": policy.RecipientLimitExternalPerHour,
		"RecipientLimitInternalPerHour": policy.RecipientLimitInternalPerHour,
		"RecipientLimitPerDay": policy.RecipientLimitPerDay,
		"ActionWhenThresholdReached": policy.ActionWhenThresholdReached,
		"NotifyOutboundSpamRecipients": policy.NotifyOutboundSpamRecipients,
		"maximum_recipient_limits": recipient_limits,
		"insecure_settings": insecure_settings,
	},
} if {
	valid_evidence
	compliant := count(insecure_settings) == 0
	affected := ["HostedOutboundSpamFilterPolicy" | not compliant]
}

generate_message(true) := "Outbound spam filter recipient limits, block action and notification recipients are in place"

generate_message(false) := "Outbound spam filter policy settings are misconfigured or incomplete"
