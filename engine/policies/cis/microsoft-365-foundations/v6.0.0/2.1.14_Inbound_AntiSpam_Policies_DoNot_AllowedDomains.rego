# METADATA
# title: Ensure inbound anti-spam policies do not contain allowed domains
# description: |
#   Anti-spam protection is a feature of Exchange Online that utilizes policies
#   to help to reduce the amount of junk email bulk and phishing emails a mailbox receives.
#   These policies contain lists to allow or block specific senders or domains.
#    • The allowed senders list
#    • The allowed domains list
#    • The blocked senders list
#    • The blocked domains list
#   The recommended state is: Do not define any Allowed domains
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.14
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Defender
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_14

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Exchange hosted content filter policy is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected the Exchange hosted content filter's default_policy object and an AllowedSenderDomains array. The collector emits an empty list when the cmdlet returns nothing, so an absent default policy is a failed collection rather than a compliant tenant.",
	},
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

allowed_sender_domains := object.get(input, "allowed_sender_domains", null)

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_object(input.default_policy)
	is_array(allowed_sender_domains)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"AllowedSenderDomains": allowed_sender_domains},
} if {
	valid_evidence
	compliant := count(allowed_sender_domains) == 0
	affected := ["HostedContentFilterPolicy" | not compliant]
}

generate_message(true) := "AllowedSenderDomains is empty for the inbound anti-spam policy"

generate_message(false) := "AllowedSenderDomains is defined for the inbound anti-spam policy"
