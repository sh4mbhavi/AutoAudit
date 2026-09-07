# METADATA
# title: Ensure the connection filter safe list is off
# description: |
#   In Microsoft 365 organizations with Exchange Online mailboxes or standalone
#   Exchange Online Protection organizations without Exchange Online mailboxes
#   connection filtering and the default connection filter policy identify good or bad
#   source email servers by IP addresses. The key components of the default connection
#   filter policy are IP Allow List, IP Block List and Safe list.
#   The safe list is a pre-configured allow list that is dynamically updated by Microsoft.
#   The recommended safe list state is: Off or False
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.13
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Defender
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_13

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Exchange hosted connection filter policy is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected the Exchange hosted connection filter's default_policy object. The collector emits an empty list and null settings when the cmdlet returns nothing, so an absent default policy is a failed collection rather than a compliant tenant. EnableSafeList must be a boolean.",
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
	is_object(input.default_policy)
	is_boolean(input.enable_safe_list)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"EnableSafeList": input.enable_safe_list},
} if {
	valid_evidence
	compliant := input.enable_safe_list == false
	affected := ["HostedConnectionFilterPolicy" | not compliant]
}

generate_message(true) := "EnableSafeList is False for the Exchange Online hosted connection filter"

generate_message(false) := "EnableSafeList is not False for the Exchange Online hosted connection filter"
