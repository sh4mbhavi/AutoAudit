# METADATA
# title: Ensure the connection filter IP allow list is not used
# description: |
#   In Microsoft 365 organizations with Exchange Online mailboxes or standalone
#   Exchange Online Protection organizations without Exchange Online mailboxes
#   connection filtering and the default connection filter policy identify good or
#   bad source email servers by IP addresses. The key components of the default connection
#   filter policy are IP Allow List, IP Block List and Safe list.
#   The recommended state is IP Allow List empty or undefined.
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.12
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Defender
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_12

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Exchange hosted connection filter policy is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected the Exchange hosted connection filter's default_policy object. The collector emits an empty list and null settings when the cmdlet returns nothing, so an absent default policy is a failed collection rather than a compliant tenant. IPAllowList must be an array.",
	},
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

ip_allow_list := object.get(input, "ip_allow_list", null)

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_object(input.default_policy)
	is_array(ip_allow_list)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"IPAllowList": ip_allow_list},
} if {
	valid_evidence
	compliant := count(ip_allow_list) == 0
	affected := ["HostedConnectionFilterPolicy" | not compliant]
}

generate_message(true) := "IPAllowList is empty in the Exchange Online hosted connection filter"

generate_message(false) := "IPAllowList is not empty in the Exchange Online hosted connection filter"
