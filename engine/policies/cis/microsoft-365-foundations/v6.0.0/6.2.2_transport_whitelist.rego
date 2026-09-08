# METADATA
# title: Ensure mail transport rules do not whitelist specific domains
# description: |
#   Transport rules that whitelist specific domains by setting SCL to -1 or
#   bypassing spam filtering based on sender domain create security risks.
#   These rules can be exploited by attackers using spoofed domains.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.2.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_2_2

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

assessed_result := output if {
	whitelist_rules := input.whitelist_rules

	# Filter to only enabled whitelist rules that set SCL to -1
	enabled_whitelist_rules := [r |
		some r in whitelist_rules
		r.state == "Enabled"
		r.set_scl == -1
	]

	# Compliant when no enabled whitelist rules exist
	compliant := count(enabled_whitelist_rules) == 0

	output := {
		"compliant": compliant,
		"message": generate_message(enabled_whitelist_rules),
		"affected_resources": [r.name | some r in enabled_whitelist_rules],
		"details": {
			"total_transport_rules": input.total_rules,
			"whitelist_rules_count": count(whitelist_rules),
			"enabled_whitelist_rules": count(enabled_whitelist_rules),
			"whitelist_rules": [{"name": r.name, "domains": r.sender_domain} | some r in enabled_whitelist_rules],
		},
	}
}

generate_message(enabled_whitelist_rules) := msg if {
	count(enabled_whitelist_rules) == 0
	msg := "No enabled transport rules whitelist specific domains"
}

generate_message(enabled_whitelist_rules) := msg if {
	count(enabled_whitelist_rules) > 0
	msg := sprintf("%d enabled transport rule(s) whitelist specific domains (SCL = -1)", [count(enabled_whitelist_rules)])
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
	is_array(input.whitelist_rules)
	is_number(input.total_rules)
	input.total_rules >= 0
	input.total_rules == floor(input.total_rules)
	count(input.whitelist_rules) <= input.total_rules
	every rule in input.whitelist_rules { is_object(rule); is_string(rule.state); is_number(rule.set_scl); is_string(rule.name); is_array(rule.sender_domain)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
