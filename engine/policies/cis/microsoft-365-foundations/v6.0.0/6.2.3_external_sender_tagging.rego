# METADATA
# title: Ensure email from external senders is identified
# description: |
#   External sender identification helps users identify potentially malicious
#   emails from outside the organization. This setting adds visual indicators
#   to emails received from external sources.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.2.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_2_3

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

assessed_result := output if {
	enabled := input.enabled
	allowed_senders := input.allowed_senders

	# Compliant when external tagging is enabled
	compliant := enabled == true

	output := {
		"compliant": compliant,
		"message": generate_message(enabled, allowed_senders),
		"affected_resources": generate_affected_resources(compliant),
		"details": {
			"external_tagging_enabled": enabled,
			"allowed_senders_count": count(allowed_senders),
			"allowed_senders": allowed_senders,
		},
	}
}

generate_message(enabled, allowed_senders) := msg if {
	enabled == true
	count(allowed_senders) == 0
	msg := "External sender tagging is enabled with no exceptions"
}

generate_message(enabled, allowed_senders) := msg if {
	enabled == true
	count(allowed_senders) > 0
	msg := sprintf("External sender tagging is enabled with %d exception(s)", [count(allowed_senders)])
}

generate_message(enabled, _) := msg if {
	enabled == false
	msg := "External sender tagging is disabled"
}

generate_message(enabled, _) := msg if {
	enabled == null
	msg := "Unable to determine external sender tagging status"
}

generate_affected_resources(true) := []
generate_affected_resources(false) := ["External sender tagging is not enabled"]

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
	is_boolean(input.enabled)
	is_array(input.allowed_senders)
	every value in input.allowed_senders { is_string(value) }
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
