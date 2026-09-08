# METADATA
# title: Ensure 'AuditBypassEnabled' is not enabled on mailboxes
# description: |
#   Mailbox audit bypass allows specified accounts to perform actions without
#   generating audit entries. No mailboxes should have AuditBypassEnabled set
#   to True, as this creates blind spots in security monitoring.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.1.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_1_3

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

assessed_result := output if {
	accounts_with_bypass := input.accounts_with_bypass_enabled
	bypass_count := input.bypass_count

	# Compliant when no accounts have audit bypass enabled
	compliant := bypass_count == 0

	output := {
		"compliant": compliant,
		"message": generate_message(bypass_count),
		"affected_resources": [a.Name | some a in accounts_with_bypass],
		"details": {
			"accounts_with_bypass_enabled": bypass_count,
			"bypassed_accounts": [a.Name | some a in accounts_with_bypass],
		},
	}
}

generate_message(bypass_count) := msg if {
	bypass_count == 0
	msg := "No accounts have mailbox audit bypass enabled"
}

generate_message(bypass_count) := msg if {
	bypass_count > 0
	msg := sprintf("%d account(s) have mailbox audit bypass enabled", [bypass_count])
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
	is_array(input.accounts_with_bypass_enabled)
	is_number(input.bypass_count)
	input.bypass_count >= 0
	input.bypass_count == floor(input.bypass_count)
	input.bypass_count == count(input.accounts_with_bypass_enabled)
	every account in input.accounts_with_bypass_enabled { is_object(account); is_string(account.Name)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
