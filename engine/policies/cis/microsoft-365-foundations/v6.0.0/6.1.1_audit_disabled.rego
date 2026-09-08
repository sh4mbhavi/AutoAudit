# METADATA
# title: Ensure 'AuditDisabled' organizationally is set to 'False'
# description: |
#   Mailbox auditing is enabled by default for all organizations. Ensure that
#   organization-wide auditing has not been explicitly disabled, as this would
#   prevent the capture of critical mailbox activities for security investigations.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.1.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_1_1

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

assessed_result := output if {
	audit_disabled := input.audit_disabled

	# Compliant when AuditDisabled is False (auditing is enabled)
	compliant := audit_disabled == false

	output := {
		"compliant": compliant,
		"message": generate_message(audit_disabled),
		"affected_resources": generate_affected_resources(compliant),
		"details": {
			"audit_disabled": audit_disabled,
		},
	}
}

generate_message(audit_disabled) := msg if {
	audit_disabled == false
	msg := "Organization-wide mailbox auditing is enabled (AuditDisabled = False)"
}

generate_message(audit_disabled) := msg if {
	audit_disabled == true
	msg := "Organization-wide mailbox auditing is disabled (AuditDisabled = True)"
}

generate_message(audit_disabled) := msg if {
	audit_disabled == null
	msg := "Unable to determine AuditDisabled status"
}

generate_affected_resources(true) := []
generate_affected_resources(false) := ["Organization mailbox auditing is disabled"]

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
	is_boolean(input.audit_disabled)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
