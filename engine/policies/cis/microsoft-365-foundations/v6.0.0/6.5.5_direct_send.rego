# METADATA
# title: Ensure Direct Send submissions are rejected
# description: |
#   Direct Send allows anonymous SMTP connections to send email as the
#   organization. This can be exploited for phishing and spoofing attacks.
#   Configure transport settings to reject unauthenticated direct send.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.5.5
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_5_5

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

assessed_result := output if {
	reject_direct_send := input.reject_direct_send

	# Compliant when RejectDirectSend is true
	compliant := reject_direct_send == true

	output := {
		"compliant": compliant,
		"message": generate_message(reject_direct_send),
		"affected_resources": generate_affected_resources(compliant),
		"details": {
			"reject_direct_send": reject_direct_send,
		},
	}
}

generate_message(reject_direct_send) := msg if {
	reject_direct_send == true
	msg := "Direct Send submissions are rejected"
}

generate_message(reject_direct_send) := msg if {
	reject_direct_send == false
	msg := "Direct Send submissions are allowed (RejectDirectSend is False)"
}

generate_message(reject_direct_send) := msg if {
	reject_direct_send == null
	msg := "Unable to determine Direct Send status"
}

generate_affected_resources(true) := []
generate_affected_resources(false) := ["Direct Send submissions are allowed"]

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
	is_boolean(input.reject_direct_send)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
