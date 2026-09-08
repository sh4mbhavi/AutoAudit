# METADATA
# title: Ensure Safe Attachments policy is enabled
# description: |
#   The Safe Attachments policy helps protect users from malware in email attachments
#   by scanning attachments for viruses, malware, and other malicious content.
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.4
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_4

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

safe_attachment_policies := object.get(input, "safe_attachment_policies", [])

policy_name(p) := name if {
	name := object.get(p, "Name", null)
	name != null
} else := identity if {
	identity := object.get(p, "Identity", null)
	identity != null
} else := "Unknown policy"

built_in_policies := [p |
	p := safe_attachment_policies[_]
	policy_name(p) == "Built-In Protection Policy"
]

has_policy := count(built_in_policies) > 0

policy := built_in_policies[0] if has_policy

else := {}

policy_identity := object.get(policy, "Identity", object.get(policy, "Name", "Unknown policy"))
policy_enable := object.get(policy, "Enable", null)
policy_action := object.get(policy, "Action", null)
policy_quarantine_tag := object.get(policy, "QuarantineTag", null)

default compliant := false

compliant if {
	has_policy
	policy_enable == true
	policy_action == "Block"
	policy_quarantine_tag == "AdminOnlyAccessPolicy"
}

assessed_result := {
	"compliant": compliant,
	"message": message,
	"affected_resources": affected_resources,
	"details": {
		"identity": policy_identity,
		"enable": policy_enable,
		"action": policy_action,
		"quarantine_tag": policy_quarantine_tag,
	},
}

message := "Safe Attachments Built-In Protection Policy is enabled, blocking threats, and correctly configured." if {
	compliant
} else := "Safe Attachments Built-In Protection Policy is disabled." if {
	has_policy
	policy_enable == false
} else := "Safe Attachments policy action is not set to 'Block'." if {
	has_policy
	policy_enable == true
	policy_action != "Block"
} else := "Safe Attachments policy does not use the 'AdminOnlyAccessPolicy' quarantine tag." if {
	has_policy
	policy_enable == true
	policy_action == "Block"
	policy_quarantine_tag != "AdminOnlyAccessPolicy"
} else := "Safe Attachments Built-In Protection Policy was not found." if {
	not has_policy
} else := "Unable to determine Safe Attachments policy configuration."

affected_resources := [] if {
	compliant
}

affected_resources := [
	sprintf("Non-compliant Safe Attachments policy: %v", [policy_identity]),
] if {
	not compliant
	has_policy
}

affected_resources := ["Safe Attachments Built-In Protection Policy not found"] if {
	not compliant
	not has_policy
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
	is_array(input.safe_attachment_policies)
	every policy in input.safe_attachment_policies { is_object(policy); is_string(policy.Name); is_boolean(policy.Enable); is_string(policy.Action); is_string(policy.QuarantineTag)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
