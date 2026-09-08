# METADATA
# title: Enable Conditional Access policies to block legacy authentication
# description: |
#   Legacy authentication protocols do not support MFA and are commonly exploited
#   in password spray and credential stuffing attacks. Implement Conditional Access
#   policies to block these protocols for all users and all applications.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-5.2.2.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Evaluation failed: unable to retrieve Conditional Access policy data",
	"details": {},
}

# Main evaluation rule
assessed_result := output if {
	policies := get_array(input, "conditional_access_policies")

	blocking_policies := [p | some p in policies; is_legacy_auth_block_policy(p)]
	compliant := count(blocking_policies) > 0

	msg := build_message(compliant, blocking_policies)
	affected := build_affected(compliant, blocking_policies)

	output := {
		"compliant": compliant,
		"message": msg,
		"affected_resources": affected,
		"details": {
			"total_policies": count(policies),
			"legacy_auth_block_policies": count(blocking_policies),
			"blocking_policy_names": [p.display_name | some p in blocking_policies],
		},
	}
}

# Helper to get array with default
get_array(obj, key) := value if {
	value := obj[key]
} else := []

is_legacy_auth_block_policy(policy) if {
	policy.state == "enabled"
	policy.targets_all_users == true
	policy.targets_all_apps == true
	policy.blocks_legacy_auth == true
	policy.grant_control == "block"
}

build_message(true, blocking_policies) := msg if {
	msg := sprintf("Found %d Conditional Access policy(ies) blocking legacy authentication", [count(blocking_policies)])
}

build_message(false, _) := "No Conditional Access policy found that blocks legacy authentication for all users and applications"

build_affected(true, _) := []
build_affected(false, _) := ["No legacy auth blocking policy configured"]

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
	is_array(input.conditional_access_policies)
	every policy in input.conditional_access_policies { is_object(policy); is_string(policy.state); is_boolean(policy.targets_all_users); is_boolean(policy.targets_all_apps); is_boolean(policy.blocks_legacy_auth); is_string(policy.grant_control)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
