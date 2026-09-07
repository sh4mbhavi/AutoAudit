# METADATA
# title: Ensure Conditional Access policies block legacy authentication
# description: |
#   Legacy authentication protocols (IMAP, SMTP, POP3, older Office clients)
#   do not support MFA and are commonly exploited in password spray and
#   credential stuffing attacks. Block these protocols via Conditional Access.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-5.2.2.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v4.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: Conditional Access policies are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a conditional_access_policies array of policy objects; collector errors invalidate the evidence. An empty array is a real answer -- the tenant has no Conditional Access policies -- and is a finding.",
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
	is_array(input.conditional_access_policies)
	every policy in input.conditional_access_policies {
		is_object(policy)
	}
}

# A policy blocks legacy authentication only when it is enabled and applies to
# every user and every application.
is_legacy_auth_block_policy(policy) if {
	policy.state == "enabled"
	policy.targets_all_users == true
	policy.targets_all_apps == true
	policy.blocks_legacy_auth == true
	policy.grant_control == "block"
}

blocking_policies := [policy |
	some policy in input.conditional_access_policies
	is_legacy_auth_block_policy(policy)
]

result := {
	"compliant": compliant,
	"message": generate_message(count(blocking_policies)),
	"affected_resources": affected,
	"details": {
		"total_policies": count(input.conditional_access_policies),
		"legacy_auth_block_policies": count(blocking_policies),
		"blocking_policy_names": [object.get(policy, "display_name", null) | some policy in blocking_policies],
	},
} if {
	valid_evidence
	compliant := count(blocking_policies) > 0
	affected := ["Conditional Access: no policy blocks legacy authentication" | not compliant]
}

generate_message(blocking) := sprintf(
	"Found %d Conditional Access policy(ies) blocking legacy authentication",
	[blocking],
) if {
	blocking > 0
}

generate_message(blocking) := "No Conditional Access policy found that blocks legacy authentication for all users and applications" if {
	blocking == 0
}
