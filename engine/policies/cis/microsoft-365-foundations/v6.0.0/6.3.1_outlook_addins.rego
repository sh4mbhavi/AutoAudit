# METADATA
# title: Ensure users installing Outlook add-ins is not allowed
# description: |
#   User installation of Outlook add-ins should be restricted to prevent
#   potentially malicious add-ins from accessing mailbox data. Add-in
#   installation should be centrally managed by administrators.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_3_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: Exchange role assignment policies are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a policies_allowing_addin_install array and at least one role assignment policy. Every tenant has a default role assignment policy, so a total of zero is a failed collection rather than a compliant tenant.",
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
	is_array(input.policies_allowing_addin_install)
	is_number(input.total_policies)
	input.total_policies > 0
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant, count(input.policies_allowing_addin_install)),
	"affected_resources": [object.get(policy, "name", null) | some policy in input.policies_allowing_addin_install],
	"details": {
		"total_policies": input.total_policies,
		"policies_allowing_addins": count(input.policies_allowing_addin_install),
		"policy_details": input.policies_allowing_addin_install,
	},
} if {
	valid_evidence
	compliant := count(input.policies_allowing_addin_install) == 0
}

generate_message(true, _) := "No role assignment policies allow user add-in installation"

generate_message(false, allowing) := sprintf(
	"%d role assignment policy(ies) allow user add-in installation",
	[allowing],
)
