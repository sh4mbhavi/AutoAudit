# METADATA
# title: Ensure additional storage providers are restricted in Outlook on the web
# description: |
#   Additional storage providers (Dropbox, Google Drive, Box, etc.) in Outlook
#   on the web can lead to data leakage if not properly controlled. Restrict
#   third-party storage providers to maintain data within corporate boundaries.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-6.5.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_6_5_3

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: OWA mailbox policies are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a policies_with_external_storage array and at least one OWA mailbox policy. Every tenant has a default OWA mailbox policy, so a total of zero is a failed collection rather than a compliant tenant.",
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
	is_array(input.policies_with_external_storage)
	is_number(input.total_policies)
	input.total_policies > 0
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant, count(input.policies_with_external_storage), input.total_policies),
	"affected_resources": input.policies_with_external_storage,
	"details": {
		"total_owa_policies": input.total_policies,
		"policies_with_external_storage": count(input.policies_with_external_storage),
		"policy_names": input.policies_with_external_storage,
	},
} if {
	valid_evidence
	compliant := count(input.policies_with_external_storage) == 0
}

generate_message(true, _, total) := sprintf(
	"All %d OWA mailbox policy(ies) restrict additional storage providers",
	[total],
)

generate_message(false, allowing, total) := sprintf(
	"%d of %d OWA mailbox policy(ies) allow additional storage providers",
	[allowing, total],
)
