# METADATA
# title: Ensure that DKIM is enabled for all Exchange Online Domains
# description: |
#     DKIM is one of the trio of authentication methods (SPF, DKIM, and DMARC) that help
#     prevent attackers from sending messages that look like they come from your domain.
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.9
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_9

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: DKIM signing configuration is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected both domains_with_dkim_enabled and domains_with_dkim_disabled arrays, covering at least one domain between them; collector errors invalidate the evidence.",
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
	is_array(input.domains_with_dkim_enabled)
	is_array(input.domains_with_dkim_disabled)

	# Neither list carrying a single domain means nothing was collected, not
	# that the tenant has no domains.
	count(input.domains_with_dkim_enabled) + count(input.domains_with_dkim_disabled) > 0
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": input.domains_with_dkim_disabled,
	"details": {
		"dkim_signing_enabled": compliant,
		"domains_with_dkim_enabled": input.domains_with_dkim_enabled,
		"domains_with_dkim_disabled": input.domains_with_dkim_disabled,
	},
} if {
	valid_evidence
	compliant := count(input.domains_with_dkim_disabled) == 0
}

generate_message(true) := "DKIM signing is enabled for Exchange Online domains"

generate_message(false) := "DKIM signing is disabled for one or more Exchange Online domains"
