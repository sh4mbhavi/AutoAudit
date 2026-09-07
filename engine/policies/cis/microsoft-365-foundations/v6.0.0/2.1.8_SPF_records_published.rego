# METADATA
# title: Ensure that SPF records are published for all Exchange Domains
# description: |
#   A corresponding Sender Policy Framework (SPF) record
#   should be created for each domain that will be configured in Exchange.
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.8
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Domain.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_2_1_8

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the tenant's domain records are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a non-empty domains array of domain objects. The collector returns an empty list when the DNS lookup itself returns nothing, and a tenant always has at least one accepted domain, so an empty list is a failed collection rather than a compliant tenant.",
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
	is_array(input.domains)
	count(input.domains) > 0
	every domain in input.domains {
		is_object(domain)
	}
}

spf_issues := [domain |
	some domain in input.domains
	not spf_record_published(domain)
]

spf_record_published(domain) if {
	record := object.get(domain, "spf_record", null)
	is_string(record)
	trimmed := trim(record, " \t\r\n")
	trimmed != ""
	startswith(lower(trimmed), "v=spf1")
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant, spf_issues),
	"affected_resources": [object.get(domain, "domain", null) | some domain in spf_issues],
	"details": {
		"total_domains": count(input.domains),
		"non_compliant_domains_count": count(spf_issues),
		"non_compliant_domains": spf_issues,
	},
} if {
	valid_evidence
	compliant := count(spf_issues) == 0
}

generate_message(true, _) := "All Exchange domains have SPF records published."

generate_message(false, issues) := sprintf(
	"%d domain(s) do not have a valid SPF record (v=spf1...) published",
	[count(issues)],
)
