# METADATA
# title: Ensure DMARC Records for all Exchange Online domains are published
# description: |
#   DMARC, or Domain-based Message Authentication, Reporting, and Conformance,
#   assists recipient mail systems in determining the appropriate action to take when
#   messages from a domain fail to meet SPF or DKIM authentication criteria.
#   Ensure that the record exists that has the following flags defined either
#   p=quarantine OR p=reject.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.10
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Domain.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_2_1_10

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

dmarc_issues := [domain |
	some domain in input.domains
	not dmarc_record_published(domain)
]

dmarc_record_published(domain) if {
	record := object.get(domain, "dmarc_record", null)
	is_string(record)
	dmarc := lower(record)
	startswith(dmarc, "v=dmarc1")
	some tag in [trim_space(part) | some part in split(dmarc, ";")]
	startswith(tag, "p=")
	trim_space(substring(tag, 2, -1)) in {"quarantine", "reject"}
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant, dmarc_issues),
	"affected_resources": [object.get(domain, "domain", null) | some domain in dmarc_issues],
	"details": {
		"total_domains": count(input.domains),
		"non_compliant_domains_count": count(dmarc_issues),
		"non_compliant_domains": dmarc_issues,
	},
} if {
	valid_evidence
	compliant := count(dmarc_issues) == 0
}

generate_message(true, _) := "All Exchange domains have DMARC records published."

generate_message(false, issues) := sprintf(
	"%d domain(s) do not meet DMARC enforcement requirements (missing record or p policy is not quarantine/reject)",
	[count(issues)],
)
