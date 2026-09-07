# METADATA
# title: Ensure password expiration policy is set to never expire
# description: |
#   Configure password policies to never expire. NIST and Microsoft recommend
#   this approach when MFA is enabled, as forced password rotation leads to
#   weaker passwords without providing security benefits.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v4.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Domain.Read.All

package cis.microsoft_365_foundations.v4_0_0.control_1_3_1

import rego.v1

# 2147483647 = "never expires" (max int32)
never_expires := 2147483647

# The comprehensions below iterate input.domains. An absent key made every
# comprehension empty, so `count(non_compliant) == 0` held and the control
# reported "All 0 managed domain(s) have password expiration disabled" -- a pass
# built out of no evidence at all.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: the tenant's domains are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a non-empty domains array carrying is_managed and password_validity_days; collector errors invalidate the evidence.",
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
		is_boolean(object.get(domain, "is_managed", null))
	}
	every domain in managed_domains {
		is_number(object.get(domain, "password_validity_days", null))
	}
}

managed_domains := [domain |
	some domain in input.domains
	domain.is_managed == true
]

non_compliant := [domain |
	some domain in managed_domains
	domain.password_validity_days != never_expires
]

result := {
	"compliant": compliant,
	"message": generate_message(count(managed_domains), count(non_compliant)),
	"affected_resources": [object.get(domain, "domain_name", null) | some domain in non_compliant],
	"details": {
		"total_managed_domains": count(managed_domains),
		"compliant_domains": count(managed_domains) - count(non_compliant),
		"non_compliant_domains": count(non_compliant),
		"domains": [{
			"name": object.get(domain, "domain_name", null),
			"password_validity_days": domain.password_validity_days,
		} |
			some domain in managed_domains
		],
	},
} if {
	valid_evidence
	compliant := count(non_compliant) == 0
}

generate_message(managed, failing) := sprintf(
	"All %d managed domain(s) have password expiration disabled",
	[managed],
) if {
	failing == 0
}

generate_message(managed, failing) := sprintf(
	"%d of %d managed domain(s) have password expiration enabled",
	[failing, managed],
) if {
	failing > 0
}
