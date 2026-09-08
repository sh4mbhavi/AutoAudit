# METADATA
# title: Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'
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
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Domain.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_1_3_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: domain password policy data is unavailable or incomplete",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected identified domains with boolean is_managed values and at least one managed domain with valid password_validity_days; collector errors invalidate the evidence.",
	},
}

# 2147483647 = "never expires" (max int32)
never_expires := 2147483647

result := output if {
	valid_evidence
	domains := input.domains
	managed_domains := [d | some d in domains; d.is_managed == true]
	non_compliant := [d | some d in managed_domains; d.password_validity_days != never_expires]

	output := {
		"compliant": count(non_compliant) == 0,
		"message": generate_message(managed_domains, non_compliant),
		"affected_resources": [d.domain_name | some d in non_compliant],
		"details": {
			"total_managed_domains": count(managed_domains),
			"compliant_domains": count(managed_domains) - count(non_compliant),
			"non_compliant_domains": count(non_compliant),
			"domains": [{"name": d.domain_name, "password_validity_days": d.password_validity_days} | some d in managed_domains],
		},
	}
}

generate_message(managed_domains, non_compliant) := msg if {
	count(non_compliant) == 0
	msg := sprintf("All %d managed domain(s) have password expiration disabled", [count(managed_domains)])
}

generate_message(managed_domains, non_compliant) := msg if {
	count(non_compliant) > 0
	msg := sprintf("%d of %d managed domain(s) have password expiration enabled", [count(non_compliant), count(managed_domains)])
}

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_array(input.domains)
	count(input.domains) > 0
	every domain in input.domains {
		valid_domain(domain)
	}

	# No managed domains means no essential password-policy evidence to assess.
	some domain in input.domains
	domain.is_managed == true
}

valid_domain(domain) if {
	is_object(domain)
	not has_collector_error(domain)
	is_string(domain.domain_name)
	trim_space(domain.domain_name) != ""
	is_boolean(domain.is_managed)
	valid_password_evidence(domain)
}

# Password settings do not apply to federated domains and can be null.
valid_password_evidence(domain) if {
	domain.is_managed == false
}

valid_password_evidence(domain) if {
	domain.is_managed == true
	is_number(domain.password_validity_days)
	domain.password_validity_days == floor(domain.password_validity_days)
	domain.password_validity_days >= 1
	domain.password_validity_days <= never_expires
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}
