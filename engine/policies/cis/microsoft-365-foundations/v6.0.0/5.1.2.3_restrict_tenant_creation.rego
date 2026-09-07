# METADATA
# title: Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
# description: Prevent non-admin users from creating tenants.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-5.1.2.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_2_3

import rego.v1

# `allowedToCreateTenants` is read with .get() by the collector, so an absent
# permission arrives as null. Null is not "false": it is the tenant not having
# told us, and recording it as a pass or as an ordinary failure both misreport.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: allowedToCreateTenants is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean defaultUserRolePermissions.allowedToCreateTenants on the authorization policy; collector errors invalidate the evidence.",
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
	is_boolean(input.allowed_to_create_tenants)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"allowed_to_create_tenants": input.allowed_to_create_tenants},
} if {
	valid_evidence
	compliant := input.allowed_to_create_tenants == false
	affected := ["authorizationPolicy" | not compliant]
}

generate_message(true) := "Non-admin users cannot create tenants (allowedToCreateTenants=false)"

generate_message(false) := "Non-admin users can create tenants (allowedToCreateTenants=true)"
