# METADATA
# title: Ensure that collaboration invitations are sent to allowed domains only
# description: Restrict external collaboration to allowed domains/tenants.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-overview
#   description: Cross-tenant access settings
# custom:
#   control_id: CIS-5.1.6.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine cross-tenant access restrictions",
	"details": {},
}

partners := object.get(input, "partners", [])
partners_count := object.get(input, "partners_count", 0)

default_inbound_access_type := access_type if {
	inbound := object.get(input, "b2b_collaboration_inbound", {})
	users_and_groups := object.get(inbound, "usersAndGroups", {})
	access_type := object.get(users_and_groups, "accessType", "")
}

compliant_value if {
	partners_count > 0
	default_inbound_access_type == "blocked"
} else := false

msg := sprintf("Cross-tenant collaboration is restricted by default (partners=%d, accessType=%v)", [partners_count, default_inbound_access_type]) if compliant_value

else := sprintf("Cross-tenant collaboration is not sufficiently restricted (partners=%d, accessType=%v)", [partners_count, default_inbound_access_type])

# Heuristic evaluation:
# - Consider compliant when the tenant has explicit partner configuration (partners_count > 0)
#   and the default inbound B2B collaboration access is not wide-open.
assessed_result := output if {
	output := {
		"compliant": compliant_value,
		"message": msg,
		"details": {
			"partners_count": partners_count,
			"partner_tenant_ids": [p.tenantId | some p in partners; p.tenantId != null],
			"default_inbound_access_type": default_inbound_access_type,
		},
	}
}

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
	is_array(input.partners)
	is_number(input.partners_count)
	input.partners_count >= 0
	input.partners_count == floor(input.partners_count)
	input.partners_count == count(input.partners)
	every partner in input.partners { is_object(partner); is_string(partner.tenantId); trim_space(partner.tenantId) != ""}
	input.b2b_collaboration_inbound.usersAndGroups.accessType in {"allowed", "blocked"}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
