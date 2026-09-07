# METADATA
# title: Ensure that SharePoint guest users cannot share items they don't own
# description: |
#   Restricting guest users from resharing content they do not own helps
#   prevent unintended sharing of SharePoint and OneDrive resources.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-7.2.5
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: SharePoint
#   data_collector_id: sharepoint.pnp.tenant
#   requires_permissions:
#   - SharePoint.Admin

package cis.microsoft_365_foundations.v6_0_0.control_7_2_5

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the SharePoint tenant setting is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean PreventExternalUsersFromResharing on the SharePoint tenant; collector errors invalidate the evidence.",
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
	is_boolean(input.prevent_external_users_from_resharing)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"prevent_external_users_from_resharing": input.prevent_external_users_from_resharing},
} if {
	valid_evidence
	compliant := input.prevent_external_users_from_resharing == true
	affected := ["SharePoint tenant: guest resharing" | not compliant]
}

generate_message(true) := "SharePoint guest users cannot reshare items they do not own"

generate_message(false) := "SharePoint guest users can reshare items they do not own"
