# METADATA
# title: Ensure Administrative accounts are cloud-only
# description: |
#   Administrative accounts should not be synced from on-premises Active Directory.
#   Cloud-only accounts reduce the attack surface by not being tied to on-premises
#   infrastructure, preventing lateral movement from compromised on-prem environments.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.1.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v3.1.0
#   severity: critical
#   service: EntraID
#   requires_permissions:
#   - User.Read.All
#   - RoleManagement.Read.Directory

package cis.microsoft_365_foundations.v3_1_0.control_1_1_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: administrative account sync status is unavailable or incomplete",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a non-empty admin_accounts array with account identities and boolean on_premises_sync_enabled values; collector errors invalidate the evidence.",
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
	is_array(input.admin_accounts)

	# No administrative accounts at all is a failed collection: a tenant cannot
	# exist without one.
	count(input.admin_accounts) > 0
	every account in input.admin_accounts {
		is_object(account)
		is_boolean(object.get(account, "on_premises_sync_enabled", null))
	}
}

synced_admins := [account |
	some account in input.admin_accounts
	account.on_premises_sync_enabled == true
]

result := {
	"compliant": compliant,
	"message": generate_message(count(synced_admins), count(input.admin_accounts)),
	"affected_resources": [object.get(account, "userPrincipalName", null) | some account in synced_admins],
	"details": {
		"total_admin_accounts": count(input.admin_accounts),
		"synced_admin_count": count(synced_admins),
		"cloud_only_admin_count": count(input.admin_accounts) - count(synced_admins),
	},
} if {
	valid_evidence
	compliant := count(synced_admins) == 0
}

generate_message(synced, total) := sprintf(
	"All %d administrative accounts are cloud-only",
	[total],
) if {
	synced == 0
}

generate_message(synced, total) := sprintf(
	"%d of %d administrative accounts are synced from on-premises AD",
	[synced, total],
) if {
	synced > 0
}
