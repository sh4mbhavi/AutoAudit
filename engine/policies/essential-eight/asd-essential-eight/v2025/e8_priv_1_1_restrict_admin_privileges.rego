# METADATA
# title: Essential Eight - Privileged access restricted and appropriately assigned
# description: |
#   Checks whether administrative privileges are limited to an appropriate set
#   of users by evaluating Entra ID directory role assignments.
#   Assesses two dimensions: whether all privileged accounts are cloud-only,
#   and whether the number of privileged users is within an appropriate threshold.
#   Research reference: 26T1-SEC-EG-002, 26T1-SEC-EG-004
# custom:
#   control_id: E8-PRIV-1.1
#   framework: essential-eight
#   benchmark: asd-essential-eight
#   version: v2025
#   severity: critical
#   service: EntraID
#   requires_permissions:
#   - RoleManagement.Read.Directory
#   - User.Read.All

package essential_eight.asd_essential_eight.v2025.control_e8_priv_1_1

import rego.v1

max_admin_accounts := 5

# "No admin accounts detected - check collector permissions" was recorded as a
# tenant failure. A tenant cannot have zero administrators; the message named the
# real cause and the verdict contradicted it.
default result := {
	"compliant": null,
	"message": "Unable to evaluate privileged access: no administrative account data is available",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a non-empty admin_accounts array and a matching numeric total_admin_accounts; a tenant cannot have zero administrators, so zero is a failed collection.",
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
	is_number(input.total_admin_accounts)
	input.total_admin_accounts > 0
	is_array(input.admin_accounts)
	every account in input.admin_accounts {
		is_object(account)
		is_boolean(object.get(account, "on_premises_sync_enabled", null))
	}
}

synced_accounts := [account |
	some account in input.admin_accounts
	account.on_premises_sync_enabled == true
]

result := {
	"compliant": compliant,
	"message": generate_message(input.total_admin_accounts, count(synced_accounts)),
	"affected_resources": affected,
	"details": {
		"total_admin_accounts": input.total_admin_accounts,
		"cloud_only_admin_count": object.get(input, "cloud_only_admin_count", null),
		"synced_admin_count": count(synced_accounts),
		"synced_accounts": [object.get(account, "userPrincipalName", null) | some account in synced_accounts],
		"threshold": max_admin_accounts,
		"threshold_exceeded": input.total_admin_accounts > max_admin_accounts,
	},
} if {
	valid_evidence
	compliant := restricted
	affected := array.concat(
		[object.get(account, "userPrincipalName", null) | some account in synced_accounts],
		[sprintf("%d privileged accounts exceed the threshold of %d", [input.total_admin_accounts, max_admin_accounts]) | input.total_admin_accounts > max_admin_accounts],
	)
}

default restricted := false

restricted if {
	count(synced_accounts) == 0
	input.total_admin_accounts <= max_admin_accounts
}

generate_message(_, synced) := sprintf(
	"%d privileged account(s) are synced from on-premises Active Directory and not cloud-only",
	[synced],
) if {
	synced > 0
}

generate_message(total, synced) := sprintf(
	"Privileged access appears excessive: %d admin account(s) found, exceeding the threshold of %d",
	[total, max_admin_accounts],
) if {
	synced == 0
	total > max_admin_accounts
}

generate_message(total, synced) := sprintf(
	"Privileged access appears appropriately restricted: %d admin account(s) found, all cloud-only",
	[total],
) if {
	synced == 0
	total <= max_admin_accounts
}
