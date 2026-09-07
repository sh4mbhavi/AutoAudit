# METADATA
# title: Ensure sign-in to shared mailboxes is blocked
# description: |
#   Shared mailboxes should not allow direct sign-in. Users should access them
#   through their own accounts using delegated permissions.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.2.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Exchange
#   requires_permissions:
#   - Exchange.ManageAsApp

package cis.microsoft_365_foundations.v6_0_0.control_1_2_2

import rego.v1

# Read `shared_mailboxes` with a type guard, not with object.get(..., []).
# The default made an absent key indistinguishable from an empty tenant, and a
# string got as far as count() -- {"shared_mailboxes": "oops"} was reported as
# "Sign-in is blocked for all 4 shared mailbox(es)", 4 being the length of the
# word.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: the tenant's shared mailboxes are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a shared_mailboxes array of mailbox objects; collector errors invalidate the evidence.",
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
	is_array(input.shared_mailboxes)
	every mailbox in input.shared_mailboxes {
		is_object(mailbox)
	}
}

non_compliant_mailboxes := [mailbox |
	some mailbox in input.shared_mailboxes
	object.get(mailbox, "account_disabled", null) == false
]

# A mailbox whose account_disabled is absent, null or not a boolean has not told
# us anything. It is not a finding and it is not a pass.
unknown_status_mailboxes := [mailbox |
	some mailbox in input.shared_mailboxes
	not is_boolean(object.get(mailbox, "account_disabled", null))
]

result := {
	"compliant": null,
	"message": sprintf(
		"Unable to determine sign-in status for %d of %d shared mailbox(es)",
		[count(unknown_status_mailboxes), count(input.shared_mailboxes)],
	),
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "At least one shared mailbox reported no boolean account_disabled value.",
		"total_shared_mailboxes": count(input.shared_mailboxes),
		"unknown_status_count": count(unknown_status_mailboxes),
	},
} if {
	valid_evidence
	count(unknown_status_mailboxes) > 0
}

result := {
	"compliant": compliant,
	"message": generate_message(count(input.shared_mailboxes), count(non_compliant_mailboxes)),
	"affected_resources": non_compliant_mailboxes,
	"details": {
		"total_shared_mailboxes": count(input.shared_mailboxes),
		"blocked_sign_in_count": count(input.shared_mailboxes) - count(non_compliant_mailboxes),
		"direct_sign_in_enabled_count": count(non_compliant_mailboxes),
	},
} if {
	valid_evidence
	count(unknown_status_mailboxes) == 0
	compliant := count(non_compliant_mailboxes) == 0
}

generate_message(total, _) := "No shared mailboxes found." if {
	total == 0
}

generate_message(total, non_compliant_count) := sprintf(
	"Sign-in is blocked for all %d shared mailbox(es).",
	[total],
) if {
	total > 0
	non_compliant_count == 0
}

generate_message(total, non_compliant_count) := sprintf(
	"%d of %d shared mailbox(es) allow direct sign-in.",
	[non_compliant_count, total],
) if {
	non_compliant_count > 0
}
