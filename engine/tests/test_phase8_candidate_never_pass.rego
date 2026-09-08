# Never-pass property tests for the CANDIDATE policies.
#
# Every consumed key of every candidate policy is swept over a matrix of missing,
# null, wrong-type, out-of-range and nested-collector-error values. Failed, missing,
# unauthorized, truncated or malformed collection must never become a pass.
package cis.microsoft_365_foundations.v6_0_0.test_candidate_never_pass

import rego.v1

matrix := [
	{"kind": "missing"},
	{"kind": "value", "v": null},
	{"kind": "value", "v": false},
	{"kind": "value", "v": true},
	{"kind": "value", "v": 0},
	{"kind": "value", "v": 1},
	{"kind": "value", "v": 2},
	{"kind": "value", "v": "x"},
	{"kind": "value", "v": [{"unexpected": 1}]},
	{"kind": "value", "v": {"collector_error": "denied"}},
]

with_entry(obj, key, entry) := object.union(obj, {key: entry.v}) if entry.kind == "value"

with_entry(obj, key, entry) := obj if entry.kind == "missing"

# ---------------------------------------------------------------------------
# 3.2.1 -- full cartesian over all three consumed keys (10^3 = 1000 inputs).
# ---------------------------------------------------------------------------

test_3_2_1_never_true if {
	every total in matrix {
		every enabled in matrix {
			every modes in matrix {
				candidate := with_entry(
					with_entry(with_entry({}, "total_policies", total), "enabled_policy_count", enabled),
					"dlp_policy_modes",
					modes,
				)
				result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as candidate
				object.get(result, "compliant", "undefined") != true
			}
		}
	}
}

# No value in the matrix is a readable list of policy modes, so the cartesian above
# can only ever reach the incomplete-evidence default. This sweep holds the mode list
# at a well-formed value so both scalar keys are swept across the live branches too.
dlp_modes_readable := ["Enable", "Disable"]

test_3_2_1_never_true_with_readable_modes if {
	every total in matrix {
		every enabled in matrix {
			candidate := with_entry(
				with_entry({"dlp_policy_modes": dlp_modes_readable}, "total_policies", total),
				"enabled_policy_count",
				enabled,
			)
			result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as candidate
			object.get(result, "compliant", "undefined") != true
		}
	}
}

# ---------------------------------------------------------------------------
# 3.3.1 -- full cartesian over the three scalar/list keys (10^3 = 1000 inputs),
# with the policy list held at a well-formed value, then the policy list varied
# singly against a base that would otherwise be evidence-complete.
# ---------------------------------------------------------------------------

label_policies_base := {
	"total_policies": 2,
	"published_label_policy_count": 1,
	"published_label_policy_location_scopes": null,
	"published_label_policies": [{"name": "Global sensitivity label policy"}],
}

test_3_3_1_never_true if {
	every total in matrix {
		every published in matrix {
			every scopes in matrix {
				candidate := with_entry(
					with_entry(
						with_entry(
							{"published_label_policies": label_policies_base.published_label_policies},
							"total_policies",
							total,
						),
						"published_label_policy_count",
						published,
					),
					"published_label_policy_location_scopes",
					scopes,
				)
				result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as candidate
				object.get(result, "compliant", "undefined") != true
			}
		}
	}
}

# Every matrix value is a malformed policy list, so this sweep asserts that no
# unreadable list yields a pass; the live branches are reached by the cartesian above,
# whose scopes value may legitimately be null.
test_3_3_1_never_true_when_policy_list_varies if {
	every policies in matrix {
		candidate := with_entry(
			object.remove(label_policies_base, ["published_label_policies"]),
			"published_label_policies",
			policies,
		)
		result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as candidate
		object.get(result, "compliant", "undefined") != true
	}
}

# ---------------------------------------------------------------------------
# 3.2.2 -- the only candidate that can return true. Swept from an empty object
# (no single key is ever enough) and from the known-passing base (no degradation
# of the evidence can leave the pass standing).
# ---------------------------------------------------------------------------

teams_consumed_keys := [
	"total_policies",
	"teams_policy_count",
	"teams_policy_mode_enable_count",
	"teams_enforcing_policy_count",
	"teams_location_exception_names",
	"teams_policies",
]

test_3_2_2_never_true_from_empty if {
	every key in teams_consumed_keys {
		every entry in matrix {
			candidate := with_entry({}, key, entry)
			result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as candidate
			object.get(result, "compliant", "undefined") != true
		}
	}
}

teams_base := {
	"total_policies": 3,
	"teams_policy_count": 3,
	"teams_policy_mode_enable_count": 3,
	"teams_enforcing_policy_count": 3,
	"teams_location_exception_names": null,
	"teams_policies": [
		{"name": "Default policy for Teams", "mode": "Enable"},
		{"name": "Contoso PII", "mode": "Enable"},
		{"name": "Contoso PCI", "mode": "Enable"},
	],
}

# CIS 3.2.2 audit steps 4 and 5 are applied to EVERY returned Teams policy, so a
# smaller enforcing count is no longer a pass -- it is a partially-enforcing
# tenant the benchmark does not decide. There is therefore no mutation of the
# consumed keys that leaves a determinate pass standing.
benign_mutations := {}

benign_mutation(key, entry) if {
	entry.kind == "value"
	entry.v in benign_mutations[key]
}

mutation_safe(key, entry) if entry.kind == "missing"

mutation_safe(key, entry) if benign_mutation(key, entry)

mutation_safe(key, entry) if {
	entry.kind == "value"
	entry.v == teams_base[key]
}

mutation_safe(key, entry) if {
	entry.kind == "value"
	not benign_mutation(key, entry)
	entry.v != teams_base[key]
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as object.union(teams_base, {key: entry.v})
	object.get(result, "compliant", "undefined") != true
}

test_3_2_2_base_is_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as teams_base
	object.get(result, "compliant", "undefined") == true
}

test_3_2_2_degradation_never_true if {
	every key in teams_consumed_keys {
		every entry in matrix {
			mutation_safe(key, entry)
		}

		removed := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as object.remove(teams_base, [key])
		object.get(removed, "compliant", "undefined") != true
	}
}

# Replaces the old "a smaller enforcing count is still a pass" assertion. Under
# the universal reading those inputs are explicitly NOT decided, and asserting
# indeterminate is stronger than asserting merely "not true".
test_3_2_2_partial_enforcement_is_indeterminate_not_pass if {
	every value in {1, 2} {
		result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as object.union(teams_base, {"teams_enforcing_policy_count": value})
		object.get(result, "compliant", "undefined") == null
		result.details.evaluation_status == "indeterminate"
		result.details.teams_enforcing_policy_count == value
		count(result.details.review_obligation) > 0
	}
}
