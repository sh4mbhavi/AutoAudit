# Semantics for the CANDIDATE policy engine/policies/candidate/.../3.2.2_dlp_policies_teams.rego.
# The candidate tree is unreachable from any scan; these tests are what makes it
# reviewable before promotion.
package cis.microsoft_365_foundations.v6_0_0.test_candidate_3_2_2

import rego.v1

# An empty tenant cannot be told apart from an unentitled or unauthorized one.
test_no_policies_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 0,
		"teams_policy_count": 0,
		"teams_policy_mode_enable_count": 0,
		"teams_enforcing_policy_count": 0,
		"teams_location_exception_names": null,
		"teams_policies": [],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	count(result.details) > 0
}

# CIS audit step 3 says remediation is required, but 3.2.2's profile is E5 ONLY
# and an E3 tenant cannot create a Teams policy at all. Absent entitlement
# evidence, an absent Teams policy is not a determinate violation.
test_no_teams_policy_is_indeterminate_without_entitlement if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 0,
		"teams_policy_mode_enable_count": 0,
		"teams_enforcing_policy_count": 0,
		"teams_location_exception_names": null,
		"teams_policies": [],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
	result.details.total_policies == 3
	result.details.teams_policy_count == 0
	result.details.profile_applicability == "E5 Level 1"
	count(result.details.review_obligation) > 0
	count(result.affected_resources) == 0
}

# The collector could not read the location evidence, so the second half of the
# audit is unknown and no verdict is reached.
test_unreadable_location_evidence_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": null,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
	count(result.message) > 0
}

# CIS audit steps 4 and 5: Teams policies exist but none is Enable over TeamsLocation All.
test_teams_policies_without_enforcement_is_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": 0,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == false
	result.details.evaluation_status == "assessed"
	count(result.affected_resources) == 2
	"Default policy for Teams" in result.affected_resources
	"Contoso PII" in result.affected_resources
}

# The only branch of the three candidates that can return true: EVERY returned
# Teams policy has Mode Enable and TeamsLocation All.
test_all_teams_policies_enforcing_is_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": 2,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == true
	result.details.evaluation_status == "assessed"
	result.details.teams_enforcing_policy_count == 2
	object.get(result.details, "teams_location_exception_names", "undefined") != "undefined"
	count(result.details.review_obligation) > 0
	count(result.affected_resources) == 0
}

# TeamsLocationException is organizational judgement: it is reported, never decided on.
test_location_exceptions_do_not_change_the_verdict if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": 2,
		"teams_location_exception_names": ["x", "y"],
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == true
	result.details.teams_location_exception_names == ["x", "y"]
}

# The listed policies must account for the reported count exactly.
test_policy_list_count_mismatch_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": 1,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# A subset count larger than its superset is malformed evidence.
test_mode_enable_greater_than_teams_count_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 3,
		"teams_enforcing_policy_count": 1,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# An enforcing policy is by construction a Mode Enable policy, so a larger
# enforcing count is inconsistent evidence rather than a stronger result.
test_enforcing_greater_than_mode_enable_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 1,
		"teams_enforcing_policy_count": 2,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Disable"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# A nested collector error invalidates the whole response.
test_nested_collector_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": 1,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "Enable"}],
		"raw": {"page": {"collector_error": "denied"}},
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}


# Some but not all returned Teams policies enforce. The benchmark does not say
# whether that passes, so neither does this policy.
test_partially_enforcing_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_2.result with input as {
		"total_policies": 3,
		"teams_policy_count": 2,
		"teams_policy_mode_enable_count": 2,
		"teams_enforcing_policy_count": 1,
		"teams_location_exception_names": null,
		"teams_policies": [{"name": "Default policy for Teams", "mode": "Enable"}, {"name": "Contoso PII", "mode": "TestWithNotifications"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
	result.details.teams_enforcing_policy_count == 1
	result.details.teams_policy_count == 2
	count(result.details.review_obligation) > 0
}
