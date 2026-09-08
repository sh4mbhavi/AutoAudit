# Semantics for the CANDIDATE policy engine/policies/candidate/.../3.2.1_dlp_policies_enabled.rego.
# The candidate tree is unreachable from any scan; these tests are what makes it
# reviewable before promotion.
package cis.microsoft_365_foundations.v6_0_0.test_candidate_3_2_1

import rego.v1

# An empty tenant cannot be told apart from an unentitled or unauthorized one.
test_no_policies_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as {"total_policies": 0, "enabled_policy_count": 0, "dlp_policy_modes": []}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

# The objective half of the audit: policies exist and none of them is On.
test_policies_exist_none_enabled_is_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as {
		"total_policies": 3,
		"enabled_policy_count": 0,
		"dlp_policy_modes": ["TestWithNotifications", "Disable", "TestWithoutNotifications"],
	}
	object.get(result, "compliant", "undefined") == false
	result.details.evaluation_status == "assessed"
	result.details.total_policies == 3
	result.details.enabled_policy_count == 0
	count(result.affected_resources) > 0
	is_string(result.message)
	count(result.message) > 0
}

# Applicability to the organization's data is an auditor judgement, so an enabled
# policy is reported and never turned into a pass.
test_policies_enabled_requires_human_review if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as {
		"total_policies": 3,
		"enabled_policy_count": 2,
		"dlp_policy_modes": ["Enable", "Enable", "Disable"],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "requires_human_review"
	result.details.total_policies == 3
	result.details.enabled_policy_count == 2
	is_string(result.details.review_obligation)
	count(result.details.review_obligation) > 0
	count(result.affected_resources) == 0
	is_string(result.message)
	count(result.message) > 0
}

# Internally inconsistent counts are malformed evidence, not a smaller finding.
test_enabled_greater_than_total_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as {
		"total_policies": 1,
		"enabled_policy_count": 2,
		"dlp_policy_modes": ["Enable", "Enable"],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# A nested collector error invalidates the whole response.
test_nested_collector_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as {
		"total_policies": 3,
		"enabled_policy_count": 2,
		"dlp_policy_modes": ["Enable", "Enable", "Disable"],
		"raw": {"page": {"collector_error": "denied"}},
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# One malformed element invalidates the whole list; elements are never dropped.
test_non_string_mode_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_2_1.result with input as {
		"total_policies": 2,
		"enabled_policy_count": 1,
		"dlp_policy_modes": ["Enable", {"mode": "Enable"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}
