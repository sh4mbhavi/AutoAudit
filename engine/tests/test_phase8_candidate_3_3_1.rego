# Semantics for the CANDIDATE policy
# engine/policies/candidate/.../3.3.1_sensitivity_label_policies_published.rego.
# The candidate tree is unreachable from any scan; these tests are what makes it
# reviewable before promotion.
package cis.microsoft_365_foundations.v6_0_0.test_candidate_3_3_1

import rego.v1

# An empty tenant cannot be told apart from an unentitled or unauthorized one.
test_no_policies_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 0,
		"published_label_policy_count": 0,
		"published_label_policy_location_scopes": null,
		"published_label_policies": [],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	count(result.details) > 0
}

# CIS audit step 3: "Ensure there is at least one sensitivity label policy published."
test_no_published_policy_is_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 2,
		"published_label_policy_count": 0,
		"published_label_policy_location_scopes": null,
		"published_label_policies": [],
	}
	object.get(result, "compliant", "undefined") == false
	result.details.evaluation_status == "assessed"
	result.details.total_policies == 2
	result.details.published_label_policy_count == 0
	count(result.affected_resources) > 0
}

# The benchmark states the pass decision is open to auditor interpretation, so the
# locations are reported and no pass is asserted.
test_published_policy_requires_human_review if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 2,
		"published_label_policy_count": 1,
		"published_label_policy_location_scopes": ["ExchangeLocation", "SharePointLocation"],
		"published_label_policies": [{"name": "Global sensitivity label policy"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "requires_human_review"
	result.details.published_label_policy_count == 1
	result.details.published_label_policy_location_scopes == ["ExchangeLocation", "SharePointLocation"]
	result.details.published_label_policy_names == ["Global sensitivity label policy"]
	count(result.details.review_obligation) > 0
	count(result.affected_resources) == 0
}

# Unreadable location scopes do not change the verdict; the review obligation stands.
test_unreadable_location_scopes_still_requires_human_review if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 2,
		"published_label_policy_count": 1,
		"published_label_policy_location_scopes": null,
		"published_label_policies": [{"name": "Global sensitivity label policy"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "requires_human_review"
	object.get(result.details, "published_label_policy_location_scopes", "undefined") == null
}

# Internally inconsistent counts are malformed evidence, not a smaller finding.
test_published_greater_than_total_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 1,
		"published_label_policy_count": 2,
		"published_label_policy_location_scopes": null,
		"published_label_policies": [{"name": "One"}, {"name": "Two"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# One malformed scope invalidates the whole list; elements are never dropped.
test_non_string_location_scope_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 2,
		"published_label_policy_count": 1,
		"published_label_policy_location_scopes": ["ExchangeLocation", {"name": "SharePointLocation"}],
		"published_label_policies": [{"name": "Global sensitivity label policy"}],
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}

# A nested collector error invalidates the whole response.
test_nested_collector_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_3_3_1.result with input as {
		"total_policies": 2,
		"published_label_policy_count": 1,
		"published_label_policy_location_scopes": null,
		"published_label_policies": [{"name": "Global sensitivity label policy"}],
		"raw": {"page": {"collector_error": "denied"}},
	}
	object.get(result, "compliant", "undefined") == null
	result.details.evaluation_status == "indeterminate"
}
