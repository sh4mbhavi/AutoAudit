package cis.microsoft_365_foundations.v4_0_0.test_control_5_2_2_3

import rego.v1

# An empty policy list is a real answer here -- the tenant has no Conditional
# Access policies, so none blocks legacy authentication -- and stays a finding.

test_compliant if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": [{"display_name": "Block legacy auth", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}]}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

test_non_compliant_report_only if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": [{"display_name": "Block legacy auth", "state": "reportOnly", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_non_compliant_no_policies if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": []}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent_evidence if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_policies_null if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_policies_string if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": "none"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_policy_not_an_object if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": ["Block legacy auth"]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_collector_error if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": [{"display_name": "Block legacy auth", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}], "collector_error": "graph returned 503"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_nested_error if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as {"conditional_access_policies": [{"display_name": "Block legacy auth", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}], "error": "authentication failed"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_null if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as null
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_array if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as []
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_string if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as "bad"
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_number if {
	result := data.cis.microsoft_365_foundations.v4_0_0.control_5_2_2_3.result with input as 1
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}
