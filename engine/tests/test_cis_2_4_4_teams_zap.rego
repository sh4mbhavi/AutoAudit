package cis.microsoft_365_foundations.v6_0_0.test_control_2_4_4

import rego.v1

test_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": true}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

test_nested_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": true}}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

test_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": false}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_nested_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": false}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_nested_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": null}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": "true"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_nested_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": "true"}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": 1}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_nested_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": 1}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": []}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_nested_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": []}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": {}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_nested_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {"ZapEnabled": {}}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_empty_policy if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": {}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_malformed_policy if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": "bad"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_null_policy if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"teams_protection_policy": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_explicit_null_does_not_fallback if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": null, "teams_protection_policy": {"ZapEnabled": true}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_collector_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": true, "collector_error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": true, "error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_root_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as null
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as []
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as "bad"
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_unknown_retains_setting_detail if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {}
	object.get(result.details, "ZeroHourAutoPurgeEnabled", "undefined") == null
}

test_disabled_retains_setting_detail if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as {"zap_enabled": false}
	result.details.ZeroHourAutoPurgeEnabled == false
	result.affected_resources == ["TeamsProtectionPolicy"]
}
