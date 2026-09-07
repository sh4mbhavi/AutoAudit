package essential_eight.asd_essential_eight.v2025.test_e8_mac_2_1

import rego.v1

test_compliant if {
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": "block", "win32_api_rule_found": true, "source": "intune", "policy_name": "ASR baseline"}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

test_non_compliant_audit_mode if {
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": "audit", "win32_api_rule_found": true, "source": "intune", "policy_name": "ASR baseline"}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent_evidence if {
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_state_null if {
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_state_empty if {
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": ""}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_state_number if {
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": 1}
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
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": "block", "win32_api_rule_found": true, "source": "intune", "policy_name": "ASR baseline", "collector_error": "graph returned 503"}
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
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as {"win32_api_rule_state": "block", "win32_api_rule_found": true, "source": "intune", "policy_name": "ASR baseline", "error": "authentication failed"}
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
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as null
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
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as []
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
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as "bad"
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
	result := data.essential_eight.asd_essential_eight.v2025.control_e8_mac_2_1.result with input as 1
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}
