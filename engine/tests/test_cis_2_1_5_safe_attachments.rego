package cis.microsoft_365_foundations.v6_0_0.test_control_2_1_5

import rego.v1

test_secure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

test_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableATPForSPOTeamsODB_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_EnableATPForSPOTeamsODB_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableATPForSPOTeamsODB_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": null, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableATPForSPOTeamsODB_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": "true", "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableATPForSPOTeamsODB_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": 1, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableATPForSPOTeamsODB_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": [], "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableATPForSPOTeamsODB_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": {}, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableSafeDocs_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": false, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_EnableSafeDocs_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableSafeDocs_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": null, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableSafeDocs_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": "true", "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableSafeDocs_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": 1, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableSafeDocs_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": [], "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_EnableSafeDocs_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": {}, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_AllowSafeDocsOpen_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": true}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_AllowSafeDocsOpen_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_AllowSafeDocsOpen_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": null}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_AllowSafeDocsOpen_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": "true"}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_AllowSafeDocsOpen_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": 1}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_AllowSafeDocsOpen_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": []}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_AllowSafeDocsOpen_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": {}}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_policy_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_policy_empty if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_policy_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": []}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_policy_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": "enabled"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_policy_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": 1}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_all_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": false, "AllowSafeDocsOpen": true}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_unknown_precedes_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": null, "AllowSafeDocsOpen": false}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_collector_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}, "collector_error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}, "error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_root_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as null
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as []
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as "bad"
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_boolean_combination_true_true_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": true}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": true}]
	sort(result.details.insecure_settings) == ["AllowSafeDocsOpen"]
	result.affected_resources == ["Default"]
}

test_boolean_combination_true_true_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	result.compliant == true
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}]
	sort(result.details.insecure_settings) == []
	result.affected_resources == []
}

test_boolean_combination_true_false_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": false, "AllowSafeDocsOpen": true}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": false, "AllowSafeDocsOpen": true}]
	sort(result.details.insecure_settings) == ["AllowSafeDocsOpen", "EnableSafeDocs"]
	result.affected_resources == ["Default"]
}

test_boolean_combination_true_false_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": false, "AllowSafeDocsOpen": false}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": true, "EnableSafeDocs": false, "AllowSafeDocsOpen": false}]
	sort(result.details.insecure_settings) == ["EnableSafeDocs"]
	result.affected_resources == ["Default"]
}

test_boolean_combination_false_true_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": true, "AllowSafeDocsOpen": true}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": true, "AllowSafeDocsOpen": true}]
	sort(result.details.insecure_settings) == ["AllowSafeDocsOpen", "EnableATPForSPOTeamsODB"]
	result.affected_resources == ["Default"]
}

test_boolean_combination_false_true_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}]
	sort(result.details.insecure_settings) == ["EnableATPForSPOTeamsODB"]
	result.affected_resources == ["Default"]
}

test_boolean_combination_false_false_true if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": false, "AllowSafeDocsOpen": true}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": false, "AllowSafeDocsOpen": true}]
	sort(result.details.insecure_settings) == ["AllowSafeDocsOpen", "EnableATPForSPOTeamsODB", "EnableSafeDocs"]
	result.affected_resources == ["Default"]
}

test_boolean_combination_false_false_false if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as {"atp_policy": {"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": false, "AllowSafeDocsOpen": false}}
	result.compliant == false
	result.details.policies_evaluated == [{"Name": "Default", "EnableATPForSPOTeamsODB": false, "EnableSafeDocs": false, "AllowSafeDocsOpen": false}]
	sort(result.details.insecure_settings) == ["EnableATPForSPOTeamsODB", "EnableSafeDocs"]
	result.affected_resources == ["Default"]
}
