package cis.microsoft_365_foundations.v6_0_0.test_control_1_3_1

import rego.v1

test_secure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

test_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 90}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_minimum_valid_days if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 1}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_below_never_expires if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483646}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_mixed_known if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483647}, {"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 90}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_federated_null_ignored if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483647}, {"domain_name": "federated.com", "is_managed": false, "password_validity_days": null}]}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

test_federated_only if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "federated.com", "is_managed": false, "password_validity_days": null}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domains_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domains_empty if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": []}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domains_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": {}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domains_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": "domains"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domains_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": 1}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domain_name_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"is_managed": true, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domain_name_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": null, "is_managed": true, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domain_name_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": [], "is_managed": true, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_domain_name_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": {}, "is_managed": true, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_is_managed_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_is_managed_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": null, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_is_managed_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": [], "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_is_managed_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": {}, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_password_validity_days_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_password_validity_days_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": null}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_password_validity_days_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_password_validity_days_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": {}}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_days_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": "2147483647"}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_days_bool if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": true}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_days_zero if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 0}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_days_negative if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": -1}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_days_fraction if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 1.5}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_days_above_max if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483648}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_managed_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": "true", "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_identity_empty if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "", "is_managed": true, "password_validity_days": 2147483647}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_null_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [null]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_empty_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_malformed_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": ["bad"]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_unknown_precedes_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 90}, {"domain_name": "contoso.com", "is_managed": true, "password_validity_days": null}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_collector_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483647}], "collector_error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483647}], "error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_record_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 2147483647, "error": "denied"}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_root_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as null
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as []
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as "bad"
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_violation_details_identify_resource if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as {"domains": [{"domain_name": "contoso.com", "is_managed": true, "password_validity_days": 90}]}
	result.compliant == false
	result.details.total_managed_domains == 1
	result.details.non_compliant_domains == 1
	result.affected_resources == ["contoso.com"]
}
