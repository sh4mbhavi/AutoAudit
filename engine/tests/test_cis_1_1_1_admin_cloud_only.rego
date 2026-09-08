package cis.microsoft_365_foundations.v6_0_0.test_control_1_1_1

import rego.v1

test_secure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
}

test_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": true, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_mixed_known if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}, {"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": true, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_accounts_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_accounts_empty if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": []}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_accounts_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": {}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_accounts_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": "accounts"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_accounts_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": 2}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_status_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": null, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_status_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": "false", "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_status_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": 0, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_status_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": [], "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_status_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": {}, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_status_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_identity_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": null, "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_identity_empty if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_identity_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": 1, "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_identity_absent if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_null_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [null]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_malformed_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": ["bad"]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_empty_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_unknown_precedes_insecure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": true, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}, {"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": null, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_collector_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}], "collector_error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": true, "sku_part_numbers": [], "high_footprint_service_plans_enabled": []}], "error": "denied"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_record_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "displayName": "Admin", "admin_roles": ["Global Administrator"], "on_premises_sync_enabled": false, "sku_part_numbers": [], "high_footprint_service_plans_enabled": [], "error": "denied"}]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_root_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as null
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as []
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_root_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as "bad"
	result.compliant == null
	result.details.evaluation_status == "indeterminate"
}

test_violation_details_identify_resource if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as {"admin_accounts": [{"userPrincipalName": "admin@contoso.com", "on_premises_sync_enabled": true}]}
	result.compliant == false
	result.details.total_admin_accounts == 1
	result.details.synced_admin_count == 1
	result.affected_resources == ["admin@contoso.com"]
}
