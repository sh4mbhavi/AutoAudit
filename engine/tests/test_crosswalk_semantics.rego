package phase4.crosswalk_semantics

import rego.v1

has_compliance(result, expected) if result.compliant == expected

test_control_1_1_1_pass if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "on_premises_sync_enabled": false}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_fail if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "on_premises_sync_enabled": true}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_malformed if {
	evidence := {"admin_accounts": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_boundary if {
	evidence := {"admin_accounts": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_partial if {
	evidence := {"admin_accounts": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_collector_error if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "on_premises_sync_enabled": false}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_1_partial_population if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "on_premises_sync_enabled": false}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_pass if {
	evidence := {"global_admin_count": 2, "global_admins": ["a", "b"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_fail if {
	evidence := {"global_admin_count": 1, "global_admins": ["a"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_malformed if {
	evidence := {"global_admin_count": "malformed", "global_admins": ["a", "b"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_boundary if {
	evidence := {"global_admin_count": 4, "global_admins": ["a", "b", "c", "d"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_partial if {
	evidence := {"global_admin_count": 2}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_collector_error if {
	evidence := {"global_admin_count": 2, "global_admins": ["a", "b"], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_count_0 if {
	evidence := {"global_admin_count": 0, "global_admins": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_count_3 if {
	evidence := {"global_admin_count": 3, "global_admins": ["a0", "a1", "a2"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_count_5 if {
	evidence := {"global_admin_count": 5, "global_admins": ["a0", "a1", "a2", "a3", "a4"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_fractional if {
	evidence := {"global_admin_count": 2.5, "global_admins": ["a", "b"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_3_inconsistent_count if {
	evidence := {"global_admin_count": 2, "global_admins": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_pass if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "uses_reduced_license_footprint": true}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_fail if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "uses_reduced_license_footprint": false}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_malformed if {
	evidence := {"admin_accounts": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_boundary if {
	evidence := {"admin_accounts": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_partial if {
	evidence := {"admin_accounts": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_collector_error if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "uses_reduced_license_footprint": true}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_1_4_partial_population if {
	evidence := {"admin_accounts": [{"userPrincipalName": "admin@example.test", "uses_reduced_license_footprint": true}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_pass if {
	evidence := {"total_groups": 0, "public_groups": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_fail if {
	evidence := {"total_groups": 1, "public_groups": [{"id": "g", "displayName": "Public"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_malformed if {
	evidence := {"total_groups": "malformed", "public_groups": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_boundary if {
	evidence := {"total_groups": 1, "public_groups": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_partial if {
	evidence := {"total_groups": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_collector_error if {
	evidence := {"total_groups": 0, "public_groups": [], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_2_1_malformed_population if {
	evidence := {"total_groups": 1, "public_groups": {}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_pass if {
	evidence := {"domains": [{"domain_name": "example.test", "is_managed": true, "password_validity_days": 2147483647}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_fail if {
	evidence := {"domains": [{"domain_name": "example.test", "is_managed": true, "password_validity_days": 90}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_malformed if {
	evidence := {"domains": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_boundary if {
	evidence := {"domains": [{"domain_name": "example.test", "is_managed": true, "password_validity_days": 2147483646}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_partial if {
	evidence := {"domains": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_collector_error if {
	evidence := {"domains": [{"domain_name": "example.test", "is_managed": true, "password_validity_days": 2147483647}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_1_partial_population if {
	evidence := {"domains": [{"domain_name": "example.test", "is_managed": true, "password_validity_days": 2147483647}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_pass if {
	evidence := {"is_office_store_enabled": false, "is_app_and_services_trial_enabled": false, "user_owned_apps_enabled": null, "collector_error": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_fail if {
	evidence := {"is_office_store_enabled": true, "is_app_and_services_trial_enabled": false, "user_owned_apps_enabled": null, "collector_error": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_malformed if {
	evidence := {"is_office_store_enabled": "malformed", "is_app_and_services_trial_enabled": false, "user_owned_apps_enabled": null, "collector_error": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_boundary if {
	evidence := {"is_office_store_enabled": false, "is_app_and_services_trial_enabled": true, "user_owned_apps_enabled": null, "collector_error": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_partial if {
	evidence := {"is_app_and_services_trial_enabled": false, "user_owned_apps_enabled": null, "collector_error": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_collector_error if {
	evidence := {"is_office_store_enabled": false, "is_app_and_services_trial_enabled": false, "user_owned_apps_enabled": null, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_1_3_4_legacy_fallback if {
	evidence := {"is_office_store_enabled": null, "is_app_and_services_trial_enabled": null, "user_owned_apps_enabled": false, "collector_error": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_1_3_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_pass if {
	evidence := {"safe_links_policies": [{"Name": "Default", "EnableSafeLinksForOffice": true}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_fail if {
	evidence := {"safe_links_policies": [{"Name": "Default", "EnableSafeLinksForOffice": false}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_malformed if {
	evidence := {"safe_links_policies": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_boundary if {
	evidence := {"safe_links_policies": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_partial if {
	evidence := {"safe_links_policies": [{}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_collector_error if {
	evidence := {"safe_links_policies": [{"Name": "Default", "EnableSafeLinksForOffice": true}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_1_partial_population if {
	evidence := {"safe_links_policies": [{"Name": "Default", "EnableSafeLinksForOffice": true}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_pass if {
	evidence := {"enable_file_filter": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_fail if {
	evidence := {"enable_file_filter": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_malformed if {
	evidence := {"enable_file_filter": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_boundary if {
	evidence := {"default_policy": {"EnableFileFilter": true}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_partial if {
	evidence := {"enable_file_filter": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_2_collector_error if {
	evidence := {"enable_file_filter": true, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_pass if {
	evidence := {"malware_filter_policies": [{"Name": "Default", "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": "admin@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_fail if {
	evidence := {"malware_filter_policies": [{"Name": "Default", "EnableInternalSenderAdminNotifications": false, "InternalSenderAdminAddress": "admin@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_malformed if {
	evidence := {"malware_filter_policies": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_boundary if {
	evidence := {"malware_filter_policies": [{"Name": "Default", "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": ""}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_partial if {
	evidence := {"malware_filter_policies": [{"EnableInternalSenderAdminNotifications": true}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_collector_error if {
	evidence := {"malware_filter_policies": [{"Name": "Default", "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": "admin@example.test"}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_default_policy_fallback if {
	evidence := {"default_policy": {"Name": "Default", "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": "admin@example.test"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_malformed_address if {
	evidence := {"malware_filter_policies": [{"Name": "Default", "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": []}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_3_partial_population if {
	evidence := {"malware_filter_policies": [{"Name": "Default", "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": "admin@example.test"}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_pass if {
	evidence := {"safe_attachment_policies": [{"Name": "Built-In Protection Policy", "Enable": true, "Action": "Block", "QuarantineTag": "AdminOnlyAccessPolicy"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_fail if {
	evidence := {"safe_attachment_policies": [{"Name": "Built-In Protection Policy", "Enable": false, "Action": "Block", "QuarantineTag": "AdminOnlyAccessPolicy"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_malformed if {
	evidence := {"safe_attachment_policies": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_boundary if {
	evidence := {"safe_attachment_policies": [{"Name": "Built-In Protection Policy", "Enable": true, "Action": "Monitor", "QuarantineTag": "AdminOnlyAccessPolicy"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_partial if {
	evidence := {"safe_attachment_policies": [{"Name": "Built-In Protection Policy", "Enable": true}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_collector_error if {
	evidence := {"safe_attachment_policies": [{"Name": "Built-In Protection Policy", "Enable": true, "Action": "Block", "QuarantineTag": "AdminOnlyAccessPolicy"}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_no_policies if {
	evidence := {"safe_attachment_policies": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_4_partial_population if {
	evidence := {"safe_attachment_policies": [{"Name": "Built-In Protection Policy", "Enable": true, "Action": "Block", "QuarantineTag": "AdminOnlyAccessPolicy"}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_pass if {
	evidence := {"atp_policy": {"EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_fail if {
	evidence := {"atp_policy": {"EnableATPForSPOTeamsODB": false, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_malformed if {
	evidence := {"atp_policy": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_boundary if {
	evidence := {"atp_policy": {"EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": true}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_partial if {
	evidence := {"atp_policy": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_5_collector_error if {
	evidence := {"atp_policy": {"EnableATPForSPOTeamsODB": true, "EnableSafeDocs": true, "AllowSafeDocsOpen": false}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_pass if {
	evidence := {"default_policy": {"BccSuspiciousOutboundMail": true, "NotifyOutboundSpam": true, "BccSuspiciousOutboundAdditionalRecipients": ["admin@example.test"], "NotifyOutboundSpamRecipients": ["admin@example.test"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_fail if {
	evidence := {"default_policy": {"BccSuspiciousOutboundMail": true, "NotifyOutboundSpam": false, "BccSuspiciousOutboundAdditionalRecipients": ["admin@example.test"], "NotifyOutboundSpamRecipients": ["admin@example.test"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_malformed if {
	evidence := {"default_policy": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_boundary if {
	evidence := {"default_policy": {"BccSuspiciousOutboundMail": true, "NotifyOutboundSpam": true, "BccSuspiciousOutboundAdditionalRecipients": ["admin@example.test"], "NotifyOutboundSpamRecipients": []}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_partial if {
	evidence := {"default_policy": {"BccSuspiciousOutboundMail": true, "NotifyOutboundSpam": true}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_collector_error if {
	evidence := {"default_policy": {"BccSuspiciousOutboundMail": true, "NotifyOutboundSpam": true, "BccSuspiciousOutboundAdditionalRecipients": ["admin@example.test"], "NotifyOutboundSpamRecipients": ["admin@example.test"]}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_6_blank_recipient if {
	evidence := {"default_policy": {"BccSuspiciousOutboundMail": true, "NotifyOutboundSpam": true, "BccSuspiciousOutboundAdditionalRecipients": ["admin@example.test"], "NotifyOutboundSpamRecipients": [" "]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_6.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_pass if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_fail if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": false, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_malformed if {
	evidence := {"anti_phish_policies": "malformed", "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_boundary if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9", "u10", "u11", "u12", "u13", "u14", "u15", "u16", "u17", "u18", "u19", "u20", "u21", "u22", "u23", "u24", "u25", "u26", "u27", "u28", "u29", "u30", "u31", "u32", "u33", "u34", "u35", "u36", "u37", "u38", "u39", "u40", "u41", "u42", "u43", "u44", "u45", "u46", "u47", "u48", "u49", "u50", "u51", "u52", "u53", "u54", "u55", "u56", "u57", "u58", "u59", "u60", "u61", "u62", "u63", "u64", "u65", "u66", "u67", "u68", "u69", "u70", "u71", "u72", "u73", "u74", "u75", "u76", "u77", "u78", "u79", "u80", "u81", "u82", "u83", "u84", "u85", "u86", "u87", "u88", "u89", "u90", "u91", "u92", "u93", "u94", "u95", "u96", "u97", "u98", "u99", "u100", "u101", "u102", "u103", "u104", "u105", "u106", "u107", "u108", "u109", "u110", "u111", "u112", "u113", "u114", "u115", "u116", "u117", "u118", "u119", "u120", "u121", "u122", "u123", "u124", "u125", "u126", "u127", "u128", "u129", "u130", "u131", "u132", "u133", "u134", "u135", "u136", "u137", "u138", "u139", "u140", "u141", "u142", "u143", "u144", "u145", "u146", "u147", "u148", "u149", "u150", "u151", "u152", "u153", "u154", "u155", "u156", "u157", "u158", "u159", "u160", "u161", "u162", "u163", "u164", "u165", "u166", "u167", "u168", "u169", "u170", "u171", "u172", "u173", "u174", "u175", "u176", "u177", "u178", "u179", "u180", "u181", "u182", "u183", "u184", "u185", "u186", "u187", "u188", "u189", "u190", "u191", "u192", "u193", "u194", "u195", "u196", "u197", "u198", "u199", "u200", "u201", "u202", "u203", "u204", "u205", "u206", "u207", "u208", "u209", "u210", "u211", "u212", "u213", "u214", "u215", "u216", "u217", "u218", "u219", "u220", "u221", "u222", "u223", "u224", "u225", "u226", "u227", "u228", "u229", "u230", "u231", "u232", "u233", "u234", "u235", "u236", "u237", "u238", "u239", "u240", "u241", "u242", "u243", "u244", "u245", "u246", "u247", "u248", "u249", "u250", "u251", "u252", "u253", "u254", "u255", "u256", "u257", "u258", "u259", "u260", "u261", "u262", "u263", "u264", "u265", "u266", "u267", "u268", "u269", "u270", "u271", "u272", "u273", "u274", "u275", "u276", "u277", "u278", "u279", "u280", "u281", "u282", "u283", "u284", "u285", "u286", "u287", "u288", "u289", "u290", "u291", "u292", "u293", "u294", "u295", "u296", "u297", "u298", "u299", "u300", "u301", "u302", "u303", "u304", "u305", "u306", "u307", "u308", "u309", "u310", "u311", "u312", "u313", "u314", "u315", "u316", "u317", "u318", "u319", "u320", "u321", "u322", "u323", "u324", "u325", "u326", "u327", "u328", "u329", "u330", "u331", "u332", "u333", "u334", "u335", "u336", "u337", "u338", "u339", "u340", "u341", "u342", "u343", "u344", "u345", "u346", "u347", "u348", "u349"]}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_partial if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_collector_error if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_unbound_policy if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}], "anti_phish_rules": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_above_target_limit if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9", "u10", "u11", "u12", "u13", "u14", "u15", "u16", "u17", "u18", "u19", "u20", "u21", "u22", "u23", "u24", "u25", "u26", "u27", "u28", "u29", "u30", "u31", "u32", "u33", "u34", "u35", "u36", "u37", "u38", "u39", "u40", "u41", "u42", "u43", "u44", "u45", "u46", "u47", "u48", "u49", "u50", "u51", "u52", "u53", "u54", "u55", "u56", "u57", "u58", "u59", "u60", "u61", "u62", "u63", "u64", "u65", "u66", "u67", "u68", "u69", "u70", "u71", "u72", "u73", "u74", "u75", "u76", "u77", "u78", "u79", "u80", "u81", "u82", "u83", "u84", "u85", "u86", "u87", "u88", "u89", "u90", "u91", "u92", "u93", "u94", "u95", "u96", "u97", "u98", "u99", "u100", "u101", "u102", "u103", "u104", "u105", "u106", "u107", "u108", "u109", "u110", "u111", "u112", "u113", "u114", "u115", "u116", "u117", "u118", "u119", "u120", "u121", "u122", "u123", "u124", "u125", "u126", "u127", "u128", "u129", "u130", "u131", "u132", "u133", "u134", "u135", "u136", "u137", "u138", "u139", "u140", "u141", "u142", "u143", "u144", "u145", "u146", "u147", "u148", "u149", "u150", "u151", "u152", "u153", "u154", "u155", "u156", "u157", "u158", "u159", "u160", "u161", "u162", "u163", "u164", "u165", "u166", "u167", "u168", "u169", "u170", "u171", "u172", "u173", "u174", "u175", "u176", "u177", "u178", "u179", "u180", "u181", "u182", "u183", "u184", "u185", "u186", "u187", "u188", "u189", "u190", "u191", "u192", "u193", "u194", "u195", "u196", "u197", "u198", "u199", "u200", "u201", "u202", "u203", "u204", "u205", "u206", "u207", "u208", "u209", "u210", "u211", "u212", "u213", "u214", "u215", "u216", "u217", "u218", "u219", "u220", "u221", "u222", "u223", "u224", "u225", "u226", "u227", "u228", "u229", "u230", "u231", "u232", "u233", "u234", "u235", "u236", "u237", "u238", "u239", "u240", "u241", "u242", "u243", "u244", "u245", "u246", "u247", "u248", "u249", "u250", "u251", "u252", "u253", "u254", "u255", "u256", "u257", "u258", "u259", "u260", "u261", "u262", "u263", "u264", "u265", "u266", "u267", "u268", "u269", "u270", "u271", "u272", "u273", "u274", "u275", "u276", "u277", "u278", "u279", "u280", "u281", "u282", "u283", "u284", "u285", "u286", "u287", "u288", "u289", "u290", "u291", "u292", "u293", "u294", "u295", "u296", "u297", "u298", "u299", "u300", "u301", "u302", "u303", "u304", "u305", "u306", "u307", "u308", "u309", "u310", "u311", "u312", "u313", "u314", "u315", "u316", "u317", "u318", "u319", "u320", "u321", "u322", "u323", "u324", "u325", "u326", "u327", "u328", "u329", "u330", "u331", "u332", "u333", "u334", "u335", "u336", "u337", "u338", "u339", "u340", "u341", "u342", "u343", "u344", "u345", "u346", "u347", "u348", "u349", "u350"]}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_disabled_rule if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}], "anti_phish_rules": [{"State": "Disabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_nested_error if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"], "error": "permission_denied"}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": ["example.test"], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_7_malformed_rule_targets if {
	evidence := {"anti_phish_policies": [{"Name": "AntiPhish", "Enabled": true, "PhishThresholdLevel": 3, "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true, "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true, "EnableSpoofIntelligence": true, "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine", "MailboxIntelligenceProtectionAction": "Quarantine", "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true, "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true, "HonorDmarcPolicy": true, "TargetedUsersToProtect": ["user@example.test"]}], "anti_phish_rules": [{"State": "Enabled", "AntiPhishPolicy": "AntiPhish", "RecipientDomainIs": [{}], "SentToMemberOf": ["all-users"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_pass if {
	evidence := {"default_policy": {"EnableFileFilter": true, "FileTypes": ["7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller", "applescript", "application", "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc", "wsf", "wsh", "xla", "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm", "xlt", "xltm", "xlw", "xnk", "xps", "xsl", "xz", "z"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_fail if {
	evidence := {"default_policy": {"EnableFileFilter": false, "FileTypes": ["7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller", "applescript", "application", "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc", "wsf", "wsh", "xla", "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm", "xlt", "xltm", "xlw", "xnk", "xps", "xsl", "xz", "z"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_malformed if {
	evidence := {"default_policy": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_boundary if {
	evidence := {"default_policy": {"EnableFileFilter": true, "FileTypes": ["7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller", "applescript", "application", "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_partial if {
	evidence := {"default_policy": {"EnableFileFilter": true}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_collector_error if {
	evidence := {"default_policy": {"EnableFileFilter": true, "FileTypes": ["7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller", "applescript", "application", "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc", "wsf", "wsh", "xla", "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm", "xlt", "xltm", "xlw", "xnk", "xps", "xsl", "xz", "z"]}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_1_11_below_coverage_threshold if {
	evidence := {"default_policy": {"EnableFileFilter": true, "FileTypes": ["7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller", "applescript", "application", "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_11.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_pass if {
	evidence := {"zap_enabled": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_fail if {
	evidence := {"zap_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_malformed if {
	evidence := {"zap_enabled": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_boundary if {
	evidence := {"teams_protection_policy": {"ZapEnabled": true}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_partial if {
	evidence := {"zap_enabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_2_4_4_collector_error if {
	evidence := {"zap_enabled": true, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_4_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_pass if {
	evidence := {"personal_devices_blocked": true, "total_configurations": 1, "platform_restrictions": [{}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_fail if {
	evidence := {"personal_devices_blocked": false, "total_configurations": 1, "platform_restrictions": [{}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_malformed if {
	evidence := {"personal_devices_blocked": "malformed", "total_configurations": 1, "platform_restrictions": [{}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_boundary if {
	evidence := {"personal_devices_blocked": false, "total_configurations": 0, "platform_restrictions": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_partial if {
	evidence := {"total_configurations": 1, "platform_restrictions": [{}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_4_2_collector_error if {
	evidence := {"personal_devices_blocked": true, "total_configurations": 1, "platform_restrictions": [{}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_4_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_pass if {
	evidence := {"allowed_to_create_apps": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_fail if {
	evidence := {"allowed_to_create_apps": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_malformed if {
	evidence := {"allowed_to_create_apps": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_boundary if {
	evidence := {"allowed_to_create_apps": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_partial if {
	evidence := {"allowed_to_create_apps": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_2_2_collector_error if {
	evidence := {"allowed_to_create_apps": false, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_pass if {
	evidence := {"default_user_role_permissions": {"permissionGrantPoliciesAssigned": []}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_fail if {
	evidence := {"default_user_role_permissions": {"permissionGrantPoliciesAssigned": ["user-consent"]}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_malformed if {
	evidence := {"default_user_role_permissions": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_boundary if {
	evidence := {"default_user_role_permissions": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_partial if {
	evidence := {"default_user_role_permissions": {}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_1_collector_error if {
	evidence := {"default_user_role_permissions": {"permissionGrantPoliciesAssigned": []}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_pass if {
	evidence := {"is_enabled": true, "reviewers": [{"query": "/users/admin"}], "notify_reviewers": true, "reminders_enabled": true, "request_duration_in_days": 30}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_fail if {
	evidence := {"is_enabled": false, "reviewers": [{"query": "/users/admin"}], "notify_reviewers": true, "reminders_enabled": true, "request_duration_in_days": 30}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_malformed if {
	evidence := {"is_enabled": "malformed", "reviewers": [{"query": "/users/admin"}], "notify_reviewers": true, "reminders_enabled": true, "request_duration_in_days": 30}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_boundary if {
	evidence := {"is_enabled": true, "reviewers": [], "notify_reviewers": true, "reminders_enabled": true, "request_duration_in_days": 30}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_partial if {
	evidence := {"reviewers": [{"query": "/users/admin"}], "notify_reviewers": true, "reminders_enabled": true, "request_duration_in_days": 30}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_5_2_collector_error if {
	evidence := {"is_enabled": true, "reviewers": [{"query": "/users/admin"}], "notify_reviewers": true, "reminders_enabled": true, "request_duration_in_days": 30, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_pass if {
	evidence := {"partners": [{"tenantId": "partner"}], "partners_count": 1, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "blocked"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_fail if {
	evidence := {"partners": [{"tenantId": "partner"}], "partners_count": 1, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "allowed"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_malformed if {
	evidence := {"partners": "malformed", "partners_count": 1, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "blocked"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_boundary if {
	evidence := {"partners": [], "partners_count": 0, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "blocked"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_partial if {
	evidence := {"partners_count": 1, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "blocked"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_collector_error if {
	evidence := {"partners": [{"tenantId": "partner"}], "partners_count": 1, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "blocked"}}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_1_inconsistent_partner_count if {
	evidence := {"partners": [], "partners_count": 1, "b2b_collaboration_inbound": {"usersAndGroups": {"accessType": "blocked"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_pass if {
	evidence := {"guest_user_role_id": "10dae51f-b6af-4016-8d66-8c2a99b929b3"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_fail if {
	evidence := {"guest_user_role_id": "a0b1b346-4d3e-4e8b-98f8-753987be4970"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_malformed if {
	evidence := {"guest_user_role_id": 17}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_boundary if {
	evidence := {"guest_user_role_id": "2af84b1e-32c8-42b7-82bc-daa82404023b"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_partial if {
	evidence := {"guest_user_role_id": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_2_collector_error if {
	evidence := {"guest_user_role_id": "10dae51f-b6af-4016-8d66-8c2a99b929b3", "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_pass if {
	evidence := {"allow_invites_from": "adminsAndGuestInviters"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_fail if {
	evidence := {"allow_invites_from": "everyone"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_malformed if {
	evidence := {"allow_invites_from": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_boundary if {
	evidence := {"allow_invites_from": "adminsGuestInvitersAndAllMembers"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_partial if {
	evidence := {"allow_invites_from": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_1_6_3_collector_error if {
	evidence := {"allow_invites_from": "adminsAndGuestInviters", "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_pass if {
	evidence := {"conditional_access_policies": [{"display_name": "Block legacy", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_fail if {
	evidence := {"conditional_access_policies": [{"display_name": "Block legacy", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "mfa"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_malformed if {
	evidence := {"conditional_access_policies": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_boundary if {
	evidence := {"conditional_access_policies": [{"display_name": "Block legacy", "state": "enabledForReportingButNotEnforced", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_partial if {
	evidence := {"conditional_access_policies": [{"display_name": "Block legacy", "state": "enabled", "targets_all_users": null, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_collector_error if {
	evidence := {"conditional_access_policies": [{"display_name": "Block legacy", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_2_3_partial_population if {
	evidence := {"conditional_access_policies": [{"display_name": "Block legacy", "state": "enabled", "targets_all_users": true, "targets_all_apps": true, "blocks_legacy_auth": true, "grant_control": "block"}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_pass if {
	evidence := {"number_matching_enabled": true, "display_app_information_enabled": true, "display_location_information_enabled": true, "state": "enabled", "include_targets": [{"id": "all_users"}], "exclude_targets": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_fail if {
	evidence := {"number_matching_enabled": false, "display_app_information_enabled": true, "display_location_information_enabled": true, "state": "enabled", "include_targets": [{"id": "all_users"}], "exclude_targets": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_malformed if {
	evidence := {"number_matching_enabled": "malformed", "display_app_information_enabled": true, "display_location_information_enabled": true, "state": "enabled", "include_targets": [{"id": "all_users"}], "exclude_targets": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_boundary if {
	evidence := {"number_matching_enabled": true, "display_app_information_enabled": true, "display_location_information_enabled": false, "state": "enabled", "include_targets": [{"id": "all_users"}], "exclude_targets": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_partial if {
	evidence := {"display_app_information_enabled": true, "display_location_information_enabled": true, "state": "enabled", "include_targets": [{"id": "all_users"}], "exclude_targets": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_1_collector_error if {
	evidence := {"number_matching_enabled": true, "display_app_information_enabled": true, "display_location_information_enabled": true, "state": "enabled", "include_targets": [{"id": "all_users"}], "exclude_targets": [], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_pass if {
	evidence := {"banned_password_list_enabled": true, "banned_password_list": "example"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_fail if {
	evidence := {"banned_password_list_enabled": false, "banned_password_list": "example"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_malformed if {
	evidence := {"banned_password_list_enabled": "malformed", "banned_password_list": "example"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_boundary if {
	evidence := {"banned_password_list_enabled": true, "banned_password_list": ""}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_partial if {
	evidence := {"banned_password_list": "example"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_2_collector_error if {
	evidence := {"banned_password_list_enabled": true, "banned_password_list": "example", "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_pass if {
	evidence := {"on_prem_protection_enabled": true, "enforce_custom_banned_passwords": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_fail if {
	evidence := {"on_prem_protection_enabled": false, "enforce_custom_banned_passwords": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_malformed if {
	evidence := {"on_prem_protection_enabled": "malformed", "enforce_custom_banned_passwords": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_boundary if {
	evidence := {"on_prem_protection_enabled": true, "enforce_custom_banned_passwords": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_partial if {
	evidence := {"enforce_custom_banned_passwords": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_3_collector_error if {
	evidence := {"on_prem_protection_enabled": true, "enforce_custom_banned_passwords": true, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_pass if {
	evidence := {"total_users": 1, "mfa_capable_count": 1, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_fail if {
	evidence := {"total_users": 1, "mfa_capable_count": 0, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_malformed if {
	evidence := {"total_users": "malformed", "mfa_capable_count": 1, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_boundary if {
	evidence := {"total_users": 0, "mfa_capable_count": 0, "mfa_registered_count": 0, "mfa_not_registered_count": 0, "mfa_registration_percentage": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_partial if {
	evidence := {"mfa_capable_count": 1, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_collector_error if {
	evidence := {"total_users": 1, "mfa_capable_count": 1, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_impossible_count if {
	evidence := {"total_users": 1, "mfa_capable_count": 2, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_4_fractional_count if {
	evidence := {"total_users": 1.5, "mfa_capable_count": 1.5, "mfa_registered_count": 1, "mfa_not_registered_count": 0, "mfa_registration_percentage": 100}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_pass if {
	evidence := {"sms_enabled": false, "voice_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_fail if {
	evidence := {"sms_enabled": true, "voice_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_malformed if {
	evidence := {"sms_enabled": "malformed", "voice_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_boundary if {
	evidence := {"sms_enabled": false, "voice_enabled": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_partial if {
	evidence := {"voice_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_5_collector_error if {
	evidence := {"sms_enabled": false, "voice_enabled": false, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_pass if {
	evidence := {"authentication_methods_policy": {"systemCredentialPreferences": {"state": "enabled"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_fail if {
	evidence := {"authentication_methods_policy": {"systemCredentialPreferences": {"state": "disabled"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_malformed if {
	evidence := {"authentication_methods_policy": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_boundary if {
	evidence := {"authentication_methods_policy": {"systemCredentialPreferences": {"state": "default"}}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_partial if {
	evidence := {"authentication_methods_policy": {}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_6_collector_error if {
	evidence := {"authentication_methods_policy": {"systemCredentialPreferences": {"state": "enabled"}}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_pass if {
	evidence := {"email_otp_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_fail if {
	evidence := {"email_otp_enabled": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_malformed if {
	evidence := {"email_otp_enabled": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_boundary if {
	evidence := {"email_otp_enabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_partial if {
	evidence := {"email_otp_enabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_2_3_7_collector_error if {
	evidence := {"email_otp_enabled": false, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_2_3_7.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_pass if {
	evidence := {"pim_enabled": true, "total_policies": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_fail if {
	evidence := {"pim_enabled": false, "total_policies": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_malformed if {
	evidence := {"pim_enabled": "malformed", "total_policies": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_boundary if {
	evidence := {"pim_enabled": true, "total_policies": 2}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_partial if {
	evidence := {"total_policies": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_collector_error if {
	evidence := {"pim_enabled": true, "total_policies": 1, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_1_inconsistent_presence if {
	evidence := {"pim_enabled": true, "total_policies": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_pass if {
	evidence := {"has_guest_reviews": true, "total_reviews": 1, "guest_reviews_count": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_fail if {
	evidence := {"has_guest_reviews": false, "total_reviews": 0, "guest_reviews_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_malformed if {
	evidence := {"has_guest_reviews": "malformed", "total_reviews": 1, "guest_reviews_count": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_boundary if {
	evidence := {"has_guest_reviews": true, "total_reviews": 2, "guest_reviews_count": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_partial if {
	evidence := {"total_reviews": 1, "guest_reviews_count": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_collector_error if {
	evidence := {"has_guest_reviews": true, "total_reviews": 1, "guest_reviews_count": 1, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_2_inconsistent_presence if {
	evidence := {"has_guest_reviews": true, "total_reviews": 1, "guest_reviews_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_pass if {
	evidence := {"access_review_definitions": [{"id": "review", "scope": {"query": "/roleManagement/directory/roleAssignments"}}], "total_reviews": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_fail if {
	evidence := {"access_review_definitions": [{"id": "review", "scope": {"query": "/groups"}}], "total_reviews": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_malformed if {
	evidence := {"access_review_definitions": "malformed", "total_reviews": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_boundary if {
	evidence := {"access_review_definitions": [], "total_reviews": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_partial if {
	evidence := {"access_review_definitions": [{"id": "review"}], "total_reviews": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_3_collector_error if {
	evidence := {"access_review_definitions": [{"id": "review", "scope": {"query": "/roleManagement/directory/roleAssignments"}}], "total_reviews": 1, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_pass if {
	evidence := {"global_admin_approval_required": true, "global_admin_policy": {"id": "policy"}, "global_admin_mfa_required": true, "global_admin_justification_required": true, "global_admin_max_activation_duration": "PT1H"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_fail if {
	evidence := {"global_admin_approval_required": false, "global_admin_policy": {"id": "policy"}, "global_admin_mfa_required": true, "global_admin_justification_required": true, "global_admin_max_activation_duration": "PT1H"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_malformed if {
	evidence := {"global_admin_approval_required": "malformed", "global_admin_policy": {"id": "policy"}, "global_admin_mfa_required": true, "global_admin_justification_required": true, "global_admin_max_activation_duration": "PT1H"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_boundary if {
	evidence := {"global_admin_approval_required": true, "global_admin_policy": {"id": "policy"}, "global_admin_mfa_required": true, "global_admin_justification_required": true, "global_admin_max_activation_duration": "PT8H"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_partial if {
	evidence := {"global_admin_policy": {"id": "policy"}, "global_admin_mfa_required": true, "global_admin_justification_required": true, "global_admin_max_activation_duration": "PT1H"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_4_collector_error if {
	evidence := {"global_admin_approval_required": true, "global_admin_policy": {"id": "policy"}, "global_admin_mfa_required": true, "global_admin_justification_required": true, "global_admin_max_activation_duration": "PT1H", "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_pass if {
	evidence := {"privileged_role_admin_approval_required": true, "privileged_role_admin_policy": {"id": "policy"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_fail if {
	evidence := {"privileged_role_admin_approval_required": false, "privileged_role_admin_policy": {"id": "policy"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_malformed if {
	evidence := {"privileged_role_admin_approval_required": "malformed", "privileged_role_admin_policy": {"id": "policy"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_boundary if {
	evidence := {"privileged_role_admin_approval_required": null, "privileged_role_admin_policy": {"id": "policy"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_partial if {
	evidence := {"privileged_role_admin_policy": {"id": "policy"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_5_3_5_collector_error if {
	evidence := {"privileged_role_admin_approval_required": true, "privileged_role_admin_policy": {"id": "policy"}, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_5_3_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_pass if {
	evidence := {"audit_disabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_fail if {
	evidence := {"audit_disabled": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_malformed if {
	evidence := {"audit_disabled": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_boundary if {
	evidence := {"audit_disabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_partial if {
	evidence := {"audit_disabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_1_collector_error if {
	evidence := {"audit_disabled": false, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_pass if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "UserPrincipalName": "mailbox@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_fail if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions"], "UserPrincipalName": "mailbox@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_malformed if {
	evidence := {"mailboxes": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_boundary if {
	evidence := {"mailboxes": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_partial if {
	evidence := {"mailboxes": [{"UserPrincipalName": "mailbox@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_collector_error if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "UserPrincipalName": "mailbox@example.test"}], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_unidentified_mailbox if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"]}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_duplicate_actions if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions"], "UserPrincipalName": "mailbox@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_superset_actions if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules", "AdditionalAction"], "UserPrincipalName": "mailbox@example.test"}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_2_partial_population if {
	evidence := {"mailboxes": [{"AuditAdmin": ["ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditDelegate": ["ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"], "AuditOwner": ["ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"], "UserPrincipalName": "mailbox@example.test"}, {}]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_pass if {
	evidence := {"accounts_with_bypass_enabled": [], "bypass_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_fail if {
	evidence := {"accounts_with_bypass_enabled": [{"Name": "mailbox"}], "bypass_count": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_malformed if {
	evidence := {"accounts_with_bypass_enabled": "malformed", "bypass_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_boundary if {
	evidence := {"accounts_with_bypass_enabled": null, "bypass_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_partial if {
	evidence := {"bypass_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_collector_error if {
	evidence := {"accounts_with_bypass_enabled": [], "bypass_count": 0, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_1_3_inconsistent_count if {
	evidence := {"accounts_with_bypass_enabled": [{"Name": "bypassed"}], "bypass_count": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_1_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_pass if {
	evidence := {"outbound_spam_filter_policies": [{"name": "Default", "auto_forwarding_mode": "Off"}], "auto_forwarding_blocked": true, "forwarding_rules": [], "whitelist_rules": [], "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_fail if {
	evidence := {"outbound_spam_filter_policies": [{"name": "Default", "auto_forwarding_mode": "On"}], "auto_forwarding_blocked": false, "forwarding_rules": [], "whitelist_rules": [], "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_malformed if {
	evidence := {"outbound_spam_filter_policies": "malformed", "auto_forwarding_blocked": true, "forwarding_rules": [], "whitelist_rules": [], "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_boundary if {
	evidence := {"outbound_spam_filter_policies": [{"name": "Default", "auto_forwarding_mode": "Off"}], "auto_forwarding_blocked": true, "forwarding_rules": [{"name": "Old", "state": "Disabled"}], "whitelist_rules": [], "total_rules": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_partial if {
	evidence := {"outbound_spam_filter_policies": [{"name": "Default", "auto_forwarding_mode": "Off"}], "auto_forwarding_blocked": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_collector_error if {
	evidence := {"outbound_spam_filter_policies": [{"name": "Default", "auto_forwarding_mode": "Off"}], "auto_forwarding_blocked": true, "forwarding_rules": [], "whitelist_rules": [], "total_rules": 0, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_contradictory_summary if {
	evidence := {"outbound_spam_filter_policies": [{"name": "Default", "auto_forwarding_mode": "On"}], "auto_forwarding_blocked": true, "forwarding_rules": [], "whitelist_rules": [], "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_1_empty_outbound_population if {
	evidence := {"outbound_spam_filter_policies": [], "auto_forwarding_blocked": true, "forwarding_rules": [], "whitelist_rules": [], "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_pass if {
	evidence := {"whitelist_rules": [], "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_fail if {
	evidence := {"whitelist_rules": [{"name": "Allow", "state": "Enabled", "set_scl": -1, "sender_domain": ["example.test"]}], "total_rules": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_malformed if {
	evidence := {"whitelist_rules": "malformed", "total_rules": 0}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_boundary if {
	evidence := {"whitelist_rules": [{"name": "Allow", "state": "Disabled", "set_scl": -1, "sender_domain": ["example.test"]}], "total_rules": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_partial if {
	evidence := {"whitelist_rules": [{}], "total_rules": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_collector_error if {
	evidence := {"whitelist_rules": [], "total_rules": 0, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_malformed_scl if {
	evidence := {"whitelist_rules": [{"name": "Allow", "state": "Enabled", "set_scl": "-1", "sender_domain": ["example.test"]}], "total_rules": 1}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_2_partial_population if {
	evidence := {"whitelist_rules": [{"name": "Allow", "state": "Enabled", "set_scl": -1, "sender_domain": ["example.test"]}, {}], "total_rules": 2}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_2.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_pass if {
	evidence := {"enabled": true, "allowed_senders": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_fail if {
	evidence := {"enabled": false, "allowed_senders": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_malformed if {
	evidence := {"enabled": "malformed", "allowed_senders": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_boundary if {
	evidence := {"enabled": true, "allowed_senders": ["trusted@example.test"]}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_partial if {
	evidence := {"allowed_senders": []}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_2_3_collector_error if {
	evidence := {"enabled": true, "allowed_senders": [], "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_2_3.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_pass if {
	evidence := {"oauth_enabled": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_fail if {
	evidence := {"oauth_enabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_malformed if {
	evidence := {"oauth_enabled": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_boundary if {
	evidence := {"oauth_enabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_partial if {
	evidence := {"oauth_enabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_1_collector_error if {
	evidence := {"oauth_enabled": true, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_1.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_pass if {
	evidence := {"smtp_client_authentication_disabled": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_fail if {
	evidence := {"smtp_client_authentication_disabled": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_malformed if {
	evidence := {"smtp_client_authentication_disabled": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_boundary if {
	evidence := {"smtp_client_authentication_disabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_partial if {
	evidence := {"smtp_client_authentication_disabled": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_4_collector_error if {
	evidence := {"smtp_client_authentication_disabled": true, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_4.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_pass if {
	evidence := {"reject_direct_send": true}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, true)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_fail if {
	evidence := {"reject_direct_send": false}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, false)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_missing if {
	evidence := {}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_malformed if {
	evidence := {"reject_direct_send": "malformed"}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_boundary if {
	evidence := {"reject_direct_send": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_partial if {
	evidence := {"reject_direct_send": null}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}

test_control_6_5_5_collector_error if {
	evidence := {"reject_direct_send": true, "collector_error": {"code": "Forbidden"}}
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_5.result with input as evidence
	has_compliance(result, null)
	is_string(result.message)
	is_object(result)
}
