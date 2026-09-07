package cis.microsoft_365_foundations.v6_0_0.test_control_6_5_2

import rego.v1

test_compliant if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": 25}}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

test_non_compliant_external_tips_off if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": false, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": 25}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_non_compliant_threshold_zero if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": 0}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent_evidence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_config_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_config_not_an_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": []}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_tip_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": null, "MailTipsLargeAudienceThreshold": 25}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_tip_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": "true", "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": 25}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_threshold_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": null}}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": 25}, "collector_error": "graph returned 503"}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as {"organization_config": {"MailTipsAllTipsEnabled": true, "MailTipsExternalRecipientsTipsEnabled": true, "MailTipsGroupMetricsEnabled": true, "MailTipsLargeAudienceThreshold": 25}, "error": "authentication failed"}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as null
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as []
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as "bad"
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_6_5_2.result with input as 1
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}
