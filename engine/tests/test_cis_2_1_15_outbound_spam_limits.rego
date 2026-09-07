package cis.microsoft_365_foundations.v6_0_0.test_control_2_1_15

import rego.v1

# The previous rule compared NotifyOutboundSpamRecipients for equality against a
# hard-coded example address, so a tenant with its own notification address
# failed. The requirement is that a recipient is configured at all.

test_compliant if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

test_compliant_at_the_limits if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

test_non_compliant_external_limit_too_high if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 501, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_non_compliant_action if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "Alert", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_non_compliant_no_notification_recipient if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": []}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent_evidence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_no_default_policy if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_limit_not_a_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": "1000", "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_action_missing if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_notify_not_an_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": "secops@contoso.com"}}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}, "collector_error": "graph returned 503"}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}, "error": "authentication failed"}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as null
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as []
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as "bad"
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as 1
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}
