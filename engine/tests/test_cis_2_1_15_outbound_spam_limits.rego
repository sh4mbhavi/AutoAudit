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

# CIS records 0 as the Default Value for every recipient limit, and says the
# value of 0 means the service defaults are being used - i.e. the prescribed cap
# was never applied. It is a tenant finding, not missing evidence, so a zeroed
# limit must be named as an insecure setting rather than passing the <= maximum
# comparison.
test_non_compliant_all_limits_zero if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 0, "RecipientLimitInternalPerHour": 0, "RecipientLimitPerDay": 0, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"RecipientLimitExternalPerHour", "RecipientLimitInternalPerHour", "RecipientLimitPerDay"}
}

test_non_compliant_single_limit_zero if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 0, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"RecipientLimitInternalPerHour"}
}

# A negative limit is not a cap Exchange can have applied, so like 0 it is
# evidence that the prescribed limit is not in force. The rule is 1 <= value <=
# maximum, and a negative number falls outside it on the low side; it is
# reported as a tenant finding so that an impossible value can never be scored
# as a pass by the <= maximum comparison alone.
test_non_compliant_negative_limit if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": -1, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"RecipientLimitExternalPerHour"}
}

# The service default action, BlockUserForToday, is a weaker action than the
# prescribed BlockUser and is not compliant.
test_non_compliant_default_action_block_user_for_today if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUserForToday", "NotifyOutboundSpamRecipients": ["secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"ActionWhenThresholdReached"}
}

# CIS audit step 4 is "Ensure the property NotifyOutboundSpamRecipients contains
# a monitored mailbox". A list that holds only a blank string, or an element
# that is not a string at all, contains no mailbox, so counting the array is not
# enough. Sibling control 2.1.6 reads the same field of the same payload and
# already rejects these, so one scan must not report the same evidence two ways.
test_non_compliant_blank_notification_recipient if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["   "]}}
	object.get(result, "compliant", "undefined") == false
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

test_non_compliant_non_string_notification_recipient if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": [null]}}
	object.get(result, "compliant", "undefined") == false
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

test_compliant_when_one_usable_mailbox_sits_beside_a_blank if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["", "secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# CIS audit step 4 is "Ensure the property NotifyOutboundSpamRecipients contains
# a monitored mailbox", and the benchmark's own remediation writes the value as
# @('admin@example.com','security@example.com'). Checking only that an element
# is a non-blank string let "@" - a string Exchange's SmtpAddress validation
# cannot produce and which no notification can be delivered to - stand in for a
# mailbox, so a tenant with no reachable notification recipient scored a pass on
# every other setting being right.
test_non_compliant_at_sign_is_not_a_mailbox if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["@"]}}
	object.get(result, "compliant", "undefined") == false
	count(result.affected_resources) > 0
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

test_non_compliant_recipient_without_a_domain if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

# A space is not a hostname character, so this reaches nobody.
test_non_compliant_recipient_with_whitespace_in_the_domain if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@bad domain.com"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

test_non_compliant_recipient_with_an_empty_domain_label if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso..com"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

# The other direction. Address validation exists to stop a false pass, not to
# manufacture a false finding, so ordinary real-world addresses must still be
# read as mailboxes: the benchmark's own remediation value, a subdomain and a
# multi-label public suffix, plus-addressing, and a hyphenated domain label.
test_compliant_with_the_benchmark_remediation_recipients if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["admin@example.com", "security@example.com"]}}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_compliant_with_plus_addressing_and_a_multi_label_domain if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["sec.ops+m365@mail.contoso-corp.co.uk"]}}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A hyphen may sit inside a DNS label but not at either end of one.
test_non_compliant_recipient_with_a_leading_hyphen_label if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@-contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

# DECIDED CASE: one usable address beside a malformed one is compliant. The
# audit step asks whether the property *contains* a monitored mailbox, so one
# deliverable address answers it; a junk sibling makes no configured mailbox
# less reachable. This is the same answer the blank-beside-usable case above
# already gives, and withholding a verdict on the whole control because of one
# unusable list element would also bury a confirmed recipient-limit finding.
test_compliant_when_a_usable_mailbox_sits_beside_a_malformed_one if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["not-an-address", "secops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A malformed recipient must not mask the limits: both findings are reported.
test_non_compliant_reports_limits_and_recipients_together if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 5000, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["@"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"RecipientLimitExternalPerHour", "NotifyOutboundSpamRecipients"}
}

# RE2's \s is only [\t\n\f\r ], so the control characters it leaves out are
# named explicitly in the rejected set: a vertical tab, a NUL or a DEL inside a
# local part is no more an address than a space is.
test_non_compliant_recipient_with_a_vertical_tab if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["sec\u000bops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

test_non_compliant_recipient_with_a_nul_byte if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 400, "RecipientLimitInternalPerHour": 800, "RecipientLimitPerDay": 900, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["sec\u0000ops@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	insecure := {field | some field in result.details.insecure_settings}
	insecure == {"NotifyOutboundSpamRecipients"}
}

# ------------------------------------- non-ASCII whitespace in the local part
# The local part is validated against an RFC 5322 atext allowlist rather than a
# denylist of specials and ASCII controls. A denylist left every non-ASCII
# codepoint accepted, so U+00A0 NO-BREAK SPACE and U+3000 IDEOGRAPHIC SPACE
# passed - a value Exchange's own SmtpAddress validation could never have
# produced, and one no notification reaches.
test_no_break_space_in_the_notification_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["ad min@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["HostedOutboundSpamFilterPolicy"]
	object.get(result.details, "insecure_settings", []) == ["NotifyOutboundSpamRecipients"]
}

test_ideographic_space_in_the_notification_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["ad　min@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["HostedOutboundSpamFilterPolicy"]
}

test_non_ascii_letter_in_the_notification_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["sécurity@contoso.com"]}}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["HostedOutboundSpamFilterPolicy"]
}

# The allowlist must not narrow what already worked: every atext punctuation
# character is still a legal local part for a monitored mailbox.
test_atext_punctuation_in_the_notification_local_part_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["sec-ops_alerts+outbound.spam{1}!x@contoso.com"]}}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# RFC 5321 s4.5.3.1.3 caps a mailbox at 254 octets. The 64-octet local part and
# 253-octet host limits sum to more than that, so a 260-octet value passed both
# and was still reported as a configured notification mailbox.
test_notification_address_over_the_mailbox_octet_limit_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"]}}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "insecure_settings", []) == ["NotifyOutboundSpamRecipients"]
}

test_notification_address_at_the_mailbox_octet_limit_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_15.result with input as {"default_policy": {"RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"]}}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}
