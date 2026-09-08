# METADATA
# title: Ensure outbound anti-spam message limits are in place
# description: |
#   The default outbound anti-spam policy in Microsoft Defender automatically applies
#   to all users and is designed to detect and limit suspicious email-sending behavior.
#   The recommended state is:
#    • External: Restrict sending to external recipients (per hour) - 500
#    • Internal: Restrict sending to internal recipients (per hour) - 1000
#    • Daily: Maximum recipient limit per day - 1000
#    • Action: Over limit action - Restrict the user from sending mail
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.15
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: Defender
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_2_1_15

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Exchange outbound spam filter policy is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected the outbound spam filter's default_policy object carrying numeric recipient limits, a string ActionWhenThresholdReached and an array NotifyOutboundSpamRecipients; collector errors invalidate the evidence.",
	},
}

# CIS recommends capping the per-hour and per-day recipient limits and blocking
# the sender once the threshold is reached. These are the CIS maximums: for a
# recipient limit, "more restrictive" means lower, which the benchmark proves by
# calling the Strict values 400/800/800 "more restrictive and also compliant".
# So the compliant range has two bounds, 1 <= value <= maximum. The lower bound
# matters because CIS records 0 as the Default Value and states that 0 means the
# service defaults are in force - the prescribed cap was never applied - so a
# zero (or otherwise unset-looking) limit is a tenant finding, not a pass and not
# missing evidence.
#
# The rule also compared NotifyOutboundSpamRecipients for equality against a
# hard-coded example address, so every tenant with its own notification address
# failed. CIS audit step 4 is "Ensure the property NotifyOutboundSpamRecipients
# contains a monitored mailbox", so the requirement is that at least one usable
# address is configured - counting the array is not enough, because a list
# holding only a blank string or a null is an unconfigured setting.
#
# Sibling control 2.1.6 reads the same field but asks a different question -
# EVERY element non-blank, for its own notification requirement - where this one
# asks whether SOME element is an address a notification could be delivered to.
# The two can therefore legitimately reach different verdicts on one payload, in
# both directions: ["@"] passes 2.1.6 and fails here, ["soc@contoso.com", ""]
# passes here and fails 2.1.6. That is two controls testing two things, not one
# scan contradicting itself, and this control does not depend on that one.
recipient_limits := {
	"RecipientLimitExternalPerHour": 500,
	"RecipientLimitInternalPerHour": 1000,
	"RecipientLimitPerDay": 1000,
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

policy := object.get(input, "default_policy", null)

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_object(policy)
	every field, _ in recipient_limits {
		is_number(object.get(policy, field, null))
	}
	is_string(object.get(policy, "ActionWhenThresholdReached", null))
	is_array(object.get(policy, "NotifyOutboundSpamRecipients", null))
}

# A limit is in place only when it is actually set (0 is the documented sentinel
# for "service defaults in use", and no positive cap can be below 1) and is at or
# below the CIS maximum.
limit_in_place(value, maximum) if {
	value >= 1
	value <= maximum
}

# A configured recipient address does not establish that the mailbox is
# monitored - nothing in this evidence says who reads it - so the control checks
# the half it can see: that at least one element is an address a notification
# could actually be delivered to. Testing only for a non-blank string was not
# that check; "@" passed it, and no notification reaches "@". CIS audit step 4
# is "Ensure the property NotifyOutboundSpamRecipients contains a monitored
# mailbox", and its remediation writes the value as
# @('admin@example.com','security@example.com'), so one deliverable address in
# the list answers the step. A non-string element is not an address either, so
# it is checked before anything is done with it.
monitored_mailbox_configured if {
	some address in policy.NotifyOutboundSpamRecipients
	is_string(address)
	deliverable_address(address)
}

# RFC 5321 s4.5.3.1.3 caps a forward path at 256 octets including the angle
# brackets, so a mailbox is at most 254. The local part and host limits below
# are 64 and 253, which sum to more than that, so the total needs its own check:
# without it a 260-octet value passed as a configured mailbox.
max_mailbox_octets := 254

deliverable_address(address) if {
	parts := split(trim_space(address), "@")
	count(parts) == 2
	mailbox_local_part(parts[0])
	registrable_host(parts[1])
	(count(parts[0]) + count(parts[1])) + 1 <= max_mailbox_octets
}

# Not full RFC 5321 validation - just enough that a value Exchange's own
# SmtpAddress validation could never have produced is not reported as a
# configured mailbox. The test is an ALLOWLIST, mirroring host_label on the
# other side of the "@": RFC 5322 s3.2.3 spells an unquoted local part as
# dot-separated runs of "atext", and atext is an enumerated ASCII set, so
# anything outside it is not a local part.
#
# A denylist was tried first and was the wrong shape. Enumerating the specials,
# ASCII whitespace and the ASCII control range left every non-ASCII codepoint
# accepted, so U+00A0 NO-BREAK SPACE and U+3000 IDEOGRAPHIC SPACE passed:
# "ad<U+00A0>min@contoso.com" is the same undeliverable value the literal space
# case is, one codepoint away. An allowlist closes all of them at once.
#
# Deliberate limit: the RFC 5321 quoted form ("sec ops"@contoso.com) is
# rejected, as is the RFC 6532 SMTPUTF8 non-ASCII form. Exchange Online
# mailboxes do not carry quoted local parts, so nothing a real tenant holds is
# refused by this, and accepting the form would also accept " "@contoso.com as a
# monitored mailbox.
local_part_atext := "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$"

mailbox_local_part(local) if {
	local != ""
	count(local) <= 64
	not startswith(local, ".")
	not endswith(local, ".")
	not contains(local, "..")
	regex.match(local_part_atext, local)
}

# RFC 1035 s2.3.1 with RFC 1123 s2.1: a label is letters, digits and inner
# hyphens, at most 63 octets, and the name needs more than one label with a
# top-level label longer than a single character. A space is not a hostname
# character, which is what makes "bad domain.com" unreachable.
host_label := `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`

registrable_host(host) if {
	count(host) <= 253
	labels := split(host, ".")
	count(labels) > 1
	every label in labels {
		regex.match(host_label, label)
		count(label) <= 63
	}
	count(labels[count(labels) - 1]) > 1
}

insecure_settings := array.concat(
	[field |
		some field, maximum in recipient_limits
		not limit_in_place(policy[field], maximum)
	],
	array.concat(
		["ActionWhenThresholdReached" | policy.ActionWhenThresholdReached != "BlockUser"],
		["NotifyOutboundSpamRecipients" | not monitored_mailbox_configured],
	),
)

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"RecipientLimitExternalPerHour": policy.RecipientLimitExternalPerHour,
		"RecipientLimitInternalPerHour": policy.RecipientLimitInternalPerHour,
		"RecipientLimitPerDay": policy.RecipientLimitPerDay,
		"ActionWhenThresholdReached": policy.ActionWhenThresholdReached,
		"NotifyOutboundSpamRecipients": policy.NotifyOutboundSpamRecipients,
		"maximum_recipient_limits": recipient_limits,
		"insecure_settings": insecure_settings,
	},
} if {
	valid_evidence
	compliant := count(insecure_settings) == 0
	affected := ["HostedOutboundSpamFilterPolicy" | not compliant]
}

generate_message(true) := "Outbound spam filter recipient limits, block action and notification recipients are in place"

generate_message(false) := "Outbound spam filter policy settings are misconfigured or incomplete"
