# METADATA
# title: Ensure the admin consent workflow is enabled
# description: Enable admin consent workflow for apps.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow
#   description: Configure the admin consent workflow
# custom:
#   control_id: CIS-5.1.5.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_1_5_2

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Evaluation failed: unable to retrieve admin consent request policy",
	"details": {},
}

compliant_value if input.is_enabled == true

else := false

msg := "Admin consent workflow is enabled" if input.is_enabled == true

else := "Admin consent workflow is disabled" if input.is_enabled == false

else := "Unable to determine admin consent workflow state"

assessed_result := output if {
	enabled := input.is_enabled
	reviewers := input.reviewers

	has_reviewers := count(reviewers) > 0

	output := {
		"compliant": compliant_value,
		"message": msg,
		"details": {
			"is_enabled": enabled,
			"reviewers_count": count(reviewers),
			"has_reviewers": has_reviewers,
			"notify_reviewers": input.notify_reviewers,
			"reminders_enabled": input.reminders_enabled,
			"request_duration_in_days": input.request_duration_in_days,
		},
	}
}

# Typed, complete collector evidence is required before an assessed result is emitted.
# Kept in this module so captured-source evaluation remains self-contained.
default result := {
	"compliant": null,
	"message": "Unable to evaluate: required evidence is missing, malformed, or incomplete",
	"affected_resources": [],
	"details": {"evaluation_status": "indeterminate"},
}

result := assessed_result if evidence_complete

evidence_complete if {
	is_object(input)
	not evidence_error
	is_boolean(input.is_enabled)
	is_array(input.reviewers)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
