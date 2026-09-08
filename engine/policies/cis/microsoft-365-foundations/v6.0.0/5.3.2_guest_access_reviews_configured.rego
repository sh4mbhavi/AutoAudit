# METADATA
# title: Ensure 'Access reviews' for Guest Users are configured
# description: Configure access reviews for guest users.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/resources/accessreviewset
#   description: Access reviews
# custom:
#   control_id: CIS-5.3.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - AccessReview.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_3_2

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine guest access reviews",
	"details": {},
}

default compliant := false

compliant if input.has_guest_reviews == true

msg := "Guest user access reviews are configured" if compliant
msg := "No guest user access reviews are configured" if not compliant

assessed_result := output if {
	_ = input.has_guest_reviews

	output := {
		"compliant": compliant,
		"message": msg,
		"details": {
			"total_reviews": input.total_reviews,
			"guest_reviews_count": input.guest_reviews_count,
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
	is_boolean(input.has_guest_reviews)
	derived_presence := input.guest_reviews_count > 0
	input.has_guest_reviews == derived_presence
	input.guest_reviews_count <= input.total_reviews
	is_number(input.total_reviews)
	input.total_reviews >= 0
	input.total_reviews == floor(input.total_reviews)
	is_number(input.guest_reviews_count)
	input.guest_reviews_count >= 0
	input.guest_reviews_count == floor(input.guest_reviews_count)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
