# METADATA
# title: Ensure 'Access reviews' for privileged roles are configured
# description: Configure access reviews for privileged roles.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/graph/api/resources/accessreviewset
#   description: Access reviews
# custom:
#   control_id: CIS-5.3.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: EntraID
#   requires_permissions:
#   - AccessReview.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_3_3

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine access reviews for privileged roles",
	"details": {},
}

is_role_query(q) if contains(q, "role")
is_role_query(q) if contains(q, "directoryrole")

# Best-effort: compliant if any access review definition query references role-based scope.
default compliant := false

compliant if {
	some d in input.access_review_definitions
	scope := d.scope
	q := lower(scope.query)
	is_role_query(q)
}

msg := sprintf(
	"Found %d access review definition(s) that appear to target roles",
	[count([d | some d in input.access_review_definitions; is_role_query(lower(d.scope.query))])],
) if compliant

msg := "No access review definitions appear to target privileged roles" if not compliant

# Best-effort: treat as compliant if any access review definition query references role-based scope.
assessed_result := output if {
	defs := input.access_review_definitions
	role_reviews := [d |
		some d in defs
		scope := d.scope
		q := lower(scope.query)
		is_role_query(q)
	]

	output := {
		"compliant": compliant,
		"message": msg,
		"details": {
			"total_reviews": input.total_reviews,
			"role_reviews_count": count(role_reviews),
			"sample_role_review_ids": [d.id | some d in role_reviews],
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
	is_array(input.access_review_definitions)
	is_number(input.total_reviews)
	input.total_reviews >= 0
	input.total_reviews == floor(input.total_reviews)
	input.total_reviews == count(input.access_review_definitions)
	every review in input.access_review_definitions { is_object(review); is_string(review.id); is_object(review.scope); is_string(review.scope.query)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
