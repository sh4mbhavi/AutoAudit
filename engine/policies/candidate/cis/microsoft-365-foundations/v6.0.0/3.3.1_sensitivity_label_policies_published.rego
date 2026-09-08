# METADATA
# title: Ensure Information Protection sensitivity label policies are published
# description: |
#   The benchmark requires at least one label policy whose Type is
#   PublishedSensitivityLabel, then states verbatim that "whether an organization
#   passes the audit is open to interpretation by the auditor". This policy
#   therefore decides only the objective half (at least one published policy
#   exists) and reports the locations for review. It can never return compliant true.
#   CANDIDATE: this file is not wired to any scan. See engine/policies/candidate/README.md.
#   Procedure source: docs/engine/Framework/CIS_M365_Benchmarks.json, which self-declares edition "v6.0.1 - 2-26-2026"; the licensed v6.0.0 procedure has not been obtained.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-3.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Compliance
#   requires_permissions:
#   - Exchange.ManageAsApp

package cis.microsoft_365_foundations.v6_0_0.control_3_3_1

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

# No label policies at all: an empty tenant is indistinguishable from an
# unentitled or unauthorized one, so this is indeterminate and never a decision.
assessed_result := output if {
	input.total_policies == 0

	output := {
		"compliant": null,
		"message": "No label policies were returned; an empty tenant cannot be distinguished from an unentitled or unauthorized one",
		"affected_resources": [],
		"details": {
			"evaluation_status": "indeterminate",
			"total_policies": 0,
		},
	}
}

# CIS 3.3.1 audit step 3: "Ensure there is at least one sensitivity label policy
# published." Label policies exist and none of them is published.
assessed_result := output if {
	input.total_policies > 0
	input.published_label_policy_count == 0

	output := {
		"compliant": false,
		"message": sprintf("%d label policy/policies exist and none has Type PublishedSensitivityLabel", [input.total_policies]),
		"affected_resources": ["No published sensitivity label policy"],
		"details": {
			"evaluation_status": "assessed",
			"total_policies": input.total_policies,
			"published_label_policy_count": 0,
		},
	}
}

# Published policies exist. The benchmark states the pass decision is open to
# auditor interpretation, so the locations are reported and no pass is asserted.
assessed_result := output if {
	input.published_label_policy_count > 0

	output := {
		"compliant": null,
		"message": sprintf(
			"%d published sensitivity label policy/policies exist; whether the organization passes is open to auditor interpretation",
			[input.published_label_policy_count],
		),
		"affected_resources": [],
		"details": {
			"evaluation_status": "requires_human_review",
			"total_policies": input.total_policies,
			"published_label_policy_count": input.published_label_policy_count,
			"published_label_policy_location_scopes": input.published_label_policy_location_scopes,
			"published_label_policy_names": [p.name | some p in input.published_label_policies],
			"review_obligation": "CIS Microsoft 365 Foundations control 3.3.1 audit step 4: review the locations defined to ensure they are in scope with the organization's needs. The benchmark states the pass decision is open to interpretation by the auditor.",
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
	is_count(input.total_policies)
	is_count(input.published_label_policy_count)
	input.published_label_policy_count <= input.total_policies
	is_names_or_null(input.published_label_policy_location_scopes)
	is_array(input.published_label_policies)
	count(input.published_label_policies) == input.published_label_policy_count
	every p in input.published_label_policies { is_object(p); is_string(p.name)}
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}

is_count(v) if {
	is_number(v)
	v >= 0
	v == floor(v)
}

is_names_or_null(v) if v == null

is_names_or_null(v) if {
	is_array(v)
	every n in v { is_string(n) }
}
