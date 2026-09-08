# METADATA
# title: Ensure DLP policies are enabled
# description: |
#   Data Loss Prevention policies let Exchange Online and SharePoint Online
#   content be scanned for sensitive data. The benchmark audit is UI-only and
#   its pass criterion -- policies "applicable to the types of data that is in
#   their interest to protect" -- is an organizational judgement, so this policy
#   decides only the objective half (at least one DLP policy is On) and reports
#   the rest for auditor review. It can never return compliant true.
#   CANDIDATE: this file is not wired to any scan. See engine/policies/candidate/README.md.
#   Procedure source: docs/engine/Framework/CIS_M365_Benchmarks.json, which self-declares edition "v6.0.1 - 2-26-2026"; the licensed v6.0.0 procedure has not been obtained.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-3.2.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Compliance
#   requires_permissions:
#   - Exchange.ManageAsApp

package cis.microsoft_365_foundations.v6_0_0.control_3_2_1

import rego.v1

default assessed_result := {"compliant": null, "message": "Evaluation failed"}

# No policies at all: an empty tenant is indistinguishable from an unentitled or
# unauthorized one, so this is indeterminate and never a decision.
assessed_result := output if {
	input.total_policies == 0

	output := {
		"compliant": null,
		"message": "No DLP policies were returned; an empty tenant cannot be distinguished from an unentitled or unauthorized one",
		"affected_resources": [],
		"details": {
			"evaluation_status": "indeterminate",
			"total_policies": 0,
		},
	}
}

# Policies exist and none is On. This half of the audit is objective.
assessed_result := output if {
	input.total_policies > 0
	input.enabled_policy_count == 0

	output := {
		"compliant": false,
		"message": sprintf("%d DLP policy/policies exist and none is On (Mode Enable)", [input.total_policies]),
		"affected_resources": ["No DLP policy is On"],
		"details": {
			"evaluation_status": "assessed",
			"total_policies": input.total_policies,
			"enabled_policy_count": 0,
			"dlp_policy_modes": input.dlp_policy_modes,
		},
	}
}

# At least one policy is On. Applicability to the organization's data is the
# auditor's call, so the facts are reported and no pass is asserted.
assessed_result := output if {
	input.enabled_policy_count > 0

	output := {
		"compliant": null,
		"message": sprintf(
			"%d of %d DLP policies are On; applicability to the data the organization needs to protect is an auditor judgement",
			[input.enabled_policy_count, input.total_policies],
		),
		"affected_resources": [],
		"details": {
			"evaluation_status": "requires_human_review",
			"total_policies": input.total_policies,
			"enabled_policy_count": input.enabled_policy_count,
			"dlp_policy_modes": input.dlp_policy_modes,
			"review_obligation": "CIS Microsoft 365 Foundations control 3.2.1 audit step 3: verify that the organization is using policies applicable to the types of data that is in their interest to protect. AutoAudit does not decide this.",
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
	is_count(input.enabled_policy_count)
	input.enabled_policy_count <= input.total_policies
	is_array(input.dlp_policy_modes)
	every mode in input.dlp_policy_modes { is_string(mode) }
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
