# METADATA
# title: Ensure DLP policies are enabled for Microsoft Teams
# description: |
#   The benchmark's PowerShell audit filters DLP compliance policies to those
#   whose Workload matches Teams, then requires Mode "Enable" and a TeamsLocation
#   that includes All. TeamsLocationException contents are an organizational
#   judgement: they are reported and never decide the verdict.
#   CANDIDATE: this file is not wired to any scan. See engine/policies/candidate/README.md.
#   Procedure source: docs/engine/Framework/CIS_M365_Benchmarks.json, which self-declares edition "v6.0.1 - 2-26-2026"; the licensed v6.0.0 procedure has not been obtained.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-3.2.2
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Compliance
#   requires_permissions:
#   - Exchange.ManageAsApp

package cis.microsoft_365_foundations.v6_0_0.control_3_2_2

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

# CIS 3.2.2 audit step 3 says "If nothing returns, then there are no policies
# that include Teams and remediation is required" -- but 3.2.2's Profile
# Applicability is "E5 Level 1" ONLY, and Teams DLP requires that entitlement.
# An E3 tenant CANNOT create a Teams-workload policy, so from this evidence
# alone "no Teams policy" is indistinguishable from "not entitled to have one".
# Calling that a violation would represent an absent capability as tenant
# noncompliance. The objective facts are reported; the verdict is withheld until
# entitlement is established (see the Purview readiness probe).
assessed_result := output if {
	input.total_policies > 0
	input.teams_policy_count == 0

	output := {
		"compliant": null,
		"message": "No DLP policy includes the Teams workload; CIS 3.2.2 applies to E5 only and entitlement was not established from this evidence",
		"affected_resources": [],
		"details": {
			"evaluation_status": "indeterminate",
			"total_policies": input.total_policies,
			"teams_policy_count": 0,
			"profile_applicability": "E5 Level 1",
			"review_obligation": "CIS Microsoft 365 Foundations control 3.2.2 applies to E5 Level 1 only. Confirm the tenant is entitled to Teams DLP before reading an absent Teams policy as a violation.",
		},
	}
}

# Teams policies exist but the location evidence could not be read as a list of
# names, so the "TeamsLocation includes All" half of the audit is unknown.
assessed_result := output if {
	input.teams_policy_count > 0
	input.teams_enforcing_policy_count == null

	output := {
		"compliant": null,
		"message": "Teams DLP location evidence is unreadable",
		"affected_resources": [],
		"details": {
			"evaluation_status": "indeterminate",
			"total_policies": input.total_policies,
			"teams_policy_count": input.teams_policy_count,
			"teams_policy_mode_enable_count": input.teams_policy_mode_enable_count,
		},
	}
}

# CIS 3.2.2 audit steps 4 and 5: Mode must be Enable and TeamsLocation must
# include All. No policy satisfies both.
assessed_result := output if {
	input.teams_policy_count > 0
	is_number(input.teams_enforcing_policy_count)
	input.teams_enforcing_policy_count == 0

	output := {
		"compliant": false,
		"message": sprintf("%d Teams DLP policy/policies exist but none has Mode Enable with TeamsLocation All", [input.teams_policy_count]),
		"affected_resources": [p.name | some p in input.teams_policies],
		"details": {
			"evaluation_status": "assessed",
			"total_policies": input.total_policies,
			"teams_policy_count": input.teams_policy_count,
			"teams_policy_mode_enable_count": input.teams_policy_mode_enable_count,
			"teams_enforcing_policy_count": 0,
			"teams_location_exception_names": input.teams_location_exception_names,
		},
	}
}

# EVERY returned Teams policy has Mode Enable and TeamsLocation All. CIS audit
# step 4 reads "For any returned policy verify Mode is set to Enable" and step 5
# "Verify TeamsLocation includes All" -- a check applied to each returned policy,
# not to one of them. Audit step 6 (TeamsLocationException review) is reported,
# never decided.
assessed_result := output if {
	input.teams_policy_count > 0
	is_number(input.teams_enforcing_policy_count)
	input.teams_enforcing_policy_count == input.teams_policy_count

	output := {
		"compliant": true,
		"message": sprintf("%d Teams DLP policy/policies have Mode Enable and TeamsLocation All", [input.teams_enforcing_policy_count]),
		"affected_resources": [],
		"details": {
			"evaluation_status": "assessed",
			"total_policies": input.total_policies,
			"teams_policy_count": input.teams_policy_count,
			"teams_policy_mode_enable_count": input.teams_policy_mode_enable_count,
			"teams_enforcing_policy_count": input.teams_enforcing_policy_count,
			"teams_location_exception_names": input.teams_location_exception_names,
			"review_obligation": "CIS Microsoft 365 Foundations control 3.2.2 audit step 6: verify TeamsLocationException includes only permitted exceptions. AutoAudit reports the exceptions and does not decide them.",
		},
	}
}

# Some but not all returned Teams policies enforce. The procedure does not say
# whether a partially-enforcing tenant passes, and inventing either answer would
# be inventing determinacy the source does not have. Reported for review.
assessed_result := output if {
	input.teams_policy_count > 0
	is_number(input.teams_enforcing_policy_count)
	input.teams_enforcing_policy_count > 0
	input.teams_enforcing_policy_count < input.teams_policy_count

	output := {
		"compliant": null,
		"message": sprintf("%d of %d Teams DLP policies have Mode Enable with TeamsLocation All", [input.teams_enforcing_policy_count, input.teams_policy_count]),
		"affected_resources": [],
		"details": {
			"evaluation_status": "indeterminate",
			"total_policies": input.total_policies,
			"teams_policy_count": input.teams_policy_count,
			"teams_policy_mode_enable_count": input.teams_policy_mode_enable_count,
			"teams_enforcing_policy_count": input.teams_enforcing_policy_count,
			"teams_location_exception_names": input.teams_location_exception_names,
			"review_obligation": "CIS Microsoft 365 Foundations control 3.2.2 audit steps 4 and 5 are applied to each returned policy. Some returned Teams policies do not enforce; the benchmark does not state whether a partially-enforcing tenant passes.",
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
	is_count(input.teams_policy_count)
	is_count(input.teams_policy_mode_enable_count)
	input.teams_policy_count <= input.total_policies
	input.teams_policy_mode_enable_count <= input.teams_policy_count
	is_count_or_null(input.teams_enforcing_policy_count)
	enforcing_within_mode_enable
	is_names_or_null(input.teams_location_exception_names)
	is_array(input.teams_policies)
	count(input.teams_policies) == input.teams_policy_count
	every p in input.teams_policies { is_object(p); is_string(p.name); is_string(p.mode)}
}

# A policy that enforces (Mode Enable AND TeamsLocation All) is by construction one
# of the Mode Enable policies, so a larger enforcing count is inconsistent evidence
# rather than a stronger result.
enforcing_within_mode_enable if input.teams_enforcing_policy_count == null

enforcing_within_mode_enable if {
	is_number(input.teams_enforcing_policy_count)
	input.teams_enforcing_policy_count <= input.teams_policy_mode_enable_count
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

is_count_or_null(v) if v == null

is_count_or_null(v) if is_count(v)

is_names_or_null(v) if v == null

is_names_or_null(v) if {
	is_array(v)
	every n in v { is_string(n) }
}
