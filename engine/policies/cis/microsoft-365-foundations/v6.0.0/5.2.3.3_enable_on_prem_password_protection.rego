# METADATA
# title: Ensure password protection is enabled for on-prem Active Directory
# description: Enable password protection for on-premises AD.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad
#   description: Password protection and banned passwords (conceptual)
# custom:
#   control_id: CIS-5.2.3.3
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - GroupSettings.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_3

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine on-prem password protection configuration",
	"details": {},
}

default compliant := false

compliant if {
	input.on_prem_protection_enabled == true
}

msg := "On-prem password protection is enabled" if compliant
msg := "On-prem password protection is not enabled" if not compliant

assessed_result := output if {
	enabled := input.on_prem_protection_enabled

	output := {
		"compliant": compliant,
		"message": msg,
		"affected_resources": ["passwordProtectionPolicy" | not compliant],
		"details": {
			"on_prem_protection_enabled": enabled,
			"enforce_custom_banned_passwords": input.enforce_custom_banned_passwords,
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
	is_boolean(input.on_prem_protection_enabled)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
