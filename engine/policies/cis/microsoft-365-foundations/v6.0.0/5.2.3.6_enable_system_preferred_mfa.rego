# METADATA
# title: Ensure system-preferred multifactor authentication is enabled
# description: Enable system-preferred MFA.
# related_resources:
# - ref: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-system-preferred
#   description: System-preferred MFA (conceptual)
# custom:
#   control_id: CIS-5.2.3.6
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Policy.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_5_2_3_6

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Unable to determine system-preferred MFA configuration",
	"details": {},
}

# Note: some tenants may not expose this setting; this remains best-effort.
default compliant := false

compliant if {
	policy := input.authentication_methods_policy
	prefs := object.get(policy, "systemCredentialPreferences", {})
	object.get(prefs, "state", null) == "enabled"
}

msg := "System-preferred MFA is enabled" if compliant
msg := sprintf(
	"System-preferred MFA is not enabled (state=%v)",
	[object.get(object.get(input.authentication_methods_policy, "systemCredentialPreferences", {}), "state", null)],
) if not compliant

# Best-effort: check tenant-level setting on authenticationMethodsPolicy if present.
assessed_result := output if {
	policy := input.authentication_methods_policy
	prefs := object.get(policy, "systemCredentialPreferences", {})
	state := object.get(prefs, "state", null)

	output := {
		"compliant": compliant,
		"message": msg,
		"details": {
			"system_credential_preferences_state": state,
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
	is_object(input.authentication_methods_policy)
	is_object(input.authentication_methods_policy.systemCredentialPreferences)
	is_string(input.authentication_methods_policy.systemCredentialPreferences.state)
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}
