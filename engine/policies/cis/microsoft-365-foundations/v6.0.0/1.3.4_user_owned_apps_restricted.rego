# METADATA
# title: Ensure 'User owned apps and services' is restricted
# description: |
#   Allowing users to own apps and services increases the risk of unauthorized
#   application integrations and data exposure. Restrict this capability so that
#   only approved administrators can enable and manage user apps and services.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.3.4
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - OrgSettings-AppsAndServices.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_1_3_4

import rego.v1

default assessed_result := {
	"compliant": null,
	"message": "Evaluation failed: unable to retrieve Microsoft 365 Apps and Services settings",
	"details": {},
}

has_modern if {
	input.is_office_store_enabled != null
	input.is_app_and_services_trial_enabled != null
} else := false

unknown if {
	input.user_owned_apps_enabled == null
	input.is_office_store_enabled == null
}

else if {
	input.user_owned_apps_enabled == null
	input.is_app_and_services_trial_enabled == null
}

else := false

compliant if {
	has_modern
	input.is_office_store_enabled == false
	input.is_app_and_services_trial_enabled == false
} else if {
	not has_modern
	input.user_owned_apps_enabled == false
} else := false

assessed_result := output if {
	office := input.is_office_store_enabled
	trial := input.is_app_and_services_trial_enabled
	legacy_enabled := input.user_owned_apps_enabled

	output := {
		# CIS intent: restricted => disabled
		"compliant": compliant,
		"message": generate_message(compliant, unknown),
		"affected_resources": generate_affected(compliant, unknown),
		"details": {
			"is_office_store_enabled": office,
			"is_app_and_services_trial_enabled": trial,
			"user_owned_apps_enabled": legacy_enabled,
			"collector_error": input.collector_error,
		},
	}
}

generate_message(true, false) := "User owned apps and services are restricted (disabled)"
generate_message(false, false) := "User owned apps and services are not restricted (enabled)"
generate_message(_, true) := "Unable to determine whether user owned apps and services are restricted"

generate_affected(true, false) := []
generate_affected(false, false) := ["User owned apps and services are enabled"]
generate_affected(_, true) := ["User owned apps and services setting unknown"]

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
	apps_settings_complete
}

# A nested collector error invalidates a partial response as well as a top-level error.
evidence_error if {
	some path, value
	walk(input, [path, value])
	count(path) > 0
	path[count(path) - 1] in {"collector_error", "error"}
	value != null
}

apps_settings_complete if {
	is_boolean(input.is_office_store_enabled)
	is_boolean(input.is_app_and_services_trial_enabled)
}

# Preserve the collector's legacy field only when both modern fields are explicitly absent.
apps_settings_complete if {
	input.is_office_store_enabled == null
	input.is_app_and_services_trial_enabled == null
	is_boolean(input.user_owned_apps_enabled)
}
