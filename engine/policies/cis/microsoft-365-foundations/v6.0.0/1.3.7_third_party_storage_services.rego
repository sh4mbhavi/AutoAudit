# METADATA
# title: Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'
# description: |
#   Third-party storage services (Dropbox, Google Drive, Box, etc.) can be
#   enabled for users in Microsoft 365 on the web, allowing them to store and
#   share documents outside organizational control alongside OneDrive and
#   team sites. This increases the risk of data breaches and makes it
#   difficult to maintain data privacy and security. Restrict the "Third
#   Party Storage Services" service principal in Entra ID to prevent this.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-1.3.7
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: medium
#   service: EntraID
#   requires_permissions:
#   - Application.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_1_3_7

import rego.v1

third_party_storage_app_id := "c1f33bc0-bdb4-4248-ba9b-096807ddb43e"

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the Third Party Storage Services service principal is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean service_principal_exists, and a boolean account_enabled whenever it exists; collector errors invalidate the evidence.",
	},
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

# A service principal that has never been created is a real, determinate answer:
# third-party storage is available by default. Only its *state* can be unknown.
valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	input.service_principal_exists == false
}

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	input.service_principal_exists == true
	is_boolean(input.account_enabled)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {
		"service_principal_exists": input.service_principal_exists,
		"account_enabled": object.get(input, "account_enabled", null),
		"app_id": third_party_storage_app_id,
	},
} if {
	valid_evidence
	compliant := restricted
	affected := [sprintf("Third Party Storage Services (appId: %s)", [third_party_storage_app_id]) | not compliant]
}

# Compliant only when the service principal has been created AND disabled.
default restricted := false

restricted if {
	input.service_principal_exists == true
	input.account_enabled == false
}

generate_message(true) := "The 'Third Party Storage Services' service principal is disabled; third-party storage is restricted."

generate_message(false) := "Third-party storage is not restricted: the 'Third Party Storage Services' service principal is absent or still enabled."
