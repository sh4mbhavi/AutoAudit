# METADATA
# title: Ensure Office 365 SharePoint infected files are disallowed for download
# description: |
#   By default, SharePoint Online allows files that Defender for Office 365
#   has detected as infected to be downloaded. Disallowing download of
#   infected files prevents inadvertent sharing of malicious content.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-7.3.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: SharePoint
#   requires_permissions:
#   - SharePoint.Admin

package cis.microsoft_365_foundations.v6_0_0.control_7_3_1

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the SharePoint tenant setting is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean DisallowInfectedFileDownload on the SharePoint tenant; collector errors invalidate the evidence.",
	},
}

# A collector error invalidates even otherwise complete evidence.
has_collector_error(obj) if {
	object.get(obj, "collector_error", null) != null
}

has_collector_error(obj) if {
	object.get(obj, "error", null) != null
}

valid_evidence if {
	is_object(input)
	not has_collector_error(input)
	is_boolean(input.disallow_infected_file_download)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"disallow_infected_file_download": input.disallow_infected_file_download},
} if {
	valid_evidence
	compliant := input.disallow_infected_file_download == true
	affected := ["SharePoint tenant: infected file download" | not compliant]
}

generate_message(true) := "Infected SharePoint files are disallowed for download"

generate_message(false) := "Infected SharePoint files are allowed for download (DisallowInfectedFileDownload is False)"
