# METADATA
# title: Ensure Microsoft 365 audit log search is Enabled
# description: |
#   Microsoft 365 audit log search should be enabled to record user and
#   administrator activities across the organization. This supports
#   security monitoring, investigations, and compliance auditing.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-3.1.1
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Compliance
#   requires_permissions:
#   - Exchange.Manage

package cis.microsoft_365_foundations.v6_0_0.control_3_1_1

import rego.v1

# The previous default was a schema-complete `compliant: false`, so a tenant
# whose audit-log evidence never arrived was stored as having failed the audit
# control -- the one control whose failure most obviously implies "no evidence".
default result := {
	"compliant": null,
	"message": "Unable to evaluate: Microsoft 365 audit log search status is unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a boolean UnifiedAuditLogIngestionEnabled from the admin audit log configuration; collector errors invalidate the evidence.",
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
	is_boolean(input.unified_audit_log_ingestion_enabled)
}

result := {
	"compliant": compliant,
	"message": generate_message(compliant),
	"affected_resources": affected,
	"details": {"unified_audit_log_ingestion_enabled": input.unified_audit_log_ingestion_enabled},
} if {
	valid_evidence
	compliant := input.unified_audit_log_ingestion_enabled == true
	affected := ["Microsoft 365 unified audit log ingestion" | not compliant]
}

generate_message(true) := "Microsoft 365 audit log search is enabled (UnifiedAuditLogIngestionEnabled is True)"

generate_message(false) := "Microsoft 365 audit log search is disabled (UnifiedAuditLogIngestionEnabled is False)"
