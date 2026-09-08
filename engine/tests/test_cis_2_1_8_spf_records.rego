package cis.microsoft_365_foundations.v6_0_0.test_control_2_1_8

import rego.v1

# An empty domains array is what the collector emits when the DNS lookup returns
# nothing, and no tenant has zero accepted domains, so it is a failed collection
# rather than a tenant with nothing to check.

test_compliant if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all"}]}
	object.get(result, "compliant", "undefined") == true
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

# INPUT RESTORED, ASSERTION INVERTED. This input is the one this case fed at
# HEAD; an earlier round rewrote it in place to carry a status so it would keep
# asserting false, which is the move that deleted the only coverage of
# status-free absence. The input is back verbatim and the assertion says what
# the repaired policy actually returns.
#
# From false to null, deliberately: an empty record string with no status, no
# spf_error key and nothing else is an object that never recorded whether a
# lookup ran. Scoring a collection that may never have run as tenant
# noncompliance is what the execution plan forbids. The absence shapes that ARE
# conclusive are covered by their own cases - the "absent" status just below and
# the legacy spf_error forms further down.
test_non_compliant_missing_spf if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": ""}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# ADDED, not a rewrite of the case above. The collector emits an authoritative
# "absent" for a domain whose zone answered and published no SPF record. That is
# the shape a missing record actually arrives in, and it is tenant
# noncompliance.
test_authoritative_absence_with_empty_record_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "", "spf_lookup_status": "absent", "spf_error_code": "no_answer"}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_non_compliant_wrong_prefix if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "spf1 -all"}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent_evidence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_domains_empty if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": []}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_domains_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": null}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_domains_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": "contoso.com"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_domains_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": {}}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_domain_not_an_object if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": ["contoso.com"]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

# INPUT RESTORED, ASSERTION INVERTED, for the same reason as
# test_non_compliant_missing_spf above: this is the HEAD input, and a non-string
# payload with no status and no error field is malformed evidence rather than a
# tenant that published nothing.
test_spf_record_not_a_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": 1}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# ADDED, not a rewrite of the case above. A non-string payload alongside an
# authoritative "absent" is still the tenant publishing no record; the status is
# what makes the absence provable.
test_authoritative_absence_with_non_string_record_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": 1, "spf_lookup_status": "absent", "spf_error_code": "no_matching_txt"}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_collector_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all"}], "collector_error": "graph returned 503"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_nested_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all"}], "error": "authentication failed"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_null if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as null
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_array if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as []
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_string if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as "bad"
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

test_root_number if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as 1
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

# CIS v6.0.0 2.1.8 audit step: the value must exist AND include
# v=spf1 include:spf.protection.outlook.com, which is what designates Exchange
# Online as a sender. Both halves are checked, and the version token is the ABNF
# literal "v=spf1" - case-insensitive, terminated by a space or the record end.

test_record_designating_exchange_online_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_uppercase_version_and_include_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "V=SPF1 INCLUDE:SPF.PROTECTION.OUTLOOK.COM -ALL", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_explicit_pass_qualifier_on_the_include_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 +include:spf.protection.outlook.com ~all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_record_without_exchange_online_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_record_authorising_every_sender_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 +all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# RFC 7208 s4.5: the version section is terminated by a space or the end of the
# record, so "v=spf10 ..." is not an SPF record and must not pass on the prefix.
test_version_token_boundary_v_spf10_is_not_a_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf10 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# DEFECT B: a DNS lookup that never completed is a failed collection, not a
# tenant that failed to publish SPF. The collector now labels every lookup with
# spf_lookup_status ("found", "absent" or "lookup_failed"); a domain whose
# lookup failed must never appear in affected_resources and must stop the
# control claiming a pass. Each indeterminate case below asserts the computed
# details as well, so it cannot be satisfied by the `default result` alone.

test_all_domains_resolve_and_publish if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [
		{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "found", "spf_error_code": null},
		{"domain": "fabrikam.com", "spf_record": "v=spf1 include:spf.protection.outlook.com ~all", "spf_lookup_status": "found", "spf_error_code": null},
	]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
	object.get(result.details, "coverage", "undefined") == "complete"
	object.get(result.details, "total_domains", "undefined") == 2
}

test_authoritative_absence_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "absent", "spf_error_code": "no_answer", "spf_error": "No TXT records"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_authoritative_absence_no_matching_txt_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "absent", "spf_error_code": "no_matching_txt", "spf_error": null}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# RFC 7208 s4.5: more than one SPF record is a permerror, so the domain has no
# usable SPF policy. The lookup answered, so it is tenant state.
test_multiple_spf_records_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "absent", "spf_error_code": "multiple_records", "spf_error": "Multiple SPF records published"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_timeout_is_indeterminate_not_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "timeout", "spf_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "coverage", "undefined") == "partial"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
	object.get(result.details, "total_domains", "undefined") == 1
	is_string(result.message)
	count(result.message) > 0
	is_object(result.details)
}

# NXDOMAIN on the domain root is a lookup failure for SPF: a Graph-verified
# domain proved its zone existed, so the SPF question was never answered.
test_root_nxdomain_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "nxdomain", "spf_error": "Domain not found"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_no_nameservers_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "no_nameservers", "spf_error": "No nameservers available"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_unexpected_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "unexpected_error", "spf_error": "empty label"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# Graph can hand back a verified domain object with no id. Nothing was asked
# about that domain, and the control must not name a resource it never
# identified.
test_domain_without_a_name_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": null, "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "missing_domain_id"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_domain_without_a_name_is_never_an_affected_resource if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": null, "spf_record": null, "spf_lookup_status": "absent", "spf_error_code": "no_answer"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

test_mixed_pass_and_lookup_failure_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [
		{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"},
		{"domain": "fabrikam.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "timeout"},
	]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "coverage", "undefined") == "partial"
	object.get(result.details, "total_domains", "undefined") == 2
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_mixed_fail_and_lookup_failure_reports_only_the_confirmed_failure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [
		{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"},
		{"domain": "fabrikam.com", "spf_record": null, "spf_lookup_status": "absent", "spf_error_code": "no_answer"},
		{"domain": "adventure-works.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "timeout"},
	]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["fabrikam.com"]
	object.get(result.details, "coverage", "undefined") == "partial"
	count(object.get(result.details, "unresolved_domains", [])) == 1
}

test_every_domain_lookup_fails_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [
		{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "timeout"},
		{"domain": "fabrikam.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "no_nameservers"},
	]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 2
}

# Evidence collected before this change carries no status field at all. A record
# string is still evidence of what was published, so it is judged on its
# contents; the absence of a record in that shape is not evidence of anything,
# because there is no status to say whether the lookup answered. The former
# test_pre_change_evidence_without_status_keeps_failing asserted that shape was
# tenant noncompliance, which is the mapping the plan forbids without exception:
# a DNS timeout scored as a finding against the tenant.
test_pre_change_evidence_without_status_and_without_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_pre_change_evidence_without_status_keeps_passing if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# An unrecognised status is not an authoritative answer either, so it must not
# be read as tenant noncompliance.
test_unknown_status_does_not_become_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "partially_resolved"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# Contradictory evidence - a record alongside a failure status - is a collection
# we know did not complete, so it is scored neither pass nor fail.
test_record_alongside_lookup_failure_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "lookup_failed", "spf_error_code": "unexpected_error"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The contradiction runs the other way too: a record sitting next to a claim
# that the tenant published nothing must not be scored as a pass.
test_record_alongside_authoritative_absence_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "absent", "spf_error_code": "no_answer"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# Truncated evidence: the lookup claims to have read a record and the payload is
# not there. That is not proof the tenant published nothing.
test_found_status_without_a_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# A status key that is present but never labelled is not the pre-change shape.
test_explicit_null_status_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": null}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_non_string_status_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": 1}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# SPF is evaluated left to right and the first matching mechanism wins, so an
# "all" ahead of the include ends evaluation before Exchange Online is reached.
# The record names the include and designates nobody.
test_all_mechanism_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -all include:spf.protection.outlook.com", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# The collector reports how many verified domains it examined. A domains array
# shorter than that count is truncated evidence, which is neither a pass nor a
# finding.
test_truncated_domain_population_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {
		"total_domains": 2,
		"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}],
	}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_intact_domain_population_is_scored if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {
		"total_domains": 1,
		"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}],
	}
	object.get(result, "compliant", "undefined") == true
	object.get(result.details, "total_domains", "undefined") == 1
}

# The pre-change shape put the reason a lookup failed in the free-text error
# field. A record sitting next to one is contradictory evidence, whichever way
# the record itself would have been scored.
test_pre_change_record_alongside_an_error_string_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -all", "spf_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_pre_change_passing_record_alongside_an_error_string_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
}

# A status key present but null is not the pre-change shape, and a record beside
# it does not rescue it. Without the record this case cannot tell the two apart.
test_explicit_null_status_with_a_passing_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_lookup_status": null}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# DEFECT 1: preemption is not only about "all". SPF is evaluated left to right
# and the FIRST matching mechanism wins, whatever qualifier it carries
# (RFC 7208 s4.6.2). A negatively qualified include of the same domain sitting
# ahead of the positive one therefore ends evaluation before the positive
# include is ever reached: every sender the positive include would have
# authorised has already matched the "-include:" and been given an SPF Fail.
# The record names Exchange Online twice and designates it not at all, so it
# does not satisfy the audit step.
test_negated_include_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -include:spf.protection.outlook.com include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# "~include:" is a softfail and "?include:" is neutral. Neither designates the
# sender as authorised, and both still match first and end evaluation.
test_softfail_include_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 ~include:spf.protection.outlook.com +include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_neutral_include_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "V=SPF1 ?INCLUDE:SPF.PROTECTION.OUTLOOK.COM INCLUDE:SPF.PROTECTION.OUTLOOK.COM -ALL", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# The mirror case, so the fix does not overcorrect: a negated include AFTER the
# positive one is unreachable, because the positive include matched first.
# Exchange Online is designated and the record passes.
test_negated_include_after_the_include_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A negated include of a DIFFERENT domain says nothing about Exchange Online:
# a sender matching it was never going to match the Exchange Online include.
test_negated_include_of_another_domain_does_not_preempt if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -include:_spf.example.net include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# DEFECT 5 (finding COR-02): the pre-change collector wrote dns.resolver.NoAnswer
# as the exact string "No TXT records". NoAnswer means the zone answered and
# holds no TXT record of any kind, so that string does prove the tenant
# published no SPF record. Reading it as "could not check" drops a real finding
# out of the compliance denominator on every historical scan, which is the same
# mistake as scoring a timeout against the tenant, only in the other direction.
test_pre_change_no_txt_records_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "No TXT records"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# Only that one legacy string is authoritative. The other three the pre-change
# collector could emit each describe a lookup that never answered the SPF
# question, so they stay unresolved.
test_pre_change_domain_not_found_stays_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "Domain not found"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_pre_change_no_nameservers_stays_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "No nameservers available"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The pre-change collector's last except clause wrote str(e), so a legacy error
# field can hold arbitrary free text. It proves nothing either way.
test_pre_change_free_text_error_stays_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "The resolution lifetime expired after 5.402 seconds"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The legacy string is authoritative about absence, not about a record: a
# record sitting next to it is still the contradiction every other shape is.
test_pre_change_no_txt_records_alongside_a_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_error": "No TXT records"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The legacy shape is the one with no status key. A domain that carries a
# status must be judged by it, so a status that says the lookup failed is not
# rescued by a legacy error string that happens to sit beside it.
test_no_txt_records_string_does_not_override_a_failure_status if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "timeout", "spf_error": "No TXT records"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# A present-and-null legacy spf_error does NOT prove absence, and this case
# exists to keep that from being "fixed" again. The pre-change collector preset
# spf_error to None and wrote it only from an except clause, so null does mean
# the TXT query returned - but its record selection was
# txt_value.startswith("v=spf1"), CASE-SENSITIVE, while RFC 7208 s4.5 with RFC
# 5234 s2.3 makes the version token case-insensitive and this control reads it
# that way. A domain publishing
#
#     V=SPF1 include:spf.protection.outlook.com -all
#
# is compliant under this control (see the uppercase case near the top of this
# file, which asserts true) and produced exactly this legacy shape. Scoring it
# false would report a compliant tenant as a finding, and nothing in the record
# tells the two apart.
#
# The legacy evidence that IS conclusive is the "No TXT records" string: an
# empty TXT RRset holds no SPF record in any spelling. That one is normalised;
# this one is not.
test_legacy_present_and_null_spf_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "is_verified": true, "spf_record": null, "dmarc_record": null, "dmarc_policy": null, "spf_error": null, "dmarc_error": null}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The confound itself, stated as a test: the uppercase record this control calls
# compliant is the one the legacy matcher missed.
test_uppercase_spf_record_is_compliant_which_is_why_legacy_null_cannot_be_absence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_lookup_status": "found", "spf_record": "V=SPF1 include:spf.protection.outlook.com -all"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# The distinction is the KEY's presence, not its value. The two restored cases
# at the top of this file feed objects that never mention spf_error, and they
# stay indeterminate; this one adds the explicit null-record spelling of the
# same silence.
test_missing_spf_error_key_is_still_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# A present-and-null error is legacy-shape evidence only. A domain carrying the
# new status fields is judged by those.
test_present_and_null_spf_error_beside_lookup_failed_status_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": null, "spf_lookup_status": "lookup_failed", "spf_error_code": "timeout"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

# The fully qualified spelling, with the trailing root dot, names the same DNS
# domain and preempts just the same. Without this the negation is trivially
# sidestepped by a dot.
test_fully_qualified_negated_include_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -include:spf.protection.outlook.com. include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_fully_qualified_softfail_include_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 ~include:spf.protection.outlook.com. include:spf.protection.outlook.com ~all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_fully_qualified_neutral_include_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 ?include:spf.protection.outlook.com. +include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# Tabs are folded to spaces before the record is split into terms, so a record
# separated by them is read the same way and preemption still applies.
test_tab_separated_negated_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1\t-include:spf.protection.outlook.com\tinclude:spf.protection.outlook.com\t-all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# The record may name Exchange Online more than once. If the FIRST positive
# include is reachable the record designates Exchange Online, whatever follows.
test_repeated_positive_includes_with_a_later_negation_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -include:spf.protection.outlook.com include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# "all" and a negated include of the same domain are not the only terms that can
# end evaluation before the include is reached. RFC 7208 s5.6: an ip4/ip6
# mechanism with a /0 prefix matches the entire address family whatever address
# precedes the slash, so a negatively qualified one hands every sender of that
# family a Fail first. Both families have to be covered before the record
# designates nobody.

test_negated_whole_address_space_before_the_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -ip4:0.0.0.0/0 -ip6:::/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# The address in front of a /0 is irrelevant to what the mechanism matches, and
# softfail and neutral qualifiers end evaluation just as fail does.
test_negated_whole_address_space_any_address_or_qualifier_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 ~ip4:1.2.3.4/0 ?ip6:2001:db8::/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# One family is not enough, and this is the case that keeps the rule from
# inventing findings: Exchange Online sends over IPv4 as well, so "we do not
# send over IPv6" still designates Exchange Online and must stay a pass.
test_negated_ipv6_only_still_designates_exchange_online if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -ip6:::/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_negated_ipv4_only_still_designates_exchange_online if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -ip4:0.0.0.0/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# Position is what matters, as it does for "all": a sender matching the include
# has already been authorised before these are reached.
test_negated_whole_address_space_after_the_include_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -ip4:0.0.0.0/0 -ip6:::/0 -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# Ordinary negated ranges are the everyday way a tenant excludes a network. They
# match a subset of senders, not all of them, so they preempt nothing.
test_ordinary_negated_ranges_before_the_include_still_pass if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 ip4:203.0.113.0/24 -ip4:198.51.100.0/24 -ip6:2001:db8::/32 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# RFC 7208 s4.6.2 stops at the first mechanism that MATCHES, not at the first
# one present. A positively qualified mechanism ahead of the blanket denials
# hands the senders it covers a Pass before those denials are reached, so the
# record does authorise senders and must not be reported as designating nobody.
test_positive_mechanism_ahead_of_the_blanket_denials_is_not_preemption if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 ip4:40.92.0.0/15 -ip4:0.0.0.0/0 -ip6:::/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A term the preemption rule cannot classify is a reason to leave the record
# alone, not to fail it: "mx" carries the default "+" qualifier and matches the
# domain's own mail exchangers.
test_unqualified_mechanism_ahead_of_the_blanket_denials_is_not_preemption if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 mx -ip4:0.0.0.0/0 -ip6:::/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# Other negatively qualified mechanisms ahead of the denials change nothing:
# none of them can authorise a sender, so every sender still reaches a denial
# before the include.
test_other_negated_mechanisms_do_not_rescue_the_blanket_denials if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -a -ip4:0.0.0.0/0 ~ip6:2001:db8::/0 include:spf.protection.outlook.com -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# ------------------------------------------------ fully qualified include name
# RFC 1035 s3.1: a trailing root dot names the same DNS domain. A record written
# "include:spf.protection.outlook.com." does include spf.protection.outlook.com
# and does designate Exchange Online, so the audit step passes it. An earlier
# round recognised the spelling only on the negating side, which meant one
# spelling could stop a record passing but could never make one pass - a false
# finding against a compliant tenant.
test_fully_qualified_include_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com. -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_fully_qualified_include_with_pass_qualifier_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 +include:spf.protection.outlook.com. ~all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# Recognising the spelling positively must not weaken preemption: an "all" ahead
# of the fully qualified include still ends evaluation before it is reached.
test_all_before_the_fully_qualified_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -all include:spf.protection.outlook.com.", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# A negated fully qualified include ahead of a positive fully qualified include
# preempts it too - the two spellings are one domain on both sides.
test_negated_then_positive_fully_qualified_include_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 -include:spf.protection.outlook.com include:spf.protection.outlook.com. -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# A different domain that merely ends in the same characters is not Exchange
# Online, dot or no dot.
test_lookalike_include_domain_is_still_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:evilspf.protection.outlook.com. -all", "spf_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}
