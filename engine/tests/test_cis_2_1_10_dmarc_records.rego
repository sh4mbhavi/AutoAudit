package cis.microsoft_365_foundations.v6_0_0.test_control_2_1_10

import rego.v1

# CIS v6.0.0 2.1.10 audit step 3 requires the record to carry, at minimum,
# v=DMARC1, p=quarantine or p=reject, pct=100, and rua and ruf reporting
# addresses. Every record expected to pass anywhere in this file meets all four;
# a record missing any one of them is a finding.

# INPUT RESTORED, ASSERTION INVERTED. This is the input this case fed at HEAD;
# an earlier round rewrote it in place to add pct=100 and a ruf so the old
# `true` assertion would keep passing, which is the move that hid a defect last
# round. The input is back verbatim and the assertion says what the repaired
# policy returns.
#
# From true to false, deliberately: audit step 3 asks for "at minimum ...
# v=DMARC1; (p=quarantine OR p=reject), pct=100, rua=mailto:<reporting email
# address> and ruf=mailto:<reporting email address>", and this record carries
# neither pct nor ruf. The old assertion encoded RFC 7489's default-pct reading,
# which the benchmark does not ask for. The full-flag record it was rewritten to
# is covered by its own case below.
test_compliant_reject if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; rua=mailto:a@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["pct_does_not_cover_all_mail", "ruf_reporting_address_missing"]}]
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == ["contoso.com"]
}

# INPUT RESTORED, ASSERTION INVERTED, same reason: a bare "p=quarantine" record
# misses pct and both reporting addresses, all three of which audit step 3
# requires. The full-flag quarantine record is covered by its own case below.
test_compliant_quarantine if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=quarantine"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["pct_does_not_cover_all_mail", "rua_reporting_address_missing", "ruf_reporting_address_missing"]}]
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == ["contoso.com"]
}

# INPUT RESTORED, verdict unchanged from HEAD. The rewrite was unnecessary here
# - p=none fails on its own - and it cost the coverage of the monitoring-stage
# record CIS's own remediation step 1 produces.
test_non_compliant_policy_none if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none"}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

# INPUT RESTORED, ASSERTION INVERTED, for the same reason as
# test_compliant_reject above: this is the HEAD input, and an earlier round
# rewrote it in place to carry a status so it would keep asserting false.
#
# From false to null, deliberately: a domain object with no record, no status
# and no dmarc_error key never recorded whether a lookup ran, and scoring a
# collection that may never have run as tenant noncompliance is what the
# execution plan forbids. The absence shapes that ARE conclusive have their own
# cases - the "absent" status just below, and the legacy dmarc_error forms.
test_non_compliant_missing_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	result.affected_resources == []
}

# ADDED, not a rewrite of the case above. The collector emits an authoritative
# "absent" for a domain whose zone answered and published no DMARC record; that
# is the shape a missing record arrives in, and it is tenant noncompliance.
test_authoritative_absence_with_no_record_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "absent", "dmarc_error_code": "no_answer"}]}
	object.get(result, "compliant", "undefined") == false
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	count(result.affected_resources) > 0
}

test_absent_evidence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": []}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": null}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": "contoso.com"}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": ["contoso.com"]}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

# INPUT RESTORED, verdict unchanged from HEAD. The rewrite achieved nothing at
# all: a collector error invalidates the evidence whatever the record says.
test_collector_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; rua=mailto:a@contoso.com"}], "collector_error": "graph returned 503"}
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

# INPUT RESTORED, verdict unchanged from HEAD, same reason.
test_nested_error if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; rua=mailto:a@contoso.com"}], "error": "authentication failed"}
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as null
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as []
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as "bad"
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
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as 1
	object.get(result, "compliant", "undefined") == null
	is_string(result.message)
	count(result.message) > 0
	is_array(result.affected_resources)
	is_object(result.details)
	count(result.details) > 0
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	result.affected_resources == []
}

# CIS's own passing examples: an enforcing policy, applied to 100% of mail, with
# reporting addresses. The third one writes ruf bare, without the mailto:
# scheme, and CIS still calls it compliant.

test_cis_example_one_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com; fo=1", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_cis_example_three_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=quarantine; pct=100; sp=none; fo=1; ri=3600; rua=mailto:rua@contoso.com; ruf=ruf@contoso.com;", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# DEFECT 3. ASSERTION INVERTED, and the test renamed from
# test_pct_absent_defaults_to_all_mail: that test was added to defend RFC 7489
# s6.3's default-pct-to-100 behaviour, which the pinned benchmark does not ask
# for. CIS v6.0.0 2.1.10 audit step 3 is a prescribed configuration, not a
# behavioural equivalence: "Ensure that the record exists and has at minimum
# the following flags defined as follows: v=DMARC1; (p=quarantine OR p=reject),
# pct=100, rua=mailto:<reporting email address> and ruf=mailto:<reporting email
# address>". "Defined as follows" means the flag is present with that value,
# and all three of the benchmark's own passing examples spell pct=100 out. An
# auditor performing this step by hand records a record with no pct as not
# meeting the criteria, so the control does too. The benchmark is the authority
# here, not the RFC.
test_pct_absent_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["pct_does_not_cover_all_mail"]}]
}

# The benchmark's remediation section writes the monitoring-stage record
# "v=DMARC1; p=none; rua=...; ruf=..." with no pct at all, and then says the
# final state "requires implementing a policy of p=reject OR p=quarantine and
# pct=100". A record still at the monitoring stage misses both requirements.
test_pct_absent_with_policy_none_misses_both_requirements if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["policy_not_quarantine_or_reject", "pct_does_not_cover_all_mail"]}]
}

# pct=0 applies the enforcing policy to zero percent of mail, which is
# functionally p=none. CIS requires pct=100.
test_pct_zero_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=0; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["pct_does_not_cover_all_mail"]}]
}

test_pct_partial_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=1; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_missing_rua_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing"]}]
}

test_missing_ruf_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["ruf_reporting_address_missing"]}]
}

test_reporting_uri_without_an_address_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# RFC 7489 s6.6.3: a record set a receiver cannot read one policy out of applies
# no policy at all, so a repeated tag must not pass on whichever value the rule
# happens to find first.
test_duplicate_policy_tag_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["record_missing_or_malformed"]}]
}

# The version tag is terminated by the tag separator, so "v=DMARC10" is not a
# DMARC record and must not pass on the prefix.
test_version_token_boundary_v_dmarc10_is_not_a_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC10; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# A record that does not open with the version tag is not a DMARC record.
test_record_not_starting_with_the_version_tag_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "p=reject; v=DMARC1; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# RFC 7489 s6.4 permits whitespace either side of the "=", so this is a legal
# enforcing record and must not be reported as a finding.
test_whitespace_around_the_equals_still_parses if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p = reject; pct = 100; rua = mailto:rua@contoso.com; ruf = mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# DEFECT B: a DNS lookup that never completed is a failed collection, not a
# tenant that failed to publish DMARC. The collector now labels every lookup
# with dmarc_lookup_status ("found", "absent" or "lookup_failed"); a domain
# whose lookup failed must never appear in affected_resources and must stop the
# control claiming a pass. Each indeterminate case below asserts the computed
# details as well, so it cannot be satisfied by the `default result` alone.

test_all_domains_resolve_and_publish if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [
		{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found", "dmarc_error_code": null},
		{"domain": "fabrikam.com", "dmarc_record": "v=DMARC1; p=quarantine; pct=100; rua=mailto:rua@fabrikam.com; ruf=mailto:ruf@fabrikam.com", "dmarc_lookup_status": "found", "dmarc_error_code": null},
	]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
	object.get(result.details, "coverage", "undefined") == "complete"
	object.get(result.details, "total_domains", "undefined") == 2
}

# NXDOMAIN on the _dmarc label is authoritative absence only while the domain's
# own zone answered. The collector proves that before it labels this "absent",
# and only then is it the ordinary way DMARC is missing.
test_dmarc_label_nxdomain_with_a_resolving_zone_is_ordinary_absence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{
		"domain": "contoso.com",
		"dmarc_record": null,
		"spf_record": "v=spf1 include:spf.protection.outlook.com -all",
		"spf_lookup_status": "found",
		"dmarc_lookup_status": "absent",
		"dmarc_error_code": "nxdomain",
		"dmarc_error": "DMARC record not found",
	}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "coverage", "undefined") == "complete"
}

# The whole zone is gone: both queries return NXDOMAIN and nothing answered
# either question. 2.1.8 and 2.1.10 must agree that this domain was not
# assessed, rather than one going indeterminate and the other naming the domain
# as a confirmed finding.
test_whole_zone_nxdomain_is_indeterminate_for_both_controls if {
	evidence := {"domains": [{
		"domain": "lapsed.contoso.com",
		"spf_record": null,
		"spf_lookup_status": "lookup_failed",
		"spf_error_code": "nxdomain",
		"spf_error": "Domain not found",
		"dmarc_record": null,
		"dmarc_lookup_status": "lookup_failed",
		"dmarc_error_code": "parent_zone_unresolved",
	}]}
	dmarc := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as evidence
	spf := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_8.result with input as evidence
	object.get(dmarc, "compliant", "undefined") == null
	object.get(spf, "compliant", "undefined") == null
	dmarc.affected_resources == []
	spf.affected_resources == []
	object.get(dmarc.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(spf.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(dmarc.details, "unresolved_domains_count", "undefined") == 1
}

test_authoritative_absence_no_answer_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "absent", "dmarc_error_code": "no_answer", "dmarc_error": "No DMARC TXT record"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_authoritative_absence_no_matching_txt_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "absent", "dmarc_error_code": "no_matching_txt", "dmarc_error": null}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# RFC 7489 s6.6.3: more than one published DMARC record means no policy applies.
test_multiple_dmarc_records_is_tenant_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "absent", "dmarc_error_code": "multiple_records", "dmarc_error": "Multiple DMARC records published"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# A record that was found but carries p=none is a content failure judged by the
# policy rule, not a status question.
test_found_record_with_policy_none_still_fails if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found", "dmarc_error_code": null}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["policy_not_quarantine_or_reject"]}]
}

test_timeout_is_indeterminate_not_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "timeout", "dmarc_error": "DNS query timeout"}]}
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

test_no_nameservers_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "no_nameservers", "dmarc_error": "No nameservers available"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_unexpected_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "unexpected_error", "dmarc_error": "empty label"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# Graph can hand back a verified domain object with no id. No DNS question was
# asked about it, and a null must never reach affected_resources.
test_domain_without_a_name_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": null, "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "missing_domain_id"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_domain_without_a_name_is_never_an_affected_resource if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": null, "dmarc_record": null, "dmarc_lookup_status": "absent", "dmarc_error_code": "nxdomain"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

test_mixed_pass_and_lookup_failure_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [
		{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"},
		{"domain": "fabrikam.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "timeout"},
	]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "coverage", "undefined") == "partial"
	object.get(result.details, "total_domains", "undefined") == 2
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_mixed_fail_and_lookup_failure_reports_only_the_confirmed_failure if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [
		{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"},
		{"domain": "fabrikam.com", "dmarc_record": "v=DMARC1; p=none; pct=100; rua=mailto:rua@fabrikam.com; ruf=mailto:ruf@fabrikam.com", "dmarc_lookup_status": "found"},
		{"domain": "adventure-works.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "no_nameservers"},
	]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["fabrikam.com"]
	object.get(result.details, "coverage", "undefined") == "partial"
	count(object.get(result.details, "unresolved_domains", [])) == 1
}

test_every_domain_lookup_fails_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [
		{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "timeout"},
		{"domain": "fabrikam.com", "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "unexpected_error"},
	]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 2
}

# Evidence collected before this change carries no status field at all. A record
# string is still judged on its contents; the absence of a record in that shape
# is unknowable, because there is no status to say whether the lookup answered.
# The former test_pre_change_evidence_without_status_keeps_failing asserted that
# shape was tenant noncompliance, which is the mapping the plan forbids.
test_pre_change_evidence_without_status_and_without_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_pre_change_evidence_without_status_keeps_passing if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# An unrecognised status is not an authoritative answer either, so it must not
# be read as tenant noncompliance.
test_unknown_status_does_not_become_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "partially_resolved"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# Contradictory evidence - a record alongside a failure status - is a collection
# we know did not complete, so it is scored neither pass nor fail. The p=none
# case matters most: an incomplete collection must not surface as a failure.
test_record_alongside_lookup_failure_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "unexpected_error"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_weak_record_alongside_lookup_failure_is_not_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none", "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "unexpected_error"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The contradiction runs the other way too: a record sitting next to a claim
# that the tenant published nothing must not be scored as a pass.
test_record_alongside_authoritative_absence_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "absent", "dmarc_error_code": "nxdomain"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# Truncated evidence: the lookup claims to have read a record and the payload is
# not there. That is not proof the tenant published nothing.
test_found_status_without_a_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# A status key that is present but never labelled is not the pre-change shape.
test_explicit_null_status_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": null}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_non_string_status_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_lookup_status": 1}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# A fragment carrying no "=" makes the record malformed, and the finding says
# so: the whole record is rejected, not just the unreadable fragment.
test_tag_without_a_value_is_malformed if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["record_missing_or_malformed"]}]
}

# Junk in front of the version tag is not a DMARC record either; the version
# must be the first tag, not the first tag that happens to parse.
test_leading_junk_before_the_version_tag_is_malformed if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "garbage; v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# RFC 7489 s6.4 writes the version value as hexadecimal octets, so unlike an SPF
# version it is case-sensitive, and s6.3 says a value that does not match
# precisely means the whole record is ignored: no receiver applies this policy.
test_lowercase_version_value_is_not_a_dmarc_record if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=dmarc1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# Tag names and the p value are quoted literals in the same ABNF, so those are
# case-insensitive.
test_uppercase_tag_names_and_policy_value_still_pass if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; P=Reject; PCT=100; RUA=mailto:rua@contoso.com; RUF=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A reporting tag has to name a mailbox. "mailto:@" reaches nobody.
test_reporting_uri_without_a_mailbox_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:@; ruf=@", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# A domains array shorter than the collector's own count is truncated evidence.
test_truncated_domain_population_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {
		"total_domains": 2,
		"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}],
	}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_intact_domain_population_is_scored if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {
		"total_domains": 1,
		"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}],
	}
	object.get(result, "compliant", "undefined") == true
	object.get(result.details, "total_domains", "undefined") == 1
}

# The pre-change shape put the reason a lookup failed in the free-text error
# field. A record sitting next to one is contradictory evidence, whichever way
# the record itself would have been scored.
test_pre_change_record_alongside_an_error_string_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none", "dmarc_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_pre_change_passing_record_alongside_an_error_string_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_error": "DNS query timeout"}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
}

# A status key present but null is not the pre-change shape, and a record beside
# it does not rescue it. Without the record this case cannot tell the two apart.
test_explicit_null_status_with_a_passing_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": null}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != true
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# RFC 6068 lets a mailto URI carry header fields after a "?", and those can hold
# an "@" of their own. Only the recipient half is the address.
test_mailto_with_header_fields_still_names_a_mailbox if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@contoso.com?subject=DMARC@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_reporting_address_with_an_unusable_host_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso..com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

test_reporting_address_without_a_host_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# A domain whose eligibility Graph never stated is unresolved, and it must stop
# the control claiming a complete pass over the domains it did examine.
test_domain_with_unknown_verification_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"total_domains": 2, "domains": [
		{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"},
		{"domain": "fabrikam.com", "is_verified": null, "dmarc_record": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "verification_unknown"},
	]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "coverage", "undefined") == "partial"
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# ---------------------------------------------------------------- D5 (DMARC)
# The exact string the pre-status collector wrote when dnspython raised NoAnswer
# on _dmarc.<domain>: the name resolved and carries no TXT records, so the zone
# answered and nothing is published where the RFC requires it. That is confirmed
# tenant state, and reading it as "could not check" drops a real finding out of
# every historical scan.
test_legacy_no_dmarc_txt_record_string_is_authoritative_absence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": "No DMARC TXT record"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "unresolved_domains_count", "undefined") == 0
	reasons := {requirement |
		some entry in result.details.non_compliant_domain_reasons
		some requirement in entry.failed_requirements
	}
	reasons == {"record_missing_or_malformed"}
}

# The legacy NXDOMAIN string is absence WHEN THE APEX ANSWERED, which is the
# same test the current collector applies to the identical DNS outcome. THIS
# input carries no apex evidence at all - it has no spf_error key, so nothing
# says whether the domain's own zone resolved - and without that the string
# cannot tell a missing _dmarc label from a whole zone that never resolved.
#
# An earlier comment here claimed the legacy collector never recorded the apex
# outcome. It did: the apex TXT query ran first and wrote spf_error in this same
# object. The two cases below feed it.
test_legacy_dmarc_record_not_found_string_without_apex_evidence_stays_unresolved if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": "DMARC record not found"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The same string with the apex outcome beside it. spf_error present and null is
# the pre-change collector saying the apex TXT query returned, so the zone
# resolved and the _dmarc NXDOMAIN is the ordinary way DMARC is absent: a
# confirmed finding, not "could not check". The current collector stamps this
# identical DNS reality absent / nxdomain.
test_legacy_dmarc_nxdomain_with_apex_answered_is_authoritative_absence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "spf_record": "v=spf1 include:spf.protection.outlook.com -all", "spf_error": null, "dmarc_record": null, "dmarc_error": "DMARC record not found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "unresolved_domains_count", "undefined") == 0
}

# The apex answered by raising NoAnswer: the zone resolved and holds no TXT
# record at all. That still proves the zone exists, so the _dmarc NXDOMAIN is
# still absence.
test_legacy_dmarc_nxdomain_with_apex_no_answer_is_authoritative_absence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "No TXT records", "dmarc_record": null, "dmarc_error": "DMARC record not found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# The apex did NOT answer. NXDOMAIN at the apex means the whole zone is gone and
# a timeout means nothing was learned, so in neither case does the _dmarc
# NXDOMAIN say anything about what the tenant published.
test_legacy_dmarc_nxdomain_with_apex_nxdomain_stays_unresolved if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "Domain not found", "dmarc_record": null, "dmarc_error": "DMARC record not found"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

test_legacy_dmarc_nxdomain_with_apex_timeout_stays_unresolved if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "spf_record": null, "spf_error": "DNS query timeout", "dmarc_record": null, "dmarc_error": "DMARC record not found"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

# ------------------------------------------- D5 (legacy present-and-null error)
# A present-and-null legacy dmarc_error does NOT prove absence, and this case
# exists to keep that from being "fixed" again. Null does mean the _dmarc TXT
# query returned - the collector preset the field and wrote it only from an
# except clause - but its record selection was
# txt_value.startswith("v=DMARC1"), case- AND whitespace-sensitive, while RFC
# 7489 s6.4 permits whitespace either side of the "=" and this control reads it
# that way. The record in the case below is compliant here and produced exactly
# this legacy shape, so scoring it false would report a compliant tenant as a
# finding.
test_legacy_present_and_null_dmarc_error_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "is_verified": true, "spf_record": null, "dmarc_record": null, "dmarc_policy": null, "spf_error": null, "dmarc_error": null}]}
	object.get(result, "compliant", "undefined") == null
	object.get(result, "compliant", "undefined") != false
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# The confound itself: RFC 7489 s6.4 allows the whitespace, this control accepts
# the record, and the legacy matcher missed it.
test_spaced_version_tag_is_compliant_which_is_why_legacy_null_cannot_be_absence if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v = DMARC1; p=reject; pct=100; rua=mailto:a@contoso.com; ruf=mailto:b@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# The distinction is the KEY, not the value. An object that never mentions
# dmarc_error never recorded whether a query ran, so it stays unresolved - which
# is what keeps a synthetic fragment from being scored as a tenant finding.
test_missing_dmarc_error_key_is_still_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "unresolved_domains_count", "undefined") == 1
}

# A present-and-null error is read only in the legacy shape. A domain carrying
# the new status fields is judged by those.
test_present_and_null_dmarc_error_beside_lookup_failed_status_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": null, "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "timeout"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

test_legacy_no_nameservers_string_stays_unresolved if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": "No nameservers available"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

test_legacy_free_text_error_stays_unresolved if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": "connection reset by peer"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

# Contradictory legacy evidence - a record sitting beside the absence string -
# is still not scored in either direction.
test_legacy_absence_string_beside_a_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_error": "No DMARC TXT record"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

# The legacy string is not a status: a domain carrying the new status fields is
# read from those, so an unresolved lookup is not rescued by an error string.
test_lookup_failed_status_beside_the_legacy_absence_string_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": null, "dmarc_error": "No DMARC TXT record", "dmarc_lookup_status": "lookup_failed", "dmarc_error_code": "timeout"}]}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
}

# ---------------------------------------------------------------------- D2
# CIS audit step 3 requires "valid reporting addresses". Any nonempty
# dot-separated labels counted as a hostname, so a space survived and
# "reports@bad domain.com" - a string no report can be delivered to - scored as
# a valid rua and ruf. Both reporting requirements must fail.
test_reporting_address_with_whitespace_in_the_host_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:reports@bad domain.com; ruf=mailto:reports@bad domain.com"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	reasons := {requirement |
		some entry in result.details.non_compliant_domain_reasons
		some requirement in entry.failed_requirements
	}
	reasons == {"rua_reporting_address_missing", "ruf_reporting_address_missing"}
}

test_reporting_address_with_whitespace_in_the_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re ports@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	reasons := {requirement |
		some entry in result.details.non_compliant_domain_reasons
		some requirement in entry.failed_requirements
	}
	reasons == {"rua_reporting_address_missing"}
}

test_reporting_address_with_a_special_in_the_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:r<f@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	reasons := {requirement |
		some entry in result.details.non_compliant_domain_reasons
		some requirement in entry.failed_requirements
	}
	reasons == {"ruf_reporting_address_missing"}
}

test_reporting_address_with_a_leading_dot_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:.rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
}

test_reporting_address_with_a_hyphen_edged_label_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@-contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
}

# The other direction: address validation exists to stop a false pass, not to
# manufacture a false finding. RFC 7489 s6.2 lets a dmarc-uri carry a maximum
# report size after a "!", which is not part of the address.
test_reporting_address_with_a_size_limit_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com!10m; ruf=mailto:ruf@contoso.com!25m"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_reporting_addresses_with_ordinary_real_world_shapes_still_pass if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:d.marc+rua@mail.contoso-corp.co.uk; ruf=mailto:rua@xn--80ak6aa92e.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_second_reporting_uri_supplies_the_address_when_the_first_is_junk if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:@,mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
}

# RFC 7489 s6.2 spells the size suffix out as "!" 1*DIGIT [k/m/g/t]. Anything
# else after an unencoded "!" is not a size limit and must not be stripped:
# "mailto:a@b.com!10m@invalid" is not a URI and must not score as an address.
test_reporting_uri_with_junk_after_the_size_suffix_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com!10m@invalid; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	reasons := {requirement |
		some entry in result.details.non_compliant_domain_reasons
		some requirement in entry.failed_requirements
	}
	reasons == {"rua_reporting_address_missing"}
}

test_reporting_uri_with_a_bare_exclamation_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com!; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
}

# Every size unit the grammar allows, upper and lower case, still passes.
test_reporting_uri_size_units_still_pass if {
	every suffix in ["!10k", "!10M", "!1g", "!2T", "!100"] {
		result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": sprintf("v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com%s; ruf=mailto:ruf@contoso.com", [suffix])}]}
		object.get(result, "compliant", "undefined") == true
	}
}

# ADDED, not rewrites. These are the full-flag records that an earlier round
# wrote over test_compliant_reject and test_compliant_quarantine with. Those two
# cases now feed their HEAD inputs again and assert the verdict the benchmark
# gives them; the full-flag records that DO satisfy audit step 3 live here, as
# their own cases, so both shapes are covered and neither test's input was
# edited to make it pass.
test_full_flag_reject_record_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_full_flag_quarantine_record_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=quarantine; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A full-flag record is still not scored when the collection itself failed.
test_collector_error_beside_a_full_flag_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}], "collector_error": "graph returned 503"}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

test_nested_error_beside_a_full_flag_record_is_indeterminate if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}], "error": "authentication failed"}
	object.get(result, "compliant", "undefined") == null
	result.affected_resources == []
	object.get(result.details, "evaluation_status", "undefined") == "indeterminate"
}

# The p=none record with every other flag present: only the policy requirement
# fails, which proves p is judged independently of pct and the reporting tags.
test_full_flag_policy_none_record_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=none; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["policy_not_quarantine_or_reject"]}]
}

# Audit step 3 spells the rua out as "rua=mailto:<reporting email address>", and
# the only bare address in any of the benchmark's passing examples is a ruf. So
# the scheme is required on the rua and optional on the ruf. RFC 7489 s6.3 makes
# a bare rua unreadable to a receiver as well, so nothing is lost by refusing it.
test_bare_rua_without_the_mailto_scheme_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=rua@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing"]}]
}

# The other half of that asymmetry, restated on its own so it cannot be lost:
# the bare ruf of the benchmark's third passing example still passes.
test_bare_ruf_is_still_accepted if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# RFC 6068 s2 percent-encodes octets that cannot appear literally in a mailto
# URI, so validating the still-encoded string let them through: this record's
# reporting mailboxes both decode to a local part holding a NUL and reach
# nobody, and the record scored as compliant.
test_percent_encoded_octet_in_a_reporting_address_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:reports%00@contoso.com; ruf=mailto:reports%00@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing", "ruf_reporting_address_missing"]}]
}

# Plus-addressed reporting mailboxes are ordinary and must keep passing. This is
# why the encoded form is refused rather than decoded: urlquery.decode would
# turn the "+" into a space and report these as unreachable.
test_plus_addressed_reporting_mailboxes_still_pass if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc+rua@contoso.com; ruf=mailto:dmarc+ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# The percent-escape rules, both directions. An escape that decodes to an
# ordinary character is a legal spelling and must keep passing - RFC 7489 s6.2
# requires "%21" for a literal "!" inside a dmarc-uri, and "%2B" is a legal if
# unnecessary spelling of the everyday plus-addressed mailbox - while an escape
# that decodes to an octet no mailbox can hold must not.
test_escape_decoding_to_an_ordinary_character_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc%2Breports@contoso.com; ruf=mailto:dmarc%21ops@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_escape_decoding_to_a_space_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re%20ports@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing"]}]
}

# INVERTED, input untouched. This case asserted noncompliance on the reasoning
# that an encoded "%" needs a second decoding pass. It does not: RFC 6068 asks
# for one pass, and one pass turns "re%25ports" into "re%ports", which RFC 5322
# s3.2.3 allows in an unquoted local part. The old assertion made a deliverable
# mailbox a tenant finding, so it was itself the defect.
test_encoded_percent_is_a_deliverable_mailbox if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re%25ports@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A "%" that is not a complete escape is not an address either, at the end of
# the local part or anywhere in it.
test_malformed_percent_escape_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:reports%zz@contoso.com; ruf=mailto:reports%@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing", "ruf_reporting_address_missing"]}]
}

# Percent escapes are collapsed before the local part's shape is judged, so
# the encoded spelling of a dot lands where a dot would: leading, trailing and
# repeated dots are refused however they are written, and an escaped dot in the
# middle is the ordinary address it decodes to. "%25" decodes in one pass to a
# literal "%", which RFC 5322 s3.2.3 allows in an unquoted local part, so it is
# a deliverable mailbox rather than a finding.
test_encoded_leading_dot_in_a_reporting_address if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:%2Ereports@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
}

test_encoded_trailing_dot_in_a_reporting_address if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:reports%2e@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
}

test_encoded_dot_beside_a_literal_dot_in_a_reporting_address if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re%2E.ports@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
}

test_encoded_dot_inside_the_local_part_in_a_reporting_address if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re%2Eports@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
}

# Length is a property of the mailbox, not of its URI spelling: 22 characters
# written entirely in escapes is a 22-character local part, and the 64-octet
# limit still bites on one that really is too long.
test_escaped_local_part_is_measured_after_decoding if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == true
}

test_escaped_local_part_over_the_octet_limit_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41%41@contoso.com; ruf=mailto:ruf@contoso.com", "dmarc_lookup_status": "found"}]}
	object.get(result, "compliant", "undefined") == false
}

# ------------------------------------- non-ASCII whitespace in the local part
# The local part is validated against an RFC 5322 atext allowlist rather than a
# denylist of specials and ASCII controls. A denylist left every non-ASCII
# codepoint accepted, so U+00A0 NO-BREAK SPACE and U+3000 IDEOGRAPHIC SPACE
# passed - the same undeliverable address the literal-space case is, one
# codepoint away. Both reporting requirements must fail.
test_no_break_space_in_the_reporting_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re ports@contoso.com; ruf=mailto:re ports@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing", "ruf_reporting_address_missing"]}]
}

test_ideographic_space_in_the_reporting_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re　ports@contoso.com; ruf=mailto:re　ports@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# An accented letter is atext in no reading of RFC 5322; SMTPUTF8 addresses are
# a documented limit of this control, not something it silently passes.
test_non_ascii_letter_in_the_reporting_local_part_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:réports@contoso.com; ruf=mailto:réports@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	result.affected_resources == ["contoso.com"]
}

# The allowlist must not narrow what already worked. Every atext punctuation
# character is still a legal local part. The URI spelling is used here for the
# characters a URI reserves - "%21" for "!", which RFC 7489 s6.2 makes the
# size-limit separator, and "%7B"/"%7D" for the braces RFC 3986 excludes from
# the URI grammar - and the escapes decode back to those characters, so the
# address is judged as the mailbox it names.
test_atext_punctuation_in_the_reporting_local_part_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:d-marc_re.ports+agg%7B1%7D%21x@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# The same punctuation written literally in the bare ruf form, where there is no
# URI grammar to reserve anything.
test_literal_atext_punctuation_in_a_bare_ruf_address_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=d-marc_re.ports+agg{1}#x@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

test_percent_escaped_plus_in_the_reporting_local_part_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc%2Breports@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# ------------------------------------------------ percent-encoded high octets
# %80-%FF spells a non-ASCII octet, which RFC 5322 atext excludes just as the
# literal codepoint is excluded. As three atext characters the escape walked
# straight past the allowlist, so "mailto:re%FFports@contoso.com" scored as a
# valid reporting address while the mailbox it names holds a byte that is not
# even valid UTF-8.
test_percent_encoded_high_octet_in_a_reporting_address_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re%FFports@contoso.com; ruf=mailto:re%FFports@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing", "ruf_reporting_address_missing"]}]
}

test_percent_encoded_utf8_host_in_a_reporting_address_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:reports@b%C3%BCcher.de; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
}

# ------------------------------------------------ literal "%" in a bare ruf
# The benchmark's third passing example writes the ruf bare, with no mailto:
# scheme and so no escaping layer. A "%" there is the ordinary atext character
# it looks like, not the start of an escape, and "re%ports@contoso.com" is a
# deliverable mailbox. Applying the URI escape rules to it reported a real
# address as a finding.
test_literal_percent_in_a_bare_ruf_address_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=re%ports@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# The escape rules still apply where there IS a URI: the same local part written
# after "mailto:" is a malformed escape and is refused.
test_malformed_escape_in_a_mailto_ruf_is_still_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com; ruf=mailto:re%ports@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
}

# ------------------------------------------------------ URI fragment and size
# RFC 3986 s3.5 makes "#" the fragment delimiter in every URI, so everything
# from the first one is a fragment and no part of the address. Reading only the
# "?" left this URI - whose recipient is empty and whose fragment is
# "@contoso.com" - scoring as a valid reporting address, because "#" is itself
# an atext character and looked like a one-character local part.
test_mailto_with_an_empty_recipient_before_a_fragment_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:#@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing"]}]
}

# A fragment after a real address is still not part of it, and the address in
# front of it is still read.
test_mailto_with_a_fragment_after_the_address_still_names_a_mailbox if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com#section; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# A "#" that really belongs to the local part is written "%23" and still works.
test_percent_encoded_hash_in_the_reporting_local_part_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:re%23ports@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}

# Whichever delimiter comes first ends the address, so a "?" inside a fragment
# does not resurrect the header split, and vice versa.
test_mailto_with_a_fragment_before_the_header_split_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:#x?to=rua@contoso.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
}

# RFC 5321 s4.5.3.1.3 caps a mailbox at 254 octets. The 64-octet local part and
# the 253-octet host limits sum to more than that, so a 260-octet address passed
# both and still could not be delivered to.
test_reporting_address_over_the_mailbox_octet_limit_is_noncompliance if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == false
	object.get(result.details, "non_compliant_domain_reasons", []) == [{"domain": "contoso.com", "failed_requirements": ["rua_reporting_address_missing"]}]
}

# A mailbox at exactly the limit is still a mailbox.
test_reporting_address_at_the_mailbox_octet_limit_still_passes if {
	result := data.cis.microsoft_365_foundations.v6_0_0.control_2_1_10.result with input as {"domains": [{"domain": "contoso.com", "dmarc_lookup_status": "found", "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com; ruf=mailto:ruf@contoso.com"}]}
	object.get(result, "compliant", "undefined") == true
	result.affected_resources == []
}
