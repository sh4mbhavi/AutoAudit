# METADATA
# title: Ensure that SPF records are published for all Exchange Domains
# description: |
#   A corresponding Sender Policy Framework (SPF) record
#   should be created for each domain that will be configured in Exchange.
#
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.8
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Domain.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_2_1_8

import rego.v1

default result := {
	"compliant": null,
	"message": "Unable to evaluate: the tenant's domain records are unavailable or malformed",
	"affected_resources": [],
	"details": {
		"evaluation_status": "indeterminate",
		"reason": "Expected a non-empty domains array of domain objects. The collector returns an empty list when the DNS lookup itself returns nothing, and a tenant always has at least one accepted domain, so an empty list is a failed collection rather than a compliant tenant.",
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
	is_array(input.domains)
	count(input.domains) > 0
	every domain in input.domains {
		is_object(domain)
	}

	# The collector reports how many verified domains it examined. If that count
	# and the array disagree the evidence is truncated, and a truncated
	# collection is not something to score - in either direction. Absent, the
	# default makes this expression trivially true.
	object.get(input, "total_domains", count(input.domains)) == count(input.domains)
}

# A DNS lookup that never completed is a failed collection, not a tenant that
# failed to publish SPF, so the two must not share a verdict. A domain is only
# scored when its evidence is internally consistent:
#
#   spf_lookup_status "found"   AND a record string  -> judge the record
#   spf_lookup_status "absent"  AND no record string -> tenant published nothing
#   no spf_lookup_status key    AND a record string  -> judge the record
#   no spf_lookup_status key    AND no record string
#                               AND spf_error is the legacy NoAnswer string
#                                                    -> tenant published nothing
#
# Everything else is unresolved. That covers "lookup_failed" and any status a
# later collector adds; a status key carrying null or a non-string; and both
# directions of contradictory evidence - a record labelled absent (which would
# otherwise silently score a pass) and a "found" label with no record to read
# (truncated evidence, which would otherwise score a failure).
#
# The pre-change evidence shape carried no status key at all, recording only a
# record string and a free-text spf_error. A record string is still evidence of
# what was published and is judged on its contents. Absence in that shape is
# read from the spf_error FIELD - not merely from an error string, because in
# that shape the field's most common value is null and null is an answer.
#
# The pre-change collector built each domain record with spf_error preset to
# None and wrote it only from an except clause (phase-11
# engine/collectors/exchange/dns/dns_security_records.py: the record literal
# sets "spf_error": None, then five except clauses assign to it). So the value
# of that field is exactly the outcome of the query:
#
#   "No TXT records"          dns.resolver.NoAnswer   -> the zone answered and
#                                                        holds no TXT record at
#                                                        all, so the tenant
#                                                        published no SPF record
#   null (field present,      the TXT query RETURNED and no answer began with
#   never assigned)           the lowercase bytes "v=spf1" -> NOT conclusive,
#                                                        see below
#   "Domain not found"        NXDOMAIN                -> unresolved
#   "No nameservers available" NoNameservers          -> unresolved
#   "DNS query timeout"       Timeout                 -> unresolved
#   anything else             str(e) from the catch-all clause -> unresolved
#
# Only the NoAnswer string proves the tenant published no SPF record, and it
# proves it whatever the record would have said: an empty TXT RRset holds no SPF
# record in any spelling. Reading it as "could not check" drops a confirmed
# finding out of the compliance denominator on every pre-change scan (finding
# COR-02), which is why it is normalised below.
#
# A present-and-null spf_error is NOT the same proof, and an earlier round of
# this repair wrongly treated it as one. What it establishes is that the query
# RETURNED - no exception was raised - not that nothing was published. The
# pre-change collector selected the record with a CASE-SENSITIVE
# txt_value.startswith("v=spf1"), while RFC 7208 s4.5 with RFC 5234 s2.3 makes
# the version token case-insensitive and this control reads it that way
# (spf_terms lowercases). So a domain publishing
#
#     V=SPF1 include:spf.protection.outlook.com -all
#
# - fully compliant under this very control, and accepted by today's
# case-insensitive collector - produced exactly spf_record: null, spf_error:
# null. Scoring that shape false manufactures a finding against a compliant
# tenant, and no signal in the legacy record distinguishes it from real absence.
# The evidence is matcher-dependent, so it stays unresolved.
#
# That is the line between the two: the NoAnswer string is a fact about DNS, the
# null is a fact about a string comparison narrower than the one this control
# applies. Absence with no spf_error key at all is unresolved too - an object
# that never recorded whether a query ran is silence, and silence is not an
# answer.
#
# A domain object with no usable name is unresolved for the same reason: the
# control cannot name a resource it never identified, and a null in
# affected_resources reaches the report unfiltered.
domain_name(domain) := name if {
	raw := object.get(domain, "domain", null)
	is_string(raw)
	name := trim_space(raw)
	name != ""
}

spf_record_text(domain) := text if {
	record := object.get(domain, "spf_record", null)
	is_string(record)
	text := trim_space(record)
	text != ""
}

has_spf_record(domain) if {
	text := spf_record_text(domain)
	text != ""
}

lookup_resolved(domain) if {
	object.get(domain, "spf_lookup_status", null) == "found"
	has_spf_record(domain)
}

lookup_resolved(domain) if {
	object.get(domain, "spf_lookup_status", null) == "absent"
	not has_spf_record(domain)
}

lookup_resolved(domain) if {
	not "spf_lookup_status" in object.keys(domain)
	has_spf_record(domain)

	# The pre-change shape recorded the reason a lookup failed in the free-text
	# error field. A record sitting next to one is the same contradiction the
	# status form makes explicit, so it is not scored either - including next to
	# the NoAnswer string below, which claims the zone holds no TXT record.
	object.get(domain, "spf_error", null) == null
}

# The one pre-change error STRING that is an answer rather than a failure.
# Matched exactly, so a free-text message that merely mentions TXT records does
# not qualify, and only in the pre-change shape: a domain carrying a status is
# judged by that status.
legacy_no_answer := "No TXT records"

lookup_resolved(domain) if {
	not "spf_lookup_status" in object.keys(domain)
	not has_spf_record(domain)
	object.get(domain, "spf_error", null) == legacy_no_answer
}

scorable(domain) if {
	domain_name(domain)
	lookup_resolved(domain)
}

lookup_unresolved(domain) if {
	not scorable(domain)
}

unresolved_domains := [domain |
	some domain in input.domains
	lookup_unresolved(domain)
]

spf_issues := [domain |
	some domain in input.domains
	not spf_record_published(domain)
	not lookup_unresolved(domain)
]

# OPEN DECISION (GRC/product, needed before release): a partially covered FAIL
# is reported as an ordinary `failed` - confirmed noncompliance dominates
# unresolved coverage - and details.coverage / details.unresolved_domains record
# what was not seen. OPAResult has no coverage field and scoring does not read
# details, so that qualification is invisible in the report and in the coverage
# percentage. Surfacing a partially covered result distinctly is a result
# contract and worker change, and is its own piece of work.
compliance := false if {
	count(spf_issues) > 0
}

# `compliance if { ... }` is `compliance := true`; opa fmt drops the explicit
# true. The three rules are mutually exclusive, so the verdict is total.
compliance if {
	count(spf_issues) == 0
	count(unresolved_domains) == 0
}

compliance := null if {
	count(spf_issues) == 0
	count(unresolved_domains) > 0
}

coverage(unresolved) := "complete" if count(unresolved) == 0

coverage(unresolved) := "partial" if count(unresolved) > 0

evaluation_status(compliant) := "indeterminate" if compliant == null

evaluation_status(compliant) := "assessed" if is_boolean(compliant)

# CIS v6.0.0 2.1.8 audit step: "Ensure that a value exists and that it includes
# v=spf1 include:spf.protection.outlook.com. This designates Exchange Online as
# a designated sender." Both halves are checked.
#
# The version is the ABNF literal "v=spf1" terminated by a space or the end of
# the record (RFC 7208 s4.5), and RFC 5234 s2.3 makes that literal
# case-insensitive: "V=SPF1 ..." is a published SPF record, "v=spf10 ..." is not
# an SPF record at all. A bare prefix test gets both wrong, so the record is
# split into terms and the first term must equal the version exactly.
#
# The include may carry the default "+" qualifier. A "-", "~" or "?" qualifier
# does not designate Exchange Online as a sender, so it does not satisfy the
# audit step. A record that reaches Exchange Online only through a redirect= or
# a chained include is reported as a finding, which is what a CIS auditor
# performing this step by hand would record.
#
# The fully qualified spelling with a trailing root dot is included. RFC 1035
# s3.1 makes "spf.protection.outlook.com." and "spf.protection.outlook.com" the
# same DNS name, so a record written that way does include
# spf.protection.outlook.com and does designate Exchange Online - and the audit
# step is a test of what the record designates. Recognising the spelling only on
# the negating side below, as an earlier round did, made this control report a
# compliant tenant as a finding: one spelling could stop a record passing but
# could never make one pass.
exchange_online_includes := {
	"include:spf.protection.outlook.com",
	"+include:spf.protection.outlook.com",
	"include:spf.protection.outlook.com.",
	"+include:spf.protection.outlook.com.",
}

# The same include under a fail, softfail or neutral qualifier. A sender that
# matches one of these matched the Exchange Online include set, so it can never
# go on to match the positive include later in the record.
#
# The fully qualified spelling with a trailing root dot names the same DNS
# domain, so it preempts too, and it is recognised on both sides: the positive
# set above carries it as well, so the two halves of this control agree on what
# counts as naming Exchange Online.
negated_exchange_online_includes := {
	"-include:spf.protection.outlook.com",
	"~include:spf.protection.outlook.com",
	"?include:spf.protection.outlook.com",
	"-include:spf.protection.outlook.com.",
	"~include:spf.protection.outlook.com.",
	"?include:spf.protection.outlook.com.",
}

all_mechanisms := {"all", "+all", "-all", "~all", "?all"}

spf_terms(text) := [term |
	some term in split(replace(lower(text), "\t", " "), " ")
	term != ""
]

# SPF is evaluated left to right and the first matching mechanism wins, so an
# "all" mechanism sitting ahead of the include ends evaluation before Exchange
# Online is ever reached: "v=spf1 -all include:spf.protection.outlook.com"
# designates nobody. Positions are compared, not mere presence.
include_positions(terms) := [position |
	some position, term in terms
	term in exchange_online_includes
]

all_positions(terms) := [position |
	some position, term in terms
	term in all_mechanisms
]

preempted_by_all(terms, position) if {
	alls := all_positions(terms)
	count(alls) > 0
	min(alls) < position
}

# "all" is not the only mechanism that can end evaluation early. RFC 7208 s4.6.2
# stops at the FIRST mechanism that matches, whatever qualifier it carries, so a
# negatively qualified include of the same domain sitting ahead of the positive
# one is just as preemptive: every sender the positive include would have
# authorised has already matched the "-include:" and been handed an SPF Fail
# (or, for "~"/"?", a softfail or neutral). Such a record names Exchange Online
# and designates it not at all.
negated_include_positions(terms) := [position |
	some position, term in terms
	term in negated_exchange_online_includes
]

preempted_by_negated_include(terms, position) if {
	negations := negated_include_positions(terms)
	count(negations) > 0
	min(negations) < position
}

# The third way a term ahead of the include ends evaluation for every sender.
# RFC 7208 s5.6: an "ip4"/"ip6" mechanism matches when the sender falls inside
# the given CIDR, and a /0 prefix length covers the whole address family
# whatever address is written in front of the slash - "0.0.0.0/0" and "1.2.3.4/0"
# are the same set. Negatively qualified, one of those hands every sender of
# that family a Fail before the include is ever consulted, exactly as "-all"
# does.
#
# BOTH families have to be covered before the include is unreachable. Exchange
# Online publishes IPv4 and IPv6 senders, so a record that hard-fails only IPv6
# ("v=spf1 -ip6:::/0 include:spf.protection.outlook.com -all", a real way to say
# "we do not send over IPv6") still designates Exchange Online over IPv4 and is
# left alone. Requiring both is what keeps this from inventing findings.
#
# And no positively qualified term may sit ahead of them. RFC 7208 s4.6.2 stops
# at the first mechanism that MATCHES, not at the first one present, so an
# earlier "ip4:40.92.0.0/15" hands the senders in that range a Pass before the
# blanket denials are ever reached: such a record does authorise senders, and
# calling it a finding would be inventing one. The guard is deliberately
# stricter than that - every term ahead of the include must carry a "-", "~" or
# "?" - because a term this rule cannot classify is a reason to leave the record
# alone, and leaving it alone means reporting it as the CIS audit step reads it:
# the include is present, so it passes.
#
# Deliberate limit: this covers terms that match every sender by construction.
# It is not a syntax check on the record as a whole - an invalid literal such as
# "ip4:999.0.0.1", or a CIDR length written with a leading zero such as "/00"
# (RFC 7208 s5.6 spells ip4-cidr-length as "0" / %x31-39 0*1DIGIT, so a padded
# zero is not a valid length), makes the whole record a PermError under s4.6 and
# no receiver honours it. Validating every mechanism is a different piece of work
# with its own false-finding risk, and the CIS audit step is a test of what the
# record contains, not of whether it parses.
negated_ip4_all := `^[-~?]ip4:[^/]+/0$`

negated_ip6_all := `^[-~?]ip6:.+/0$`

negated_all_addresses_positions(terms, pattern) := [position |
	some position, term in terms
	regex.match(pattern, term)
]

negatively_qualified(term) if {
	substring(term, 0, 1) in {"-", "~", "?"}
}

preempted_by_negated_address_space(terms, position) if {
	v4 := negated_all_addresses_positions(terms, negated_ip4_all)
	v6 := negated_all_addresses_positions(terms, negated_ip6_all)
	count(v4) > 0
	count(v6) > 0
	min(v4) < position
	min(v6) < position

	# terms[0] is the version token, which matches nothing.
	every term in array.slice(terms, 1, position) {
		negatively_qualified(term)
	}
}

# The earliest positive include is the only candidate worth testing: anything
# that preempts a later one preempts it too.
designates_exchange_online(terms) if {
	includes := include_positions(terms)
	count(includes) > 0
	not preempted_by_all(terms, min(includes))
	not preempted_by_negated_include(terms, min(includes))
	not preempted_by_negated_address_space(terms, min(includes))
}

# DECIDED, not overlooked: this is a test of what the record CONTAINS, which is
# what the audit step asks ("Ensure that a value exists and that it includes
# v=spf1 include:spf.protection.outlook.com"). It is not a syntax check on the
# record as a whole. A record that repeats the version token, or carries a term
# matching no RFC 7208 s4.6 directive or modifier grammar, is a PermError that no
# receiver honours - and this control still reports it as containing the include,
# because that is the finding a CIS auditor running the step by hand would
# record. Validating the full grammar is a separate piece of work with its own
# false-finding risk; it is not being done here by omission.
spf_record_published(domain) if {
	terms := spf_terms(spf_record_text(domain))
	terms[0] == "v=spf1"
	designates_exchange_online(terms)
}

result := {
	"compliant": compliance,
	"message": generate_message(compliance, spf_issues, unresolved_domains),
	# A domain whose lookup did not complete is never named here: the control
	# has no evidence that it is misconfigured.
	"affected_resources": [domain_name(domain) | some domain in spf_issues],
	"details": {
		"total_domains": count(input.domains),
		"non_compliant_domains_count": count(spf_issues),
		"non_compliant_domains": spf_issues,
		"unresolved_domains_count": count(unresolved_domains),
		"unresolved_domains": unresolved_domains,
		"coverage": coverage(unresolved_domains),
		"evaluation_status": evaluation_status(compliance),
	},
} if {
	valid_evidence
}

generate_message(true, _, _) := "All Exchange domains publish an SPF record that designates Exchange Online as a sender."

generate_message(false, issues, unresolved) := sprintf(
	"%d domain(s) do not publish an SPF record that starts with v=spf1 and includes spf.protection.outlook.com",
	[count(issues)],
) if count(unresolved) == 0

generate_message(false, issues, unresolved) := sprintf(
	"%d domain(s) do not publish an SPF record that starts with v=spf1 and includes spf.protection.outlook.com; a further %d domain(s) could not be checked because the DNS lookup did not complete",
	[count(issues), count(unresolved)],
) if count(unresolved) > 0

generate_message(null, _, unresolved) := sprintf(
	"Unable to evaluate: the DNS lookup did not complete for %d domain(s), so their SPF records are unknown",
	[count(unresolved)],
)
