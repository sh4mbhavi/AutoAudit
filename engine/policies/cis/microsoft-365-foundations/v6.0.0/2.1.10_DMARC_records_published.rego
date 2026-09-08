# METADATA
# title: Ensure DMARC Records for all Exchange Online domains are published
# description: |
#   DMARC, or Domain-based Message Authentication, Reporting, and Conformance,
#   assists recipient mail systems in determining the appropriate action to take when
#   messages from a domain fail to meet SPF or DKIM authentication criteria.
#   Ensure that the record exists that has the following flags defined either
#   p=quarantine OR p=reject.
# related_resources:
# - ref: https://www.cisecurity.org/benchmark/microsoft_365
#   description: CIS Microsoft 365 Foundations Benchmark
# custom:
#   control_id: CIS-2.1.10
#   framework: cis
#   benchmark: microsoft-365-foundations
#   version: v6.0.0
#   severity: high
#   service: Exchange
#   requires_permissions:
#   - Domain.Read.All

package cis.microsoft_365_foundations.v6_0_0.control_2_1_10

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
# failed to publish DMARC, so the two must not share a verdict. A domain is only
# scored when its evidence is internally consistent:
#
#   dmarc_lookup_status "found"   AND a record string  -> judge the record
#   dmarc_lookup_status "absent"  AND no record string -> tenant published none
#   no dmarc_lookup_status key    AND a record string  -> judge the record
#
# Everything else is unresolved. That covers "lookup_failed" and any status a
# later collector adds; a status key carrying null or a non-string; and both
# directions of contradictory evidence - a record labelled absent (which would
# otherwise silently score a pass) and a "found" label with no record to read
# (truncated evidence, which would otherwise score a failure).
#
# NXDOMAIN on the _dmarc.<domain> label is "absent" and still fails here, but
# only when the collector saw the domain's own zone answer; when the zone itself
# did not resolve the collector labels the DMARC lookup "lookup_failed" and this
# control returns indeterminate, in step with 2.1.8 on the same evidence.
#
# The pre-change evidence shape carried no status key at all. A record string is
# still evidence of what was published and is judged on its contents. A missing
# record in that shape is read from the dmarc_error FIELD, which the pre-change
# collector preset to None and wrote only from an except clause (phase-11
# engine/collectors/exchange/dns/dns_security_records.py). Two of its values
# are answers rather than failures:
#
#   "No DMARC TXT record"   NoAnswer      the _dmarc label exists and holds no
#                                         TXT record -> published nothing.
#   "DMARC record not found" NXDOMAIN     the _dmarc label does not exist, which
#                                         is the ORDINARY way DMARC is absent
#                                         since _dmarc.<domain> exists only if
#                                         someone created it. This one is an
#                                         answer only when the domain's OWN zone
#                                         is known to have resolved - see
#                                         legacy_apex_answered below.
#
# Both are facts about DNS: an empty TXT RRset and a nonexistent label hold no
# DMARC record in any spelling, so neither depends on how the collector matched
# the record.
#
# A present-and-null dmarc_error is NOT such a fact, and an earlier round of
# this repair wrongly treated it as one. It establishes that the query RETURNED,
# not that nothing was published: the pre-change collector selected the record
# with a CASE- AND WHITESPACE-SENSITIVE txt_value.startswith("v=DMARC1"), while
# RFC 7489 s6.4 permits whitespace either side of the "=" and this control reads
# it that way. So a domain publishing
#
#   v = DMARC1; p=reject; pct=100; rua=mailto:a@x.com; ruf=mailto:b@x.com
#
# - which this control accepts as compliant - produced exactly dmarc_record:
# null, dmarc_error: null. Scoring that shape false manufactures a finding
# against a compliant tenant, and nothing in the legacy record tells it apart
# from real absence, so it stays unresolved.
#
# Every other legacy value (timeout, no nameservers, free text) leaves no way to
# tell "the tenant published nothing" from "the lookup never answered", and the
# plan forbids resolving that ambiguity into noncompliance. So does an absent
# dmarc_error KEY: that is an object that never recorded whether a query ran.
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

dmarc_record_text(domain) := text if {
	record := object.get(domain, "dmarc_record", null)
	is_string(record)
	text := trim_space(record)
	text != ""
}

has_dmarc_record(domain) if {
	text := dmarc_record_text(domain)
	text != ""
}

lookup_resolved(domain) if {
	object.get(domain, "dmarc_lookup_status", null) == "found"
	has_dmarc_record(domain)
}

lookup_resolved(domain) if {
	object.get(domain, "dmarc_lookup_status", null) == "absent"
	not has_dmarc_record(domain)
}

# Before the status fields existed the collector wrote exactly "No DMARC TXT
# record" when dnspython raised NoAnswer on _dmarc.<domain>: the name resolved
# and carries no TXT records, so the zone answered and nothing is published
# where the RFC requires it. That is the same tenant state the "absent" status
# records today, and every historical scan carrying it read as "could not check"
# instead of "no record published" - dropping a real finding out of the
# denominator. Only this exact string qualifies; every other legacy error
# (timeout, no nameservers, domain not found, free text) is genuinely ambiguous
# and stays unresolved below.
lookup_resolved(domain) if {
	not "dmarc_lookup_status" in object.keys(domain)
	not has_dmarc_record(domain)
	object.get(domain, "dmarc_error", null) == "No DMARC TXT record"
}

# NXDOMAIN on _dmarc.<domain> is how DMARC is normally absent: the label exists
# only if someone published a record there. It proves absence when the domain's
# own zone answered, and proves nothing when the whole zone failed to resolve -
# which is exactly the distinction the current collector draws before stamping
# absent / nxdomain, using the apex query's own outcome.
#
# The pre-change record carries that same apex outcome, in the spf_error field
# of the same object: the apex TXT query ran first and wrote there.
#
# The apex answered when spf_error is present and null (no exception was raised,
# so the query returned) or holds the NoAnswer string (the zone answered, holding
# no TXT record). Note exactly what is read out of a null here: that the QUERY
# RETURNED, which is matcher-independent and sound, and NOT that no SPF record
# exists, which the case-sensitive legacy matcher cannot establish - which is why
# the absence clause above was withdrawn.
#
# This guard is deliberately NARROWER than the current collector's apex_answered
# flag, not equivalent to it. That flag is set before decoding, so an apex TXT
# answer whose octets are not text still counts as answered; the legacy collector
# let the same UnicodeDecodeError reach its catch-all except clause and wrote
# free text into spf_error, which reads here as unknown. The difference only ever
# resolves the legacy shape MORE conservatively, which is the safe direction.
#
# NXDOMAIN at the apex ("Domain not found"), a timeout, no nameservers or free
# text all leave the zone's fate unknown, so the _dmarc NXDOMAIN stays unresolved
# beside them. A record with no spf_error key at all carries no apex evidence and
# is unresolved for the same reason.
legacy_apex_answered(domain) if {
	"spf_error" in object.keys(domain)
	object.get(domain, "spf_error", null) == null
}

legacy_apex_answered(domain) if {
	object.get(domain, "spf_error", null) == "No TXT records"
}

lookup_resolved(domain) if {
	not "dmarc_lookup_status" in object.keys(domain)
	not has_dmarc_record(domain)
	object.get(domain, "dmarc_error", null) == "DMARC record not found"
	legacy_apex_answered(domain)
}

lookup_resolved(domain) if {
	not "dmarc_lookup_status" in object.keys(domain)
	has_dmarc_record(domain)

	# The pre-change shape recorded the reason a lookup failed in the free-text
	# error field. A record sitting next to one is the same contradiction the
	# status form makes explicit, so it is not scored either.
	object.get(domain, "dmarc_error", null) == null
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

dmarc_issues := [domain |
	some domain in input.domains
	not dmarc_record_published(domain)
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
	count(dmarc_issues) > 0
}

# `compliance if { ... }` is `compliance := true`; opa fmt drops the explicit
# true. The three rules are mutually exclusive, so the verdict is total.
compliance if {
	count(dmarc_issues) == 0
	count(unresolved_domains) == 0
}

compliance := null if {
	count(dmarc_issues) == 0
	count(unresolved_domains) > 0
}

coverage(unresolved) := "complete" if count(unresolved) == 0

coverage(unresolved) := "partial" if count(unresolved) > 0

evaluation_status(compliant) := "indeterminate" if compliant == null

evaluation_status(compliant) := "assessed" if is_boolean(compliant)

# CIS v6.0.0 2.1.10 audit step 3: "Ensure that the record exists and has at
# minimum the following flags defined as follows: v=DMARC1; (p=quarantine OR
# p=reject), pct=100, rua=mailto:<reporting email address> and
# ruf=mailto:<reporting email address>". The benchmark spells out why pct
# matters - its passing examples "affect 100% of mail pct=100 as well as
# containing valid reporting addresses" - so a record that applies an enforcing
# policy to a fraction of mail (pct=0 is functionally p=none) does not satisfy
# the control.
#
# The record is parsed once into a tag list. RFC 7489 s6.4 permits whitespace
# either side of the "=", so both halves are trimmed, and tag names are
# case-insensitive so they are lowercased. Tag VALUES are not: s6.4 spells the
# version out as the octets %x44.4d.41.52.43.31, and s6.3 says it "MUST match
# precisely" or the whole record is ignored, so "v=dmarc1" is a record no
# receiver honours and "v=DMARC10" is not a record at all.
#
# Three ways a record is rejected outright rather than read leniently, each of
# which would otherwise be a false pass:
#   - a fragment that carries no "=" at all ("...; pct; ...", or a record with
#     leading junk). Dropping it silently would let junk sit in front of the
#     version tag, and would report a record the receiver ignores outright as
#     one this control read and understood.
#   - the version tag anywhere but first, or not matching exactly.
#   - a repeated tag (s6.6.3: a receiver applies no policy it cannot read one
#     value out of, so neither can this control read one enforcing p out of two).
dmarc_parts(record) := [part |
	some raw in split(record, ";")
	part := trim_space(raw)
	part != ""
]

dmarc_wellformed(record) if {
	every part in dmarc_parts(record) {
		indexof(part, "=") > 0
	}
}

dmarc_pairs(record) := [[lower(trim_space(substring(part, 0, indexof(part, "=")))), trim_space(substring(part, indexof(part, "=") + 1, -1))] |
	some part in dmarc_parts(record)
	indexof(part, "=") > 0
]

# The parsed tag list, defined only for a record that is well formed, opens with
# the version tag and repeats no tag. Kept as a list of pairs rather than an
# object: an object comprehension over a record that repeats a tag raises an
# eval error instead of returning a verdict.
dmarc_pairs_of(domain) := pairs if {
	record := dmarc_record_text(domain)
	dmarc_wellformed(record)
	pairs := dmarc_pairs(record)
	count(pairs) > 0
	pairs[0][0] == "v"
	pairs[0][1] == "DMARC1"
	names := [name | some [name, _] in pairs]
	count(names) == count({name | some name in names})
}

tag_value(domain, name) := value if {
	some [key, raw] in dmarc_pairs_of(domain)
	key == name
	value := raw
}

# s6.4 writes the p values as quoted literals, so they are case-insensitive.
enforcing_policy(domain) if {
	lower(tag_value(domain, "p")) in {"quarantine", "reject"}
}

# CIS v6.0.0 2.1.10 audit step 3, quoted in full because the RFC and the
# benchmark disagree here and the benchmark is the authority: "Ensure that the
# record exists and has at minimum the following flags defined as follows:
# v=DMARC1; (p=quarantine OR p=reject), pct=100, rua=mailto:<reporting email
# address> and ruf=mailto:<reporting email address>".
#
# "Defined as follows" is a prescribed configuration: the flag has to be there
# carrying that value. RFC 7489 s6.3 does default an absent pct to 100, and the
# effect on mail is the same, but the audit step is not a test of effect - all
# three of the benchmark's own passing examples spell pct=100 out, and an
# auditor running step 3 by hand against a record with no pct records it as not
# meeting the criteria. So does this control. Do not reintroduce the RFC default
# here: an earlier round did, and it turned a record missing a required flag
# into a pass.
applies_to_all_mail(domain) if {
	tag_value(domain, "pct") == "100"
}

# CIS audit step 3 asks for "rua=mailto:<reporting email address> and
# ruf=mailto:<reporting email address>", and the benchmark's third passing
# example drops the scheme on exactly one of the two ("ruf=ruf@contoso.com").
# So the bare form is accepted for ruf, where the benchmark's own example uses
# it, and nowhere else - see acceptable_report_uri below. Either way the address
# itself has to be one: a local part, an "@", and a domain that looks like a
# domain. "rua=mailto:@" reaches nobody.
# RFC 5321 s4.5.3.1.3 caps a forward path at 256 octets including the angle
# brackets, so a mailbox is at most 254. The local part and the host each have
# their own limit below (64 and 253), and 64 + 1 + 253 is 318 - so checking only
# those two accepted a 260-octet address no SMTP implementation is required to
# handle. The total is measured on the same spelling each path measures its
# local part on: decoded for a URI, literal for a bare address.
max_mailbox_octets := 254

mailbox_address_uri(address) if {
	parts := split(trim_space(address), "@")
	count(parts) == 2
	mailbox_local_part_uri(parts[0])
	registrable_host(parts[1])
	(count(local_part_shape(parts[0])) + count(parts[1])) + 1 <= max_mailbox_octets
}

mailbox_address_literal(address) if {
	parts := split(trim_space(address), "@")
	count(parts) == 2
	mailbox_local_part_literal(parts[0])
	registrable_host(parts[1])
	(count(parts[0]) + count(parts[1])) + 1 <= max_mailbox_octets
}

# Not full RFC 5321 validation - just enough that a string no report can be
# delivered to is not accepted as a reporting address. The test is an ALLOWLIST,
# mirroring host_label on the other side of the "@": RFC 5322 s3.2.3 spells an
# unquoted local part as dot-separated runs of "atext", and atext is an
# enumerated ASCII set, so anything outside it is not a local part.
#
# A denylist was tried first and was the wrong shape. Enumerating the specials,
# ASCII whitespace and the ASCII control range left every non-ASCII codepoint
# accepted, so U+00A0 NO-BREAK SPACE and U+3000 IDEOGRAPHIC SPACE passed:
# "re<U+00A0>ports@contoso.com" is the same undeliverable address the literal
# space case is, one codepoint away. An allowlist closes all of them at once and
# does not have to be extended again for the next character class.
#
# "%" IS atext, deliberately: the escapes that arrive from a mailto: URI are
# judged by the two percent patterns below, not by this one.
#
# Deliberate limit: the RFC 5321 quoted form ("re ports"@contoso.com) is
# rejected, as is the RFC 6532 SMTPUTF8 non-ASCII form. Accepting the quoted
# form would also accept " "@contoso.com as a reporting address; no benchmark
# example uses either, and DMARC reporting to a non-ASCII mailbox is not
# something this control has evidence for.
local_part_atext := "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$"

# The same octets again, in the percent-encoded spelling. The address being
# validated has usually just come out of a mailto: URI, and RFC 6068 s2
# percent-encodes exactly the octets that cannot appear literally, so checking
# only the literal form let them through: "mailto:reports%00@contoso.com" scored
# as a valid reporting address while the mailbox it decodes to holds a NUL and
# reaches nobody.
#
# The escapes are matched rather than decoded. RE2 has no decoder, and
# urlquery.decode is not one either for this purpose - it turns "+" into a
# space, which would report the everyday plus-addressed
# "dmarc+reports@contoso.com" as unreachable. Matching keeps the escapes that
# decode to an ordinary character usable: "%2B" is a legal, if unnecessary,
# spelling of "+", and RFC 7489 s6.2 actually requires "%21" for a literal "!"
# inside a dmarc-uri, so refusing every escape would have turned records the
# benchmark is satisfied with into findings.
#
# %00-%1F and %7F are the control range, %20 space, %22 quote, %28 %29 parens,
# %2C comma, %3A colon, %3B semicolon, %3C %3E angle brackets, %40 "@", %5B %5C
# %5D brackets and backslash. "%25" is NOT among them: it decodes, in the one
# pass RFC 6068 asks for, to a literal "%", which RFC 5322 s3.2.3 allows in an
# unquoted local part, so "mailto:re%25ports@contoso.com" is the correct URI
# spelling of the perfectly deliverable "re%ports@contoso.com".
#
# %80-%FF is the whole high range, and it is refused for the same reason the
# atext allowlist refuses a literal non-ASCII codepoint: RFC 5322 atext is
# ASCII, so no octet above %7F is local-part content. Without this the escape
# spelling walked straight past the allowlist - "mailto:re%FFports@contoso.com"
# is three atext characters as written, and scored as a valid reporting address
# while the mailbox it decodes to holds a byte that is neither ASCII nor even
# valid UTF-8. That was the same false pass as the literal-space case, reached
# through the encoding.
percent_escape_disallowed := `(?i:%(0[0-9a-f]|1[0-9a-f]|2[0289c]|3[abce]|40|5[bcd]|7f|[89a-f][0-9a-f]))`

# A "%" that is not a complete escape at all: nothing this control can read as
# an address, in either the URI or the bare form.
percent_escape_malformed := `%([^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|[0-9A-Fa-f]?$)`

# The escapes are collapsed before the SHAPE of the local part is judged, because
# dot placement and length are properties of the address, not of how it is spelt
# in a URI. "%2E" is a dot wherever a dot would be; every escape that survives
# the two patterns above stands for exactly one ordinary character, so it counts
# as one. Judging the encoded spelling instead walked past all three shape
# checks: "%2Ereports" decodes to a leading dot, "reports%2e" to a trailing one,
# and a 22-character mailbox written entirely in escapes measured 66.
local_part_shape(local) := shape if {
	dotted := replace(replace(local, "%2E", "."), "%2e", ".")
	shape := regex.replace(dotted, `(?i:%[0-9a-f]{2})`, "a")
}

# Two entry points, because a percent sign means two different things depending
# on where the address came from. Inside a mailto: URI it introduces an escape
# (RFC 6068 s2), so the escapes are checked and collapsed. In the BARE form the
# benchmark's third example uses for ruf ("ruf=ruf@contoso.com") there is no URI
# and no escaping layer, so a "%" is just the literal, perfectly legal atext
# character it looks like - "re%ports@contoso.com" is a deliverable mailbox, and
# applying the escape rules to it reported a real address as a finding.
mailbox_local_part_uri(local) if {
	# Judged on the decoded shape, since that is the address the escapes spell.
	well_formed_local_part(local, local_part_shape(local))
	not regex.match(percent_escape_disallowed, local)
	not regex.match(percent_escape_malformed, local)
}

mailbox_local_part_literal(local) if {
	# No escaping layer, so the octets ARE the address and are measured as they
	# stand: a literal "%2E" here is three ordinary characters, not a dot.
	well_formed_local_part(local, local)
}

well_formed_local_part(local, shape) if {
	local != ""
	count(shape) <= 64
	not startswith(shape, ".")
	not endswith(shape, ".")
	not contains(shape, "..")
	regex.match(local_part_atext, local)
}

# Not full hostname validation either - just enough that "@", ".com",
# "contoso..com" and "bad domain.com" cannot be reported as a reporting address
# the tenant can be told is fine. RFC 1035 s2.3.1 with RFC 1123 s2.1: a label is
# letters, digits and inner hyphens, at most 63 octets. Counting non-empty
# dot-separated pieces was not that test - it let a space through, and a space
# is not a hostname character, so "reports@bad domain.com" reached nobody while
# scoring as a valid reporting address.
host_label := `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`

registrable_host(host) if {
	count(host) <= 253
	labels := split(host, ".")
	count(labels) > 1
	every label in labels {
		regex.match(host_label, label)
		count(label) <= 63
	}
	count(labels[count(labels) - 1]) > 1
}

# RFC 6068: a mailto URI may carry header fields after a "?", and those can
# themselves contain an "@". Only the recipient half is an address.
#
# A "#" ends it too. RFC 3986 s3.5 makes "#" the fragment delimiter in EVERY
# URI, so everything from the first one is a fragment and no part of the
# addr-spec. Reading only the "?" left "mailto:#@contoso.com" - a URI whose
# recipient is empty and whose fragment is "@contoso.com" - scoring as a valid
# reporting address, because "#" is itself an atext character and "#" plus
# "contoso.com" looked like a mailbox. A "#" that really is part of a local part
# has to be written "%23", which still validates.
#
# Whichever delimiter comes first wins.
mailto_delimiter(rest) := index if {
	candidates := [position |
		some delimiter in ["?", "#"]
		position := indexof(rest, delimiter)
		position >= 0
	]
	count(candidates) > 0
	index := min(candidates)
}

mailto_recipient(rest) := substring(rest, 0, mailto_delimiter(rest))

mailto_recipient(rest) := rest if {
	not mailto_delimiter(rest)
}

mailto_report_uri(uri) if {
	startswith(lower(uri), "mailto:")
	mailbox_address_uri(mailto_recipient(substring(uri, 7, -1)))
}

bare_report_address(uri) if {
	not contains(uri, ":")
	mailbox_address_literal(uri)
}

# The two tags are not held to the same rule, because the benchmark does not
# hold them to the same rule. Audit step 3 requires "rua=mailto:<reporting email
# address> and ruf=mailto:<reporting email address>"; the only place the pinned
# text departs from that is its third passing example, which writes
# "ruf=ruf@contoso.com" bare while still spelling the rua out as a mailto: URI.
# So a bare ruf is accepted - reporting a record CIS itself calls compliant as a
# finding would be wrong - and a bare rua is not: nothing in the benchmark
# accepts one, and RFC 7489 s6.3 defines the rua value as a list of DMARC URIs,
# so a receiver does not read a bare address as a reporting destination either.
# Both authorities agree here, which is what makes the asymmetry safe.
acceptable_report_uri("rua", uri) if {
	mailto_report_uri(uri)
}

acceptable_report_uri("ruf", uri) if {
	mailto_report_uri(uri)
}

acceptable_report_uri("ruf", uri) if {
	bare_report_address(uri)
}

# RFC 7489 s6.2 lets a dmarc-uri carry a maximum report size after a "!"
# ("rua=mailto:reports@contoso.com!10m"), and s6.3 requires any "!" inside the
# URI itself to be percent-encoded, so the first one ends the URI. The size
# limit is not part of the address, and it is stripped here rather than inside
# mailbox validation: left on, the host would read as "contoso.com!10m" and a
# legitimate record with a size limit would be reported as having no reporting
# address. Header fields after a "?" (RFC 6068) stay separate, in
# mailto_recipient, for the same reason.
# s6.2 spells the suffix out as "!" 1*DIGIT [ "k" / "m" / "g" / "t" ], so only
# that shape is stripped. Stripping at any "!" would discard whatever followed
# it, and "mailto:a@b.com!10m@invalid" - which is not a URI at all - would score
# as a reporting address. A "!" that is not a size limit leaves this rule
# undefined, which rejects the URI, as an unencoded "!" in a dmarc-uri must be.
report_uri_size_suffix := `^[0-9]+[kmgtKMGT]?$`

report_uri_without_size(uri) := substring(uri, 0, indexof(uri, "!")) if {
	indexof(uri, "!") >= 0
	regex.match(report_uri_size_suffix, substring(uri, indexof(uri, "!") + 1, -1))
}

report_uri_without_size(uri) := uri if {
	indexof(uri, "!") == -1
}

reporting_address(domain, tag) if {
	some uri in split(tag_value(domain, tag), ",")
	acceptable_report_uri(tag, report_uri_without_size(trim_space(uri)))
}

# Named requirements, so the finding says which one the domain misses rather
# than only that it missed something.
dmarc_failures(domain) := array.concat(
	["record_missing_or_malformed" | not dmarc_pairs_of(domain)],
	array.concat(
		array.concat(
			["policy_not_quarantine_or_reject" | dmarc_pairs_of(domain); not enforcing_policy(domain)],
			["pct_does_not_cover_all_mail" | dmarc_pairs_of(domain); not applies_to_all_mail(domain)],
		),
		array.concat(
			["rua_reporting_address_missing" | dmarc_pairs_of(domain); not reporting_address(domain, "rua")],
			["ruf_reporting_address_missing" | dmarc_pairs_of(domain); not reporting_address(domain, "ruf")],
		),
	),
)

dmarc_record_published(domain) if {
	count(dmarc_failures(domain)) == 0
}

result := {
	"compliant": compliance,
	"message": generate_message(compliance, dmarc_issues, unresolved_domains),
	# A domain whose lookup did not complete is never named here: the control
	# has no evidence that it is misconfigured.
	"affected_resources": [domain_name(domain) | some domain in dmarc_issues],
	"details": {
		"total_domains": count(input.domains),
		"non_compliant_domains_count": count(dmarc_issues),
		"non_compliant_domains": dmarc_issues,
		"non_compliant_domain_reasons": [{
			"domain": domain_name(domain),
			"failed_requirements": dmarc_failures(domain),
		} |
			some domain in dmarc_issues
		],
		"unresolved_domains_count": count(unresolved_domains),
		"unresolved_domains": unresolved_domains,
		"coverage": coverage(unresolved_domains),
		"evaluation_status": evaluation_status(compliance),
	},
} if {
	valid_evidence
}

generate_message(true, _, _) := "All Exchange domains publish an enforcing DMARC record covering all mail with reporting addresses."

generate_message(false, issues, unresolved) := sprintf(
	"%d domain(s) do not meet DMARC enforcement requirements (missing or malformed record, p policy is not quarantine/reject, pct does not cover all mail, or rua/ruf reporting addresses are missing)",
	[count(issues)],
) if count(unresolved) == 0

generate_message(false, issues, unresolved) := sprintf(
	"%d domain(s) do not meet DMARC enforcement requirements (missing or malformed record, p policy is not quarantine/reject, pct does not cover all mail, or rua/ruf reporting addresses are missing); a further %d domain(s) could not be checked because the DNS lookup did not complete",
	[count(issues), count(unresolved)],
) if count(unresolved) > 0

generate_message(null, _, unresolved) := sprintf(
	"Unable to evaluate: the DNS lookup did not complete for %d domain(s), so their DMARC records are unknown",
	[count(unresolved)],
)
