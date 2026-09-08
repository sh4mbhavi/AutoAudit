"""The DNS collector's exception-to-status mapping, exercised for real.

The Rego tests for CIS 2.1.8 and 2.1.10 hand-write ``spf_lookup_status`` and
``dmarc_lookup_status`` values, so they prove what the policies do with a label
but not that the collector ever emits it. The mapping itself is the load-bearing
half of the indeterminate mechanism: it is where a DNS answer becomes either a
claim about tenant state or an admission that nothing was learned, and it is
where the NXDOMAIN asymmetry lived (a whole-zone failure labelled an
authoritative absence, which 2.1.10 then reported as tenant noncompliance).

Every test drives the real collector with the real dnspython exception classes
and a stubbed resolver. No network, no tenant.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import dns.resolver
import pytest

from collectors.exchange.dns.dns_security_records import (
    DnsSecurityRecordsDataCollector,
)


class _Rdata:
    """One TXT answer, in dnspython's character-string form.

    RFC 1035 s3.3.14 makes a character-string an arbitrary octet string rather
    than text, and dnspython hands the octets over as bytes, so a test may pass
    raw bytes as well as text. Text arguments keep their previous meaning.
    """

    def __init__(self, *strings: str | bytes) -> None:
        self.strings = [s if isinstance(s, bytes) else s.encode() for s in strings]


# A TXT answer that is not text at all. Zones carry these: binary
# domain-verification blobs and other non-security records share the RRset with
# SPF, and the whole RRset comes back in one answer.
BINARY_TXT = _Rdata(bytes([0xFF, 0xFE, 0x00, 0x80]))


class _Graph:
    """The only Graph call the collector makes."""

    def __init__(self, domains: list[dict]) -> None:
        self._domains = domains

    async def get_domains(self) -> list[dict]:
        return self._domains


def _collect(domains: list[dict], resolve) -> list[dict]:
    """Run the collector against a stubbed resolver, return its domain records."""
    collector = DnsSecurityRecordsDataCollector()
    with patch("dns.resolver.resolve", side_effect=resolve) as resolver:
        evidence = asyncio.run(collector.collect(_Graph(domains)))
    evidence["queried"] = [call.args[0] for call in resolver.call_args_list]
    return evidence


VERIFIED = [{"id": "contoso.com", "isVerified": True}]


def _always(exception: type[Exception]):
    def resolve(_name, _rdtype):
        raise exception()

    return resolve


def _answers(mapping: dict):
    def resolve(name, _rdtype):
        outcome = mapping.get(name)
        if outcome is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(outcome, type) and issubclass(outcome, Exception):
            raise outcome()
        return outcome

    return resolve


# The defect: one NXDOMAIN, two opposite verdicts. When the domain's own zone
# does not resolve, the _dmarc query is unanswered for exactly the reason the
# apex query is, so it must not be labelled an authoritative absence.
def test_whole_zone_nxdomain_leaves_both_lookups_unresolved() -> None:
    record = _collect(VERIFIED, _always(dns.resolver.NXDOMAIN))["domains"][0]
    assert record["spf_lookup_status"] == "lookup_failed"
    assert record["spf_error_code"] == "nxdomain"
    assert record["dmarc_lookup_status"] == "lookup_failed"
    assert record["dmarc_error_code"] == "parent_zone_unresolved"


# The parent zone answered, so a missing _dmarc label is genuine absence.
def test_dmarc_nxdomain_under_a_resolving_zone_is_authoritative_absence() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {"contoso.com": [_Rdata("v=spf1 include:spf.protection.outlook.com -all")]}
        ),
    )["domains"][0]
    assert record["spf_lookup_status"] == "found"
    assert record["dmarc_lookup_status"] == "absent"
    assert record["dmarc_error_code"] == "nxdomain"


# A Graph domain object with no id identifies nothing. Neither query may run:
# "_dmarc.None" is a resolvable name whose NXDOMAIN would read as absence.
def test_domain_without_an_id_is_never_queried_or_labelled_absent() -> None:
    evidence = _collect([{"isVerified": True}], _always(dns.resolver.NXDOMAIN))
    record = evidence["domains"][0]
    assert evidence["queried"] == []
    assert record["domain"] is None
    assert record["spf_lookup_status"] == "lookup_failed"
    assert record["spf_error_code"] == "missing_domain_id"
    assert record["dmarc_lookup_status"] == "lookup_failed"
    assert record["dmarc_error_code"] == "missing_domain_id"


@pytest.mark.parametrize(
    ("blank_id", "reason"),
    [
        (None, "null id"),
        ("", "empty id"),
        ("   ", "whitespace id"),
        (7, "non-string id"),
    ],
)
def test_every_unusable_identifier_fails_closed(blank_id, reason) -> None:
    evidence = _collect(
        [{"id": blank_id, "isVerified": True}], _always(dns.resolver.NXDOMAIN)
    )
    assert evidence["queried"] == [], reason
    for prefix in ("spf", "dmarc"):
        assert evidence["domains"][0][f"{prefix}_lookup_status"] == "lookup_failed"
        assert evidence["domains"][0][f"{prefix}_error_code"] == "missing_domain_id"


@pytest.mark.parametrize(
    ("exception", "spf_status", "spf_code", "dmarc_status", "dmarc_code"),
    [
        (dns.resolver.NoAnswer, "absent", "no_answer", "absent", "no_answer"),
        (
            dns.resolver.NoNameservers,
            "lookup_failed",
            "no_nameservers",
            "lookup_failed",
            "no_nameservers",
        ),
        (dns.resolver.Timeout, "lookup_failed", "timeout", "lookup_failed", "timeout"),
    ],
)
def test_resolver_exception_mapping(
    exception, spf_status, spf_code, dmarc_status, dmarc_code
) -> None:
    record = _collect(VERIFIED, _always(exception))["domains"][0]
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        spf_status,
        spf_code,
    )
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        dmarc_status,
        dmarc_code,
    )


# An unclassified failure - including a scanner-side bug - is not evidence of
# tenant state.
def test_unexpected_error_fails_closed() -> None:
    record = _collect(VERIFIED, _always(ValueError))["domains"][0]
    assert record["spf_lookup_status"] == "lookup_failed"
    assert record["spf_error_code"] == "unexpected_error"


def test_records_are_read_and_parsed() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all")
                ],
                "_dmarc.contoso.com": [
                    _Rdata("v=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com")
                ],
            }
        ),
    )["domains"][0]
    assert record["spf_lookup_status"] == "found"
    assert record["spf_record"] == "v=spf1 include:spf.protection.outlook.com -all"
    assert record["dmarc_lookup_status"] == "found"
    assert record["dmarc_policy"]["p"] == "reject"
    assert record["dmarc_policy"]["rua"] == "mailto:rua@contoso.com"


# TXT records split into several character-strings are one value.
def test_multi_string_txt_record_is_joined() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protec", "tion.outlook.com -all")
                ]
            }
        ),
    )["domains"][0]
    assert record["spf_record"] == "v=spf1 include:spf.protection.outlook.com -all"


# RFC 5234 s2.3 makes the SPF version literal case-insensitive, so this is a
# published record. Labelling it "absent" would assert the tenant published
# nothing on a lookup that read one. The DMARC tag name is a quoted literal too,
# so "V=DMARC1" is equally valid.
def test_uppercase_version_tag_is_a_published_record() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("V=SPF1 INCLUDE:SPF.PROTECTION.OUTLOOK.COM -ALL")
                ],
                "_dmarc.contoso.com": [_Rdata("V=DMARC1; p=reject")],
            }
        ),
    )["domains"][0]
    assert record["spf_lookup_status"] == "found"
    assert record["dmarc_lookup_status"] == "found"


# The DMARC version VALUE is the opposite case: RFC 7489 s6.4 writes it as the
# octets %x44.4d.41.52.43.31, and s6.3 says a value that does not match
# precisely means the whole record is ignored. Reading "v=dmarc1" as a published
# policy would credit the tenant with one no receiver applies.
def test_lowercase_dmarc_version_value_is_not_a_record() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all")
                ],
                "_dmarc.contoso.com": [_Rdata("v=dmarc1; p=reject")],
            }
        ),
    )["domains"][0]
    assert record["dmarc_record"] is None
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "absent",
        "no_matching_txt",
    )


# RFC 7489 s6.4 permits whitespace either side of the "=", so this is a
# published record and the collector must read it.
def test_whitespace_around_the_dmarc_version_equals_is_a_record() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all")
                ],
                "_dmarc.contoso.com": [_Rdata("v = DMARC1; p = reject")],
            }
        ),
    )["domains"][0]
    assert record["dmarc_lookup_status"] == "found"
    assert record["dmarc_policy"]["p"] == "reject"


# RFC 7208 s4.5: the version section is terminated by a space or the end of the
# record, so "v=spf10" is not an SPF record and the zone published none.
def test_version_token_boundary_is_not_a_record() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf10 include:spf.protection.outlook.com -all")
                ],
                "_dmarc.contoso.com": [_Rdata("v=DMARC10; p=reject")],
            }
        ),
    )["domains"][0]
    assert record["spf_record"] is None
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "absent",
        "no_matching_txt",
    )
    assert record["dmarc_record"] is None
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "absent",
        "no_matching_txt",
    )


# RFC 7208 s4.5 (SPF permerror) and RFC 7489 s6.6.3 (no policy applies): more
# than one record means the domain has no usable one. The lookup answered, so it
# is tenant state, but no record may be handed on as if it were in force.
def test_multiple_records_leave_no_usable_record() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all"),
                    _Rdata("v=spf1 -all"),
                ],
                "_dmarc.contoso.com": [
                    _Rdata("v=DMARC1; p=reject"),
                    _Rdata("v=DMARC1; p=none"),
                ],
            }
        ),
    )["domains"][0]
    assert record["spf_record"] is None
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "absent",
        "multiple_records",
    )
    assert record["dmarc_record"] is None
    assert record["dmarc_policy"] is None
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "absent",
        "multiple_records",
    )


# Unverified domains are not the tenant's to configure.
def test_unverified_domains_are_skipped() -> None:
    evidence = _collect(
        [{"id": "unverified.test", "isVerified": False}],
        _always(dns.resolver.NXDOMAIN),
    )
    assert evidence["domains"] == []
    assert evidence["total_domains"] == 0


# Graph's domain resource always carries isVerified. An object without it says
# nothing about whether this control applies, so dropping it silently would let
# the remaining domains report a complete pass over a population that shrank.
def test_domain_that_does_not_state_verification_is_kept_and_unresolved() -> None:
    evidence = _collect(
        [
            {"id": "contoso.com", "isVerified": True},
            {"id": "fabrikam.com"},
        ],
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all")
                ],
                "_dmarc.contoso.com": [_Rdata("v=DMARC1; p=reject; pct=100")],
            }
        ),
    )
    assert evidence["total_domains"] == 2
    assert "fabrikam.com" not in evidence["queried"]
    assert "_dmarc.fabrikam.com" not in evidence["queried"]
    unknown = [r for r in evidence["domains"] if r["domain"] == "fabrikam.com"][0]
    assert unknown["is_verified"] is None
    for prefix in ("spf", "dmarc"):
        assert unknown[f"{prefix}_lookup_status"] == "lookup_failed"
        assert unknown[f"{prefix}_error_code"] == "verification_unknown"


def test_explicitly_unverified_domains_stay_out_of_scope() -> None:
    evidence = _collect(
        [
            {"id": "contoso.com", "isVerified": True},
            {"id": "unverified.test", "isVerified": False},
        ],
        _answers({}),
    )
    assert [record["domain"] for record in evidence["domains"]] == ["contoso.com"]
    assert evidence["total_domains"] == 1


# The defect: every TXT answer was decoded before anything was filtered, so one
# unrelated binary answer raised UnicodeDecodeError and sent the whole lookup to
# lookup_failed/unexpected_error - throwing away an SPF and a DMARC record that
# had both been retrieved successfully. A record that was read must be reported.
def test_binary_txt_answer_does_not_discard_the_records_that_were_read() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all"),
                    BINARY_TXT,
                ],
                "_dmarc.contoso.com": [
                    _Rdata(
                        "v=DMARC1; p=reject; pct=100; "
                        "rua=mailto:rua@contoso.com; ruf=mailto:ruf@contoso.com"
                    ),
                    BINARY_TXT,
                ],
            }
        ),
    )["domains"][0]
    assert (record["spf_lookup_status"], record["spf_error_code"]) == ("found", None)
    assert record["spf_record"] == "v=spf1 include:spf.protection.outlook.com -all"
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "found",
        None,
    )
    assert record["dmarc_policy"]["p"] == "reject"
    assert record["dmarc_policy"]["pct"] == "100"


# Order must not matter either: the binary answer commonly comes back first.
def test_binary_txt_answer_before_the_record_is_still_skipped() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    BINARY_TXT,
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all"),
                ],
                "_dmarc.contoso.com": [BINARY_TXT, _Rdata("v=DMARC1; p=quarantine")],
            }
        ),
    )["domains"][0]
    assert record["spf_lookup_status"] == "found"
    assert record["dmarc_lookup_status"] == "found"


# Skipping the binary answer must not mean skipping the examination. Every
# candidate is still counted, so a second copy of a security record beside a
# binary answer is still the permerror it was without one (RFC 7208 s4.5, RFC
# 7489 s6.6.3): the lookup answered, and no usable record is published.
def test_duplicate_record_beside_a_binary_answer_is_still_detected() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [
                    _Rdata("v=spf1 include:spf.protection.outlook.com -all"),
                    BINARY_TXT,
                    _Rdata("v=spf1 -all"),
                ],
                "_dmarc.contoso.com": [
                    _Rdata("v=DMARC1; p=reject"),
                    BINARY_TXT,
                    _Rdata("v=DMARC1; p=none"),
                ],
            }
        ),
    )["domains"][0]
    assert record["spf_record"] is None
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "absent",
        "multiple_records",
    )
    assert record["dmarc_record"] is None
    assert record["dmarc_policy"] is None
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "absent",
        "multiple_records",
    )


# A binary answer is not a security record, so on its own it leaves the zone
# with none published - authoritative absence, not a failed lookup.
def test_binary_txt_answer_alone_is_authoritative_absence() -> None:
    record = _collect(
        VERIFIED,
        _answers({"contoso.com": [BINARY_TXT], "_dmarc.contoso.com": [BINARY_TXT]}),
    )["domains"][0]
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "absent",
        "no_matching_txt",
    )
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "absent",
        "no_matching_txt",
    )


# The one candidate that opens with the version token but whose octets are not
# text. Something IS published, so "absent" would be a false statement about the
# tenant, and it cannot be read, so it is not a record to hand on either: the
# lookup fails closed and the control returns indeterminate rather than either.
def test_undecodable_candidate_is_neither_read_nor_called_absent() -> None:
    record = _collect(
        VERIFIED,
        _answers(
            {
                "contoso.com": [_Rdata(b"v=spf1 include:\xff\xfe.example -all")],
                "_dmarc.contoso.com": [_Rdata(b"v=DMARC1; p=reject; rua=\xff\xfe")],
            }
        ),
    )["domains"][0]
    assert record["spf_record"] is None
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "lookup_failed",
        "undecodable_record",
    )
    assert record["dmarc_record"] is None
    assert record["dmarc_policy"] is None
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "lookup_failed",
        "undecodable_record",
    )


# The apex zone answered - with a TXT record whose octets are not text, which
# leaves spf_lookup_status "lookup_failed" while the zone plainly did answer. A
# missing _dmarc label under that zone is still a confirmed absence, and reading
# the apex outcome off the SPF status instead of off the query dropped it into
# "could not check", hiding a real DMARC finding.
def test_dmarc_absence_survives_an_undecodable_spf_record_at_the_apex() -> None:
    record = _collect(
        VERIFIED,
        _answers({"contoso.com": [_Rdata(b"v=spf1 include:\xff\xfe.example -all")]}),
    )["domains"][0]
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "lookup_failed",
        "undecodable_record",
    )
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "absent",
        "nxdomain",
    )


# The other direction is unchanged: no answer from the apex at all still leaves
# the _dmarc NXDOMAIN unresolved.
def test_dmarc_nxdomain_stays_unresolved_when_the_apex_query_timed_out() -> None:
    record = _collect(VERIFIED, _answers({"contoso.com": dns.resolver.Timeout}))[
        "domains"
    ][0]
    assert (record["spf_lookup_status"], record["spf_error_code"]) == (
        "lookup_failed",
        "timeout",
    )
    assert (record["dmarc_lookup_status"], record["dmarc_error_code"]) == (
        "lookup_failed",
        "parent_zone_unresolved",
    )
