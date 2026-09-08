"""DNS security records collector.

CIS Microsoft 365 Foundations Benchmark Controls:
    v6.0.0: 2.1.8, 2.1.10

Control Descriptions:
    2.1.8 - Ensure that SPF records are published for all Exchange Domains
    2.1.10 - Ensure DMARC Records for all Exchange Online domains are published

Connection Method: Microsoft Graph API + DNS queries
Required Scopes: Domain.Read.All
Graph Endpoint: /domains
DNS Records: SPF (TXT), DMARC (_dmarc.{domain} TXT)

Note: This collector uses a two-step approach:
    1. Retrieve tenant domains via Microsoft Graph API
    2. Query DNS for SPF and DMARC records for each verified domain
"""

import re
from typing import Any

from collectors.base import BaseDataCollector
from collectors.graph_client import GraphClient

# RFC 1035 s3.3.14 makes a TXT character-string an arbitrary octet string, not
# text, and a single RRset routinely mixes security records with unrelated
# answers - binary verification blobs among them. So version matching happens on
# the octets and only a matched candidate is decoded. Decoding the whole answer
# set first meant one unrelated non-UTF-8 answer raised UnicodeDecodeError and
# sent the lookup to lookup_failed/unexpected_error, discarding an SPF or DMARC
# record that had already been retrieved successfully.
#
# ASCII is the only encoding either version token can be written in, so the
# bytes forms of these patterns match exactly what the text forms did:
# bytes.lower() and bytes.strip() are ASCII-only operations.
#
# RFC 7208 s4.5 defines the SPF version section as the ABNF literal "v=spf1",
# terminated by a space or the end of the record, and RFC 5234 s2.3 makes a
# quoted ABNF literal case-insensitive: "V=SPF1 ..." is a published SPF record
# and "v=spf10 ..." is not an SPF record at all. Matching on the bare prefix gets
# both of those wrong, and the wrong answer is now stamped into an authoritative
# status, so the terminator and the case are both checked here.
SPF_VERSION = b"v=spf1"
SPF_TERMINATORS = (b" ", b"\t")

# DMARC is deliberately not the same rule. RFC 7489 s6.4 spells the version
# value out as the hexadecimal octets %x44.4d.41.52.43.31, which - unlike a
# quoted literal - is case-SENSITIVE, and s6.3 says the value "MUST match
# precisely" or the whole record is ignored. So "v=dmarc1" is a record no
# receiver honours and must not be read as a published policy. The same section
# permits whitespace either side of the "=", which is why this is a pattern
# rather than a prefix test.
DMARC_VERSION = re.compile(rb"^[vV][ \t]*=[ \t]*DMARC1(?:[ \t;]|$)")


def _matches_spf_version(txt_value: bytes) -> bool:
    """True when the TXT octets open with exactly the SPF version token."""
    lowered = txt_value.strip().lower()
    if not lowered.startswith(SPF_VERSION):
        return False
    remainder = lowered[len(SPF_VERSION) :]
    return remainder == b"" or remainder[:1] in SPF_TERMINATORS


def _matches_dmarc_version(txt_value: bytes) -> bool:
    """True when the TXT octets open with exactly the DMARC version tag."""
    return DMARC_VERSION.match(txt_value.strip()) is not None


class DnsSecurityRecordsDataCollector(BaseDataCollector):
    """Collects DNS security records (SPF, DMARC) for CIS compliance evaluation.

    This collector retrieves all verified domains from the tenant via Graph API,
    then performs DNS lookups for SPF and DMARC records on each domain.
    """

    async def collect(self, client: GraphClient) -> dict[str, Any]:
        """Collect DNS security records for all tenant domains.

        Returns:
            Dict containing:
            - domains: List of domain records with SPF/DMARC data
            - total_domains: Number of verified domains checked
        """
        import dns.resolver

        # Step 1: Get domains from Graph API
        domains = await client.get_domains()

        # Step 2: Filter for verified domains. Graph's domain resource always
        # carries isVerified, so an object without an explicit true/false is
        # anomalous evidence rather than an unverified domain: dropping it would
        # shrink the population silently and let the remaining domains report a
        # complete pass. Those objects are kept and marked unresolved instead.
        verified_domains = [d for d in domains if d.get("isVerified") is True]
        unknown_eligibility = [
            d for d in domains if not isinstance(d.get("isVerified"), bool)
        ]

        domain_records = []
        for domain, verified in [(d, True) for d in verified_domains] + [
            (d, None) for d in unknown_eligibility
        ]:
            domain_id = domain.get("id")

            record = {
                "domain": domain_id,
                "is_verified": verified,
                "is_default": domain.get("isDefault", False),
                "is_initial": domain.get("isInitial", False),
                "authentication_type": domain.get("authenticationType"),
                "spf_record": None,
                "dmarc_record": None,
                "dmarc_policy": None,
                "spf_error": None,
                "dmarc_error": None,
                # Structured per-lookup outcome, so a policy never has to parse
                # the free-text *_error strings to tell "the tenant has not
                # published a usable record" from "the lookup never answered".
                #   "found"         - exactly one record of the expected kind
                #                     was read
                #   "absent"        - the lookup completed authoritatively and
                #                     no usable record is published (tenant
                #                     state), which includes a published set
                #                     the RFCs require a receiver to discard
                #   "lookup_failed" - no authoritative answer was obtained, so
                #                     the absence of a record is unproven
                # The *_error fields keep their exact previous values; these
                # fields are purely additive for existing consumers.
                "spf_lookup_status": None,
                "spf_error_code": None,
                "dmarc_lookup_status": None,
                "dmarc_error_code": None,
            }

            # Graph returned a domain object that does not say whether it is
            # verified, so whether this control even applies to it is unknown.
            # Nothing is asked about it and nothing is asserted about it.
            if verified is not True:
                for prefix in ("spf", "dmarc"):
                    record[f"{prefix}_error"] = (
                        "Domain object does not state whether it is verified"
                    )
                    record[f"{prefix}_lookup_status"] = "lookup_failed"
                    record[f"{prefix}_error_code"] = "verification_unknown"
                domain_records.append(record)
                continue

            # Graph handed back a verified domain object with no usable name. No
            # DNS question can be asked about it, so nothing about this domain's
            # tenant state is known: labelling either lookup authoritatively
            # would report a scanner-side fault as a tenant finding, against a
            # resource with no identifier. Both lookups are skipped rather than
            # built from the unusable value - "_dmarc.None" is a resolvable name
            # whose NXDOMAIN would otherwise read as authoritative absence.
            if not isinstance(domain_id, str) or not domain_id.strip():
                for prefix in ("spf", "dmarc"):
                    record[f"{prefix}_error"] = (
                        "Domain object carries no usable domain name"
                    )
                    record[f"{prefix}_lookup_status"] = "lookup_failed"
                    record[f"{prefix}_error_code"] = "missing_domain_id"
                domain_records.append(record)
                continue

            # Whether the domain's own zone answered the apex query at all. It
            # is recorded as its own fact rather than inferred from
            # spf_lookup_status, because the two are not the same question: an
            # apex that answers with an undecodable SPF record leaves the SPF
            # status "lookup_failed" while the zone plainly did answer, and the
            # DMARC NXDOMAIN branch below needs the zone's answer, not the SPF
            # verdict. Reading it off the status dropped a confirmed missing
            # DMARC record into "could not check" for exactly that domain.
            apex_answered = False

            # Query SPF record (TXT record at domain root)
            try:
                answers = dns.resolver.resolve(domain_id, "TXT")
                apex_answered = True
                # Candidates are selected on the octets, so an answer that is
                # not text is simply not an SPF record - every answer is still
                # examined, which is what keeps a second copy detectable.
                candidates = [
                    value
                    for value in self._txt_octets(answers)
                    if _matches_spf_version(value)
                ]
                if len(candidates) > 1:
                    # RFC 7208 s4.5: more than one SPF record is a permerror -
                    # the domain has no usable SPF policy. The lookup answered,
                    # so this is tenant state, not a failed collection.
                    record["spf_error"] = "Multiple SPF records published"
                    record["spf_lookup_status"] = "absent"
                    record["spf_error_code"] = "multiple_records"
                elif not candidates:
                    # The zone answered with TXT records and none of them is an
                    # SPF record: authoritative absence, not a failed lookup.
                    record["spf_lookup_status"] = "absent"
                    record["spf_error_code"] = "no_matching_txt"
                else:
                    spf_text = self._decode_record(candidates[0])
                    if spf_text is None:
                        # The one candidate opens with the version token but its
                        # octets are not text. Something is published, so
                        # "absent" would be a false claim about the tenant, and
                        # it cannot be read, so there is no record to hand on
                        # either. Neither, and it fails closed.
                        #
                        # ACCEPTED COVERAGE GAP, decided deliberately: the
                        # policy will return indeterminate for this domain
                        # rather than a finding. Stamping "absent" was
                        # considered and rejected - it would assert the tenant
                        # published nothing when the zone demonstrably published
                        # something, and the unreadable octets may well surround
                        # a valid include. Reporting "could not check" is the
                        # only claim the evidence supports.
                        record["spf_error"] = "SPF record could not be decoded as text"
                        record["spf_lookup_status"] = "lookup_failed"
                        record["spf_error_code"] = "undecodable_record"
                    else:
                        record["spf_record"] = spf_text
                        record["spf_lookup_status"] = "found"
            except dns.resolver.NXDOMAIN:
                # The domain root does not exist in DNS at all. A Graph-verified
                # domain proved its zone existed at verification time, so this
                # means the domain lapsed, was delegated away, or the resolver is
                # being lied to - the SPF question was never actually answered.
                record["spf_error"] = "Domain not found"
                record["spf_lookup_status"] = "lookup_failed"
                record["spf_error_code"] = "nxdomain"
            except dns.resolver.NoAnswer:
                # The zone answered and carries no TXT records, so no v=spf1
                # record is published. The lookup succeeded; the tenant has not
                # done the thing.
                apex_answered = True
                record["spf_error"] = "No TXT records"
                record["spf_lookup_status"] = "absent"
                record["spf_error_code"] = "no_answer"
            except dns.resolver.NoNameservers:
                # SERVFAIL, REFUSED, DNSSEC failure or broken delegation: no
                # authoritative answer, so absence is unproven.
                record["spf_error"] = "No nameservers available"
                record["spf_lookup_status"] = "lookup_failed"
                record["spf_error_code"] = "no_nameservers"
            except dns.resolver.Timeout:
                record["spf_error"] = "DNS query timeout"
                record["spf_lookup_status"] = "lookup_failed"
                record["spf_error_code"] = "timeout"
            except Exception as e:
                # Unclassified failure - including a scanner-side bug - is by
                # definition not evidence of tenant state, so it fails closed.
                record["spf_error"] = str(e)
                record["spf_lookup_status"] = "lookup_failed"
                record["spf_error_code"] = "unexpected_error"

            # Query DMARC record (TXT record at _dmarc.{domain})
            dmarc_domain = f"_dmarc.{domain_id}"
            try:
                answers = dns.resolver.resolve(dmarc_domain, "TXT")
                candidates = [
                    value
                    for value in self._txt_octets(answers)
                    if _matches_dmarc_version(value)
                ]
                if len(candidates) > 1:
                    # RFC 7489 s6.6.3: when the retrieved set holds more than one
                    # DMARC record the domain owner's policy is not applied. The
                    # lookup answered, so this is tenant state.
                    record["dmarc_error"] = "Multiple DMARC records published"
                    record["dmarc_lookup_status"] = "absent"
                    record["dmarc_error_code"] = "multiple_records"
                elif not candidates:
                    # _dmarc.<domain> answered with TXT records and none is a
                    # DMARC record: authoritative absence.
                    record["dmarc_lookup_status"] = "absent"
                    record["dmarc_error_code"] = "no_matching_txt"
                else:
                    dmarc_text = self._decode_record(candidates[0])
                    if dmarc_text is None:
                        # As for SPF: published but unreadable is neither a
                        # record nor proof that none was published. Same
                        # accepted coverage gap - indeterminate, not a finding.
                        record["dmarc_error"] = (
                            "DMARC record could not be decoded as text"
                        )
                        record["dmarc_lookup_status"] = "lookup_failed"
                        record["dmarc_error_code"] = "undecodable_record"
                    else:
                        record["dmarc_record"] = dmarc_text
                        record["dmarc_policy"] = self._parse_dmarc_policy(dmarc_text)
                        record["dmarc_lookup_status"] = "found"
            except dns.resolver.NXDOMAIN:
                # _dmarc.<domain> only exists if someone created it, so the
                # parent zone answering "that name is not here" is the ordinary
                # way DMARC is absent - but only while the parent zone is there
                # to answer. When the apex query just returned no authoritative
                # answer of its own, this NXDOMAIN carries the same "nothing
                # answered the question" meaning it carries for SPF, and calling
                # it absence would report a failed collection as tenant
                # noncompliance. The apex outcome is already known because the
                # SPF block above always runs first and always records whether
                # the zone answered it.
                if apex_answered:
                    record["dmarc_error"] = "DMARC record not found"
                    record["dmarc_lookup_status"] = "absent"
                    record["dmarc_error_code"] = "nxdomain"
                else:
                    record["dmarc_error"] = (
                        "DMARC lookup returned NXDOMAIN and the domain's own "
                        "zone did not answer either"
                    )
                    record["dmarc_lookup_status"] = "lookup_failed"
                    record["dmarc_error_code"] = "parent_zone_unresolved"
            except dns.resolver.NoAnswer:
                # The name exists (commonly a CNAME to a DMARC host) but has no
                # TXT records, so no DMARC record is retrievable where the RFC
                # requires it to be.
                record["dmarc_error"] = "No DMARC TXT record"
                record["dmarc_lookup_status"] = "absent"
                record["dmarc_error_code"] = "no_answer"
            except dns.resolver.NoNameservers:
                # The zone said nothing at all, as opposed to NXDOMAIN's "not
                # here": no authoritative answer, so absence is unproven.
                record["dmarc_error"] = "No nameservers available"
                record["dmarc_lookup_status"] = "lookup_failed"
                record["dmarc_error_code"] = "no_nameservers"
            except dns.resolver.Timeout:
                record["dmarc_error"] = "DNS query timeout"
                record["dmarc_lookup_status"] = "lookup_failed"
                record["dmarc_error_code"] = "timeout"
            except Exception as e:
                # Unclassified failure, including name construction faults on a
                # malformed domain id. Fails closed.
                record["dmarc_error"] = str(e)
                record["dmarc_lookup_status"] = "lookup_failed"
                record["dmarc_error_code"] = "unexpected_error"

            domain_records.append(record)

        return {
            "domains": domain_records,
            "total_domains": len(domain_records),
        }

    @staticmethod
    def _txt_octets(answers: Any) -> list[bytes]:
        """Join each answer's character-strings into one TXT value, as octets.

        RFC 1035 s3.3.14 gives a character-string no encoding, so the octets are
        carried through unchanged and nothing is decoded here. An answer that is
        not text is then just an answer that does not match a version token,
        instead of an exception that discards every other answer with it.
        """
        return [
            b"".join(s if isinstance(s, bytes) else s.encode() for s in rdata.strings)
            for rdata in answers
        ]

    @staticmethod
    def _decode_record(candidate: bytes) -> str | None:
        """Decode a matched record, or None when its octets are not text."""
        try:
            return candidate.decode()
        except UnicodeDecodeError:
            return None

    def _parse_dmarc_policy(self, dmarc_record: str) -> dict[str, str]:
        """Parse DMARC record into key-value pairs.

        Args:
            dmarc_record: Raw DMARC TXT record value

        Returns:
            Dict with DMARC policy settings (p, sp, rua, ruf, pct, etc.)
        """
        policy = {}
        # Split by semicolons and parse key=value pairs. RFC 7489 s6.4 permits
        # whitespace either side of the "=", so both halves are trimmed.
        parts = dmarc_record.split(";")
        for part in parts:
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                policy[key.strip()] = value.strip()
        return policy
