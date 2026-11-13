"""Fail-fast admission checks.

Cheap structural checks run before any parent lookup. Signature verification
of the uploaded zone is last. Glue is checked before the parent lookup: it
uses only the uploaded zone, and a local defect must not cause a parent query.
"""

from __future__ import annotations

from datetime import datetime, timezone

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rrset

from dns_host.chain import Delegation, authenticate_parent
from dns_host.denial import check_nsec3
from dns_host.errors import ApiError
from dns_host.rrtypes import WALLET_TYPE, admission_block_reason, type_name
from dns_host.zone import ParsedZone

DNSKEY = int(dns.rdatatype.DNSKEY)
SOA = int(dns.rdatatype.SOA)
NS = int(dns.rdatatype.NS)
NSEC3PARAM = int(dns.rdatatype.NSEC3PARAM)
NSEC3 = int(dns.rdatatype.NSEC3)
NSEC = int(dns.rdatatype.NSEC)
RRSIG = int(dns.rdatatype.RRSIG)
CNAME = int(dns.rdatatype.CNAME)
A = int(dns.rdatatype.A)
AAAA = int(dns.rdatatype.AAAA)
URI = int(dns.rdatatype.URI)
APEX_ONLY = {SOA, DNSKEY, NSEC3PARAM}
APEX_ONLY_DATA = {URI, WALLET_TYPE}
ALLOWED_DNSKEY_ALGS = {13, 15}


def _err(status: int, error: str, message: str) -> ApiError:
    return ApiError(status, error, message)


def check_limits(zone: ParsedZone, settings) -> None:
    names = {name for name, _rdtype in zone.rrsets}
    # RRSIG records are their own JSON rrset; count data rrsets plus one RRSIG
    # rrset per distinct signature owner, which matches the upload document.
    sig_owners = {name for name, _covered in zone.sigs}
    rrset_count = len(zone.rrsets) + len(sig_owners)
    if rrset_count > settings.max_rrsets or len(names | sig_owners) > settings.max_names:
        raise _err(
            413,
            "payload_too_large",
            f"zone exceeds max_rrsets={settings.max_rrsets} or max_names={settings.max_names}",
        )


def check_soa(zone: ParsedZone, settings, held_serial: int | None) -> int:
    soa_rrs = [rr for (name, rdtype), rr in zone.rrsets.items() if rdtype == SOA]
    if len(soa_rrs) != 1 or soa_rrs[0].name != zone.apex or len(soa_rrs[0]) != 1:
        raise _err(422, "bad_soa", "zone must contain exactly one SOA at the apex")
    serial = int(list(soa_rrs[0])[0].serial)
    if held_serial is not None and serial <= held_serial:
        raise _err(
            409,
            "serial_not_increased",
            f"SOA serial {serial} is not greater than the stored serial {held_serial}",
        )
    now = settings.now()
    if serial > now + settings.serial_future_seconds:
        raise _err(422, "serial_in_future", "SOA serial is too far ahead of the service clock")
    if serial < now - settings.serial_past_seconds:
        raise _err(422, "serial_stale", "SOA serial is outside the freshness window")
    return serial


def check_types_and_ttl(zone: ParsedZone, settings) -> None:
    allowed = {item.upper() for item in settings.type_allowlist}
    for (name, rdtype), rrset in zone.rrsets.items():
        text = type_name(rdtype)
        blocked = admission_block_reason(rdtype)
        if blocked is not None:
            raise _err(422, "type_not_allowed", blocked)
        if text not in allowed:
            raise _err(422, "type_not_allowed", f"{text} is not in the type allowlist")
        if int(rrset.ttl) < settings.min_ttl or int(rrset.ttl) > settings.max_ttl:
            raise _err(422, "ttl_out_of_range", f"TTL {rrset.ttl} at {name} is outside the configured bounds")
        for rdata in rrset:
            _check_rdata_length(rdata, name, text, settings)
        if rdtype in APEX_ONLY and name != zone.apex:
            code = {SOA: "bad_soa", DNSKEY: "bad_dnskey", NSEC3PARAM: "bad_nsec3param"}[rdtype]
            raise _err(422, code, f"{text} is only permitted at the apex")
        if int(rdtype) in APEX_ONLY_DATA and name != zone.apex:
            raise _err(422, "type_not_allowed", f"{text} is only permitted at the zone apex")
        if rdtype == NS and name != zone.apex:
            raise _err(422, "type_not_allowed", "NS is only permitted at the apex")
    for (name, _covered), rrset in zone.sigs.items():
        if int(rrset.ttl) < settings.min_ttl or int(rrset.ttl) > settings.max_ttl:
            raise _err(422, "ttl_out_of_range", f"TTL {rrset.ttl} at {name} RRSIG is outside the configured bounds")
        for rdata in rrset:
            _check_rdata_length(rdata, name, "RRSIG", settings)
    by_name: dict = {}
    for (name, rdtype) in zone.rrsets:
        if rdtype in (NSEC3, NSEC):
            continue
        by_name.setdefault(name, set()).add(rdtype)
    for name, types in by_name.items():
        if CNAME in types and types - {CNAME}:
            raise _err(422, "type_not_allowed", f"CNAME at {name} shares its owner name with other data")


def _check_rdata_length(rdata, name, text, settings) -> None:
    length = len(rdata.to_wire())
    if length > settings.max_rdata_bytes:
        raise _err(
            413,
            "payload_too_large",
            f"{text} rdata at {name} is {length} bytes; limit is {settings.max_rdata_bytes}",
        )


def check_dnskey(zone: ParsedZone) -> None:
    rrset = zone.get(DNSKEY)
    if rrset is None or len(rrset) == 0:
        raise _err(422, "bad_dnskey", "apex DNSKEY RRset is missing")
    saw_ksk = False
    for key in rrset:
        if int(key.algorithm) not in ALLOWED_DNSKEY_ALGS or int(key.protocol) != 3:
            raise _err(422, "bad_dnskey", "DNSKEY must use protocol 3 and algorithm 13 or 15")
        flags = int(key.flags)
        if flags not in (256, 257):
            raise _err(422, "bad_dnskey", "DNSKEY flags must be 256 (ZSK) or 257 (KSK)")
        if flags == 257:
            saw_ksk = True
    if not saw_ksk:
        raise _err(422, "bad_dnskey", "apex DNSKEY set has no SEP/KSK (flags 257)")


def check_rrsig_meta(zone: ParsedZone, settings) -> None:
    dnskeys = list(zone.get(DNSKEY) or [])
    keytags = {(int(key.algorithm), int(dns.dnssec.key_id(key))) for key in dnskeys}
    now = settings.now()
    for (name, rdtype), rrset in zone.rrsets.items():
        sigset = zone.sigs.get((name, rdtype))
        if sigset is None or len(sigset) == 0:
            raise _err(
                422,
                "rrsig_incomplete",
                f"{dns.rdatatype.to_text(rdtype)} at {name} has no RRSIG",
            )
        for sig in sigset:
            _check_one_sig(sig, name, rdtype, rrset.ttl, keytags, zone.apex, now, settings)
    for (name, covered), sigset in zone.sigs.items():
        if (name, covered) not in zone.rrsets:
            raise _err(
                422,
                "rrsig_incomplete",
                f"RRSIG at {name} covers {dns.rdatatype.to_text(covered)} which is not in the zone",
            )


def _check_one_sig(sig, name, rdtype, ttl, keytags, apex, now, settings) -> None:
    if int(sig.type_covered) != int(rdtype):
        raise _err(422, "rrsig_key_mismatch", f"RRSIG at {name} covers the wrong type")
    if int(sig.algorithm) not in ALLOWED_DNSKEY_ALGS:
        raise _err(422, "rrsig_key_mismatch", f"RRSIG at {name} is not algorithm 13 or 15")
    if sig.signer.canonicalize() != apex.canonicalize():
        raise _err(422, "rrsig_key_mismatch", f"RRSIG at {name} signer is not the apex")
    if int(sig.labels) != len(name) - 1:
        raise _err(422, "rrsig_key_mismatch", f"RRSIG at {name} has the wrong label count")
    if int(sig.original_ttl) != int(ttl):
        raise _err(422, "rrsig_key_mismatch", f"RRSIG at {name} original TTL does not match the RRset")
    if (int(sig.algorithm), int(sig.key_tag)) not in keytags:
        raise _err(422, "rrsig_key_mismatch", f"RRSIG at {name} key tag {sig.key_tag} matches no DNSKEY")
    inception = int(sig.inception)
    expiration = int(sig.expiration)
    if inception > now + settings.rrsig_inception_future_seconds:
        raise _err(422, "rrsig_window", f"RRSIG at {name} inception is too far in the future")
    if expiration < now + settings.rrsig_min_remaining_seconds:
        raise _err(422, "rrsig_window", f"RRSIG at {name} is not inside its validity window")
    if expiration - inception > settings.rrsig_max_lifetime_seconds:
        raise _err(422, "rrsig_window", f"RRSIG at {name} lifetime exceeds the configured maximum")
    if expiration > now + settings.rrsig_max_lifetime_seconds + settings.rrsig_inception_future_seconds:
        raise _err(422, "rrsig_window", f"RRSIG at {name} expires outside the configured policy")


def check_denial(zone: ParsedZone) -> None:
    owners: dict[dns.name.Name, set[int]] = {}
    nsec3 = []
    nsec = {}
    for (name, rdtype), rrset in zone.rrsets.items():
        if rdtype == NSEC3:
            nsec3.append(rrset)
            continue
        if rdtype == NSEC:
            nsec[name] = rrset
            continue
        owners.setdefault(name, set()).add(rdtype)
    if nsec:
        raise _err(422, "type_not_allowed", "plain NSEC zones are rejected; NSEC3 is required")
    param = zone.get(NSEC3PARAM)
    if param is not None or nsec3:
        if nsec3 and param is None:
            raise _err(422, "bad_nsec3param", "NSEC3 records require NSEC3PARAM")
        check_nsec3(zone.apex, owners, nsec3, param)
        return
    raise _err(422, "bad_nsec3param", "zone has no NSEC3PARAM")


def check_apex_ns(zone: ParsedZone, settings) -> None:
    have = {target.canonicalize() for target in zone.apex_ns_names()}
    if not have:
        raise _err(422, "apex_ns_incomplete", "apex NS RRset is missing")
    required = {name.canonicalize() for name in settings.service_ns}
    if not required <= have:
        missing = sorted(name.to_text() for name in settings.service_ns if name.canonicalize() not in have)
        raise _err(
            422,
            "apex_ns_incomplete",
            "apex NS is missing service nameserver(s): " + ", ".join(missing),
        )


def check_glue(zone: ParsedZone) -> None:
    for target in zone.apex_ns_names():
        if target != zone.apex and not target.is_subdomain(zone.apex):
            continue
        if zone.get(A, target) is None and zone.get(AAAA, target) is None:
            raise _err(422, "glue_missing", f"in-bailiwick NS {target} has no A or AAAA in the zone")


def offline_checks(zone: ParsedZone, settings, held_serial: int | None) -> int:
    check_limits(zone, settings)
    serial = check_soa(zone, settings, held_serial)
    check_types_and_ttl(zone, settings)
    check_dnskey(zone)
    check_rrsig_meta(zone, settings)
    check_denial(zone)
    check_apex_ns(zone, settings)
    check_glue(zone)
    if zone.apex == settings.catalog_zone:
        raise _err(400, "bad_request", "the catalog zone name cannot be uploaded")
    return serial


def parent_checks(zone: ParsedZone, settings, lookup) -> Delegation:
    delegation = authenticate_parent(lookup, settings, zone.apex)
    parent_ns = {name.canonicalize() for name in delegation.ns_names}
    apex_ns = {name.canonicalize() for name in zone.apex_ns_names()}
    service = {name.canonicalize() for name in settings.service_ns}
    if not service <= parent_ns:
        raise _err(
            403,
            "parent_ns_incomplete",
            "parent delegation NS does not include every service nameserver",
        )
    if parent_ns != apex_ns:
        raise _err(422, "ns_set_mismatch", "parent delegation NS set does not equal the apex NS set")
    if delegation.proved_ds_absent or delegation.ds_rrset is None or len(delegation.ds_rrset) == 0:
        raise _err(403, "parent_ds_missing", "parent has no DS for this apex")
    return delegation


def ds_matches(zone: ParsedZone, delegation: Delegation, settings) -> list:
    from dns_host.chain import _keys_matching_ds

    matched = _keys_matching_ds(
        zone.apex, zone.get(DNSKEY), list(delegation.ds_rrset), settings.ds_digest_types
    )
    if not matched:
        raise _err(403, "parent_ds_mismatch", "parent DS does not match a KSK in the uploaded zone")
    return matched


def verify_signatures(zone: ParsedZone, matched_ksks, now: int) -> None:
    dnskey = zone.get(DNSKEY)
    ksk_rrset = dns.rrset.from_rdata(zone.apex, dnskey.ttl, *matched_ksks)
    dnskey_sigs = zone.sigs.get((zone.apex, DNSKEY))
    ksk_tags = {int(dns.dnssec.key_id(key)) for key in matched_ksks}
    saw_ksk_sig = False
    try:
        for sig in dnskey_sigs:
            if int(sig.key_tag) in ksk_tags:
                dns.dnssec.validate(
                    dnskey,
                    dns.rrset.from_rdata(zone.apex, dnskey.ttl, sig),
                    {zone.apex: ksk_rrset},
                    now=float(now),
                )
                saw_ksk_sig = True
            else:
                dns.dnssec.validate(
                    dnskey,
                    dns.rrset.from_rdata(zone.apex, dnskey.ttl, sig),
                    {zone.apex: dnskey},
                    now=float(now),
                )
        if not saw_ksk_sig:
            raise _err(422, "zone_validation_failed", "DNSKEY RRset is not signed by the DS-matched KSK")
        for (name, rdtype), rrset in zone.rrsets.items():
            if rdtype == DNSKEY and name == zone.apex:
                continue
            sigset = zone.sigs[(name, rdtype)]
            for sig in sigset:
                dns.dnssec.validate(
                    rrset,
                    dns.rrset.from_rdata(name, rrset.ttl, sig),
                    {zone.apex: dnskey},
                    now=float(now),
                )
    except ApiError:
        raise
    except Exception as exc:
        raise _err(422, "zone_validation_failed", f"signature verification failed: {exc}") from exc


def next_expire_hint(zone: ParsedZone) -> str:
    expiries = zone.rrsig_expiries()
    earliest = min(expiries) if expiries else 0
    return datetime.fromtimestamp(earliest, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
