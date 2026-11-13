"""Catalog zone (RFC 9432 schema version 2).

The catalog is unsigned. Secondaries authenticate the transfer with the
AXFR allow-list and optional TSIG, not with DNSSEC. Member labels are the
first 32 hex characters of SHA-256 over the canonical wire name, which fits
in one label and stays stable across restarts.
"""

from __future__ import annotations

import hashlib

import dns.name
import dns.rdataclass
import dns.rdata
import dns.rdatatype
import dns.rrset


def member_label(apex: dns.name.Name) -> str:
    return hashlib.sha256(apex.canonicalize().to_wire()).hexdigest()[:32]


def catalog_rrsets(settings, serial: int, members: list[str]) -> list:
    origin = settings.catalog_zone
    ttl = settings.catalog_ttl
    mname = settings.service_ns[0]
    rname = settings.catalog_rname
    soa_text = (
        f"{mname.to_text()} {rname.to_text()} {int(serial)} "
        f"{settings.soa_refresh} {settings.soa_retry} {settings.soa_expire} {settings.soa_minimum}"
    )
    soa = dns.rrset.from_text(origin, ttl, "IN", "SOA", soa_text)
    ns = dns.rrset.from_text(
        origin,
        ttl,
        "IN",
        "NS",
        *[name.to_text() for name in settings.service_ns],
    )
    version = dns.rrset.from_text(dns.name.from_text("version", origin), ttl, "IN", "TXT", '"2"')
    rrsets = [soa, ns, version]
    for apex_text in members:
        apex = dns.name.from_text(apex_text)
        owner = dns.name.from_text(member_label(apex), dns.name.from_text("zones", origin))
        ptr = dns.rrset.from_text(owner, ttl, "IN", "PTR", apex.to_text())
        rrsets.append(ptr)
    return rrsets


def catalog_soa(settings, serial: int):
    return catalog_rrsets(settings, serial, [])[0]
