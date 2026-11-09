"""Build and sign zones for the demo CLI and the test suite.

The hosting service never signs customer zones. Signing lives here so a
self-hoster can produce a sample upload, and so tests can generate fixtures
instead of checking in static signatures.
"""

from __future__ import annotations

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdata
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

from dns_host.denial import expected_types, hash_label, zone_names_and_ents

ALG = dns.dnssec.ECDSAP256SHA256


def generate_key(flags: int):
    private = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(private.public_key(), ALG, flags=flags)
    return private, dnskey


def sign_rrset(rrset, private, dnskey, signer, inception: int, expiration: int):
    return dns.dnssec.sign(
        rrset,
        private,
        signer=signer,
        dnskey=dnskey,
        inception=int(inception),
        expiration=int(expiration),
    )


def _rr(name, rdtype, ttl, *texts, origin):
    rdatas = [
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.from_text(rdtype),
            text,
            origin=origin,
            relativize=False,
        )
        for text in texts
    ]
    return dns.rrset.from_rdata(name, ttl, *rdatas)


def signed_zone_document(
    *,
    apex: str,
    serial: int,
    ns_names: list[str],
    ksk_private,
    ksk,
    zsk_private,
    zsk,
    inception: int,
    expiration: int,
    ttl: int = 300,
    extras: list[tuple[str, str, list[str]]] | None = None,
    nsec3: bool = True,
    tamper: str | None = None,
    soa_rname: str | None = None,
    soa_mname: str | None = None,
) -> dict:
    origin = dns.name.from_text(apex)
    if not origin.is_absolute():
        origin = dns.name.from_text(apex if apex.endswith(".") else apex + ".")
    mname = dns.name.from_text(soa_mname or ns_names[0])
    rname = dns.name.from_text(soa_rname or "hostmaster." + origin.to_text())
    soa_text = (
        f"{mname.to_text()} {rname.to_text()} {int(serial)} 3600 600 864000 300"
    )
    records = [
        _rr(origin, "SOA", ttl, soa_text, origin=origin),
        _rr(origin, "NS", ttl, *[dns.name.from_text(item).to_text() for item in ns_names], origin=origin),
        dns.rrset.from_rdata(origin, ttl, ksk, zsk),
    ]
    if nsec3:
        records.append(_rr(origin, "NSEC3PARAM", ttl, "1 0 0 -", origin=origin))
    for name_text, rdtype, rrdatas in extras or []:
        owner = dns.name.from_text(name_text, origin)
        records.append(_rr(owner, rdtype, ttl, *rrdatas, origin=origin))

    owners: dict[dns.name.Name, set[int]] = {}
    for rrset in records:
        owners.setdefault(rrset.name, set()).add(int(rrset.rdtype))
    covered = zone_names_and_ents(set(owners), origin)

    if nsec3:
        hashed = []
        for name in covered:
            label = hash_label(name, b"", 0, 1).lower()
            types = expected_types(owners.get(name, set()))
            hashed.append((label, name, types))
        hashed.sort(key=lambda item: item[0])
        for index, (label, _name, types) in enumerate(hashed):
            nxt = hashed[(index + 1) % len(hashed)][0]
            type_text = " ".join(dns.rdatatype.to_text(item) for item in sorted(types))
            text = f"1 0 0 - {nxt}" + (f" {type_text}" if type_text else "")
            owner = dns.name.from_text(label, origin)
            records.append(_rr(owner, "NSEC3", ttl, text, origin=origin))
    else:
        names = sorted(covered, key=lambda name: tuple(reversed(name.canonicalize().labels)))
        for index, name in enumerate(names):
            nxt = names[(index + 1) % len(names)]
            types = expected_types(owners.get(name, set()))
            type_text = " ".join(dns.rdatatype.to_text(item) for item in sorted(types))
            text = nxt.to_text() + (f" {type_text}" if type_text else "")
            records.append(_rr(name, "NSEC", ttl, text, origin=origin))

    sigs_by_owner: dict[dns.name.Name, list] = {}
    for rrset in records:
        if int(rrset.rdtype) == int(dns.rdatatype.DNSKEY):
            signature = sign_rrset(rrset, ksk_private, ksk, origin, inception, expiration)
        else:
            signature = sign_rrset(rrset, zsk_private, zsk, origin, inception, expiration)
        sigs_by_owner.setdefault(rrset.name, []).append(signature)

    def _presentation(rrset) -> dict:
        return {
            "kind": "dns#resourceRecordSet",
            "name": rrset.name.to_text(),
            "type": dns.rdatatype.to_text(rrset.rdtype),
            "ttl": int(rrset.ttl),
            "rrdatas": [rdata.to_text(origin=origin, relativize=False) for rdata in rrset],
        }

    rrsets = [_presentation(rrset) for rrset in records]
    for owner, signatures in sigs_by_owner.items():
        rrsets.append(
            {
                "kind": "dns#resourceRecordSet",
                "name": owner.to_text(),
                "type": "RRSIG",
                "ttl": int(ttl),
                "rrdatas": [sig.to_text(origin=origin, relativize=False) for sig in signatures],
            }
        )
    if tamper:
        for item in rrsets:
            if item["type"] == "TXT" and item["name"] == dns.name.from_text(tamper, origin).to_text():
                item["rrdatas"] = ['"tampered"']
                break
        else:
            raise RuntimeError(f"tamper target {tamper} not found")
    return {"kind": "dnsauth#signedZone", "apex": origin.to_text(), "rrsets": rrsets}


def ds_text(apex: str, dnskey, digest: str = "SHA256") -> str:
    name = dns.name.from_text(apex)
    ds = dns.dnssec.make_ds(name, dnskey, digest)
    return f"{name.to_text()} IN DS {ds.to_text()}"
