"""Parse an upload document into dnspython RRsets and persist them by wire."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

import dns.rdataclass
import dns.rdata
import dns.rdatatype
import dns.rrset

from dns_host.errors import ApiError
from dns_host.names import name_in_bailiwick, normalise_apex, normalise_name

RRSIG = dns.rdatatype.RRSIG


@dataclass
class ParsedZone:
    apex: dns.name.Name
    rrsets: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = field(default_factory=dict)
    sigs: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = field(default_factory=dict)

    def get(self, rdtype, name=None):
        owner = self.apex if name is None else name
        return self.rrsets.get((owner, int(rdtype)))

    def soa_rdata(self):
        rrset = self.get(dns.rdatatype.SOA)
        if rrset is None or len(rrset) != 1:
            return None
        return list(rrset)[0]

    def apex_ns_names(self) -> list:
        rrset = self.get(dns.rdatatype.NS)
        if rrset is None:
            return []
        return [rdata.target for rdata in rrset]

    def ksks(self) -> list:
        rrset = self.get(dns.rdatatype.DNSKEY)
        if rrset is None:
            return []
        return [key for key in rrset if (int(key.flags) & 0x0101) == 0x0101]

    def rrsig_expiries(self) -> list[int]:
        expiries = []
        for rrset in self.sigs.values():
            for sig in rrset:
                expiries.append(int(sig.expiration))
        return expiries

    def to_document(self) -> dict:
        grouped: dict[tuple[str, str], dict] = {}
        for (name, _rdtype), rrset in self.rrsets.items():
            _add_group(grouped, rrset)
        for (name, covered), rrset in self.sigs.items():
            _add_group(grouped, rrset)
        rrsets = [grouped[key] for key in sorted(grouped)]
        return {"apex": self.apex.to_text(), "rrsets": rrsets}

    def axfr_rrsets(self) -> list:
        """SOA first, then every other RRset including RRSIGs. No trailing SOA."""

        ordered = []
        soa = self.get(dns.rdatatype.SOA)
        if soa is not None:
            ordered.append(soa)
        rest = []
        for key in sorted(self.rrsets, key=_sort_key):
            if key[1] == int(dns.rdatatype.SOA):
                continue
            rest.append(self.rrsets[key])
        for key in sorted(self.sigs, key=_sort_key):
            rest.append(self.sigs[key])
        ordered.extend(rest)
        return ordered


def _sort_key(key):
    name, rdtype = key
    return (tuple(reversed(name.canonicalize().labels)), int(rdtype))


def _add_group(grouped: dict, rrset: dns.rrset.RRset) -> None:
    type_text = dns.rdatatype.to_text(rrset.rdtype)
    map_key = (rrset.name.to_text(), type_text)
    bucket = grouped.get(map_key)
    wires = [base64.b64encode(rdata.to_wire()).decode("ascii") for rdata in rrset]
    if bucket is None:
        grouped[map_key] = {
            "name": rrset.name.to_text(),
            "type": type_text,
            "ttl": int(rrset.ttl),
            "wire": wires,
        }
    else:
        bucket["wire"].extend(wires)


def document_to_zone(apex: dns.name.Name, document: dict) -> ParsedZone:
    parsed = ParsedZone(apex=apex)
    for item in document["rrsets"]:
        rdtype = dns.rdatatype.from_text(item["type"])
        name = normalise_name(item["name"])
        ttl = int(item["ttl"])
        rdatas = []
        for encoded in item["wire"]:
            wire = base64.b64decode(encoded)
            rdatas.append(dns.rdata.from_wire(dns.rdataclass.IN, rdtype, wire, 0, len(wire)))
        if rdtype == RRSIG:
            by_covered: dict[int, list] = {}
            for rdata in rdatas:
                by_covered.setdefault(int(rdata.type_covered), []).append(rdata)
            for covered, group in by_covered.items():
                parsed.sigs[(name, covered)] = dns.rrset.from_rdata(name, ttl, *group)
        else:
            parsed.rrsets[(name, int(rdtype))] = dns.rrset.from_rdata(name, ttl, *rdatas)
    return parsed


def parse_upload(body: dict, url_apex: dns.name.Name) -> ParsedZone:
    if not isinstance(body, dict):
        raise ApiError(400, "bad_request", "JSON body must be an object")
    if body.get("kind") != "dnsauth#signedZone":
        raise ApiError(400, "bad_request", 'kind must be "dnsauth#signedZone"')
    if "apex" not in body or "rrsets" not in body:
        raise ApiError(400, "bad_request", "apex and rrsets are required")
    apex = normalise_apex(body["apex"])
    if apex != url_apex:
        raise ApiError(400, "bad_request", "JSON apex does not match the URL apex")
    rrsets = body["rrsets"]
    if not isinstance(rrsets, list):
        raise ApiError(400, "bad_request", "rrsets must be an array")
    parsed = ParsedZone(apex=apex)
    seen: set[tuple[dns.name.Name, int]] = set()
    for index, item in enumerate(rrsets):
        if not isinstance(item, dict):
            raise ApiError(400, "bad_request", f"rrsets[{index}] must be an object")
        if item.get("kind") != "dns#resourceRecordSet":
            raise ApiError(400, "bad_request", f"rrsets[{index}].kind must be dns#resourceRecordSet")
        for field_name in ("name", "type", "ttl", "rrdatas"):
            if field_name not in item:
                raise ApiError(400, "bad_request", f"rrsets[{index}] missing {field_name}")
        try:
            owner = normalise_name(item["name"], what=f"rrsets[{index}].name")
        except ApiError:
            raise
        if not name_in_bailiwick(owner, apex):
            raise ApiError(
                422,
                "name_out_of_bailiwick",
                f"{owner} is not at or below {apex}",
            )
        try:
            rdtype = dns.rdatatype.from_text(str(item["type"]))
        except Exception as exc:
            raise ApiError(400, "bad_request", f"rrsets[{index}].type is not a DNS type") from exc
        if not isinstance(item["ttl"], int) or isinstance(item["ttl"], bool) or item["ttl"] < 0:
            raise ApiError(400, "bad_request", f"rrsets[{index}].ttl must be a non-negative integer")
        datas = item["rrdatas"]
        if not isinstance(datas, list) or not datas:
            raise ApiError(400, "bad_request", f"rrsets[{index}].rrdatas must be a non-empty array")
        key = (owner, int(rdtype))
        if key in seen:
            raise ApiError(422, "duplicate_rrset", f"duplicate RRset {owner} {dns.rdatatype.to_text(rdtype)}")
        seen.add(key)
        rdatas = []
        texts = set()
        for data in datas:
            if not isinstance(data, str) or not data.strip():
                raise ApiError(400, "bad_request", f"rrsets[{index}].rrdatas must be strings")
            if data in texts:
                raise ApiError(400, "bad_request", f"rrsets[{index}] contains duplicate rdata")
            texts.add(data)
            try:
                rdatas.append(
                    dns.rdata.from_text(
                        dns.rdataclass.IN, rdtype, data, origin=apex, relativize=False
                    )
                )
            except Exception as exc:
                raise ApiError(
                    400,
                    "bad_request",
                    f"rrsets[{index}] {dns.rdatatype.to_text(rdtype)} rdata did not parse: {exc}",
                ) from exc
        if rdtype == RRSIG:
            by_covered: dict[int, list] = {}
            for rdata in rdatas:
                by_covered.setdefault(int(rdata.type_covered), []).append(rdata)
            for covered, group in by_covered.items():
                sig_key = (owner, covered)
                if sig_key in parsed.sigs:
                    raise ApiError(422, "duplicate_rrset", f"duplicate RRSIG covering {owner}")
                parsed.sigs[sig_key] = dns.rrset.from_rdata(owner, int(item["ttl"]), *group)
        else:
            parsed.rrsets[key] = dns.rrset.from_rdata(owner, int(item["ttl"]), *rdatas)
    return parsed
