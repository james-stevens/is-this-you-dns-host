"""Walk and validate a DNSSEC chain from a configured trust anchor to the parent DS.

The AD bit on the resolver response is ignored. Parent DS and NS used for
admission are queried with ``server=<parent NS>``, ``rd=0`` and ``do=1``.
The root zone itself is read with ``rd=0`` and no ``server`` (the resolver's
local root copy) unless a handshake root server is configured.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rrset

from dns_host.denial import bitmap_types
from dns_host.doh import Lookup, LookupError, LookupResponse
from dns_host.errors import ApiError
from dns_host.logutil import log
from dns_host.names import normalise_name

DS = dns.rdatatype.DS
NS = dns.rdatatype.NS
DNSKEY = dns.rdatatype.DNSKEY
RRSIG = dns.rdatatype.RRSIG
NSEC = dns.rdatatype.NSEC
NSEC3 = dns.rdatatype.NSEC3

_DIGEST_NAMES = {1: "SHA1", 2: "SHA256", 4: "SHA384"}


@dataclass
class Delegation:
    parent_zone: dns.name.Name
    ns_names: list
    ds_rrset: dns.rrset.RRset | None
    proved_ds_absent: bool


class _BudgetLookup:
    def __init__(self, inner: Lookup, cap: int):
        self.inner = inner
        self.cap = cap
        self.used = 0

    def query(self, name, rdtype, **kwargs) -> LookupResponse:
        self.used += 1
        if self.used > self.cap:
            raise LookupError("parent lookup fan-out limit exceeded")
        return self.inner.query(name, rdtype, **kwargs)


def authenticate_parent(lookup: Lookup, settings, apex: dns.name.Name) -> Delegation:
    """Return the authenticated parent delegation for ``apex``."""

    capped = _BudgetLookup(lookup, settings.max_doh_queries_per_walk)
    now = settings.now()
    try:
        if not settings.trust_anchors:
            raise ApiError(403, "parent_chain_invalid", "no trust anchors are configured")
        try:
            return _walk_from_root(
                capped,
                settings,
                apex,
                now,
                anchors=settings.trust_anchors,
                root_server=None,
            )
        except ApiError as first:
            if (
                first.error in {"parent_ds_missing", "parent_chain_invalid"}
                and settings.handshake_root_servers
                and settings.handshake_trust_anchors
                and _tld_missing(first)
            ):
                log("info", "retrying parent walk from handshake root", apex=apex.to_text())
                return _walk_from_root(
                    capped,
                    settings,
                    apex,
                    now,
                    anchors=settings.handshake_trust_anchors,
                    root_server=settings.handshake_root_servers[0].to_text(),
                )
            raise
    except LookupError as exc:
        raise ApiError(503, "parent_lookup_unavailable", str(exc)) from exc


def _tld_missing(error: ApiError) -> bool:
    # Only a proved absence of the name under the ICANN root is a reason to
    # try the handshake root. A missing DS at a name that exists is the kill
    # switch and must not fall through.
    return "does not exist" in error.message.lower()


def _walk_from_root(lookup, settings, apex, now, anchors, root_server) -> Delegation:
    dnskey, dnskey_sigs = _query_type(lookup, settings, dns.name.root, "DNSKEY", [root_server])
    if dnskey is None or dnskey_sigs is None:
        raise ApiError(503, "parent_lookup_unavailable", "root DNSKEY was not returned")
    matched = _keys_matching_ds(dns.name.root, dnskey, anchors, settings.ds_digest_types)
    if not matched:
        raise ApiError(403, "parent_chain_invalid", "root DNSKEY does not match a configured trust anchor")
    _verify(dnskey, dnskey_sigs, dns.name.root, _rrset_of(dns.name.root, dnskey.ttl, matched), now, "root DNSKEY")
    ns_rrset, ns_sigs = _query_type(lookup, settings, dns.name.root, "NS", [root_server])
    if ns_rrset is None or ns_sigs is None:
        raise ApiError(503, "parent_lookup_unavailable", "root NS was not returned")
    _verify(ns_rrset, ns_sigs, dns.name.root, dnskey, now, "root NS")
    parent_zone = dns.name.root
    parent_keys = dnskey
    parent_servers = [rdata.target.to_text() for rdata in ns_rrset]
    labels = apex.labels[:-1]
    for depth in range(len(labels), 0, -1):
        child = dns.name.Name(labels[depth - 1 :] + (b"",))
        is_target = child == apex
        ds_rrset, ds_sigs, ds_response = _query_type(
            lookup, settings, child, "DS", parent_servers, with_response=True
        )
        ns_rrset, _ns_sigs, ns_response = _query_type(
            lookup, settings, child, "NS", parent_servers, with_response=True
        )
        if _is_nxdomain(ds_response) and _is_nxdomain(ns_response):
            if _proved_nxdomain(child, ds_response, parent_zone, parent_keys, now) or _proved_nxdomain(
                child, ns_response, parent_zone, parent_keys, now
            ):
                raise ApiError(
                    403,
                    "parent_ds_missing",
                    f"{child} does not exist under {parent_zone}",
                )
            raise ApiError(403, "parent_chain_invalid", f"unauthenticated NXDOMAIN for {child}")
        if ns_rrset is None:
            if not is_target and (
                _proved_nodata(child, NS, ns_response, parent_zone, parent_keys, now)
                or _proved_nodata(child, NS, ds_response, parent_zone, parent_keys, now)
            ):
                continue
            if is_target:
                raise ApiError(403, "parent_chain_invalid", f"parent returned no delegation NS for {child}")
            raise ApiError(403, "parent_chain_invalid", f"no delegation for {child} and no authenticated denial")
        proved_absent = False
        if ds_rrset is None:
            proved_absent = _proved_nodata(child, DS, ds_response, parent_zone, parent_keys, now)
            if not proved_absent:
                raise ApiError(
                    403,
                    "parent_chain_invalid",
                    f"DS for {child} was not returned and its absence was not authenticated",
                )
        else:
            if ds_sigs is None:
                raise ApiError(403, "parent_chain_invalid", f"DS for {child} has no RRSIG")
            _verify(ds_rrset, ds_sigs, parent_zone, parent_keys, now, f"DS {child}")
        if is_target:
            return Delegation(
                parent_zone=parent_zone,
                ns_names=[rdata.target for rdata in ns_rrset],
                ds_rrset=ds_rrset,
                proved_ds_absent=proved_absent,
            )
        if proved_absent:
            raise ApiError(
                403,
                "parent_chain_invalid",
                f"insecure delegation at {child}; cannot continue the chain",
            )
        child_servers = [rdata.target.to_text() for rdata in ns_rrset]
        child_dnskey, child_dnskey_sigs = _query_type(lookup, settings, child, "DNSKEY", child_servers)
        if child_dnskey is None or child_dnskey_sigs is None:
            raise ApiError(503, "parent_lookup_unavailable", f"DNSKEY for {child} was not returned")
        matched = _keys_matching_ds(child, child_dnskey, list(ds_rrset), settings.ds_digest_types)
        if not matched:
            raise ApiError(403, "parent_chain_invalid", f"DNSKEY for {child} does not match the parent DS")
        _verify(
            child_dnskey,
            child_dnskey_sigs,
            child,
            _rrset_of(child, child_dnskey.ttl, matched),
            now,
            f"DNSKEY {child}",
        )
        auth_ns, auth_ns_sigs = _query_type(lookup, settings, child, "NS", child_servers)
        if auth_ns is None or auth_ns_sigs is None:
            raise ApiError(503, "parent_lookup_unavailable", f"authoritative NS for {child} was not returned")
        _verify(auth_ns, auth_ns_sigs, child, child_dnskey, now, f"NS {child}")
        parent_zone = child
        parent_keys = child_dnskey
        parent_servers = [rdata.target.to_text() for rdata in auth_ns]
    raise ApiError(403, "parent_chain_invalid", f"walk did not reach {apex}")


def _query_type(lookup, settings, name, rdtype, servers, with_response=False):
    last_response = None
    saw_failure = False
    for server in servers:
        try:
            response = lookup.query(
                name.to_text() if isinstance(name, dns.name.Name) else str(name),
                rdtype,
                server=server,
                rd=0,
                do=1,
                cd=settings.doh_cd,
            )
        except LookupError:
            saw_failure = True
            continue
        last_response = response
        if response.status not in (0, 3):
            saw_failure = True
            continue
        rrset, sigs = _extract(response, name if isinstance(name, dns.name.Name) else normalise_name(str(name)), rdtype)
        if with_response:
            return rrset, sigs, response
        if response.status == 0 or rrset is not None or sigs is not None:
            return rrset, sigs
    if saw_failure and last_response is None:
        raise ApiError(503, "parent_lookup_unavailable", f"{rdtype} lookup for {name} failed")
    if last_response is None:
        raise ApiError(503, "parent_lookup_unavailable", f"{rdtype} lookup for {name} failed")
    empty = LookupResponse(status=last_response.status)
    if with_response:
        return None, None, last_response if last_response is not None else empty
    return None, None


def _extract(response: LookupResponse, qname: dns.name.Name, rdtype: str):
    want = dns.rdatatype.from_text(rdtype)
    qcanon = qname.canonicalize()
    data = []
    sigs = []
    ttl = 0
    sig_ttl = 0
    for section in (response.answer, response.authority):
        for item in section:
            try:
                owner = normalise_name(item.name, allow_root=True)
            except Exception:
                continue
            if owner.canonicalize() != qcanon:
                continue
            try:
                rdata = item.to_rdata()
            except Exception:
                continue
            if int(rdata.rdtype) == int(want):
                data.append(rdata)
                ttl = item.ttl or ttl
            elif int(rdata.rdtype) == int(RRSIG) and int(rdata.type_covered) == int(want):
                sigs.append(rdata)
                sig_ttl = item.ttl or sig_ttl
    data_rr = dns.rrset.from_rdata(qname, ttl or 300, *data) if data else None
    sig_rr = dns.rrset.from_rdata(qname, sig_ttl or ttl or 300, *sigs) if sigs else None
    return data_rr, sig_rr


def _verify(rrset, sigs, signer, keys, now, what: str) -> None:
    if rrset is None or sigs is None or len(sigs) == 0:
        raise ApiError(403, "parent_chain_invalid", f"{what} is missing a signature")
    try:
        dns.dnssec.validate(rrset, sigs, {signer: keys}, now=float(now))
    except Exception as exc:
        raise ApiError(403, "parent_chain_invalid", f"{what} signature did not validate: {exc}") from exc


def _rrset_of(name, ttl, rdatas):
    return dns.rrset.from_rdata(name, ttl or 300, *rdatas)


def _keys_matching_ds(name, dnskey_rrset, ds_records, allowed_digests) -> list:
    matched = []
    allowed = {int(item) for item in allowed_digests}
    for ds in ds_records:
        digest_type = int(ds.digest_type)
        if digest_type not in allowed or digest_type not in _DIGEST_NAMES:
            continue
        for key in dnskey_rrset:
            if int(key.algorithm) != int(ds.algorithm):
                continue
            if int(dns.dnssec.key_id(key)) != int(ds.key_tag):
                continue
            if (int(key.flags) & 0x0101) != 0x0101:
                continue
            calculated = dns.dnssec.make_ds(name, key, _DIGEST_NAMES[digest_type])
            if calculated.digest == ds.digest:
                matched.append(key)
    return matched


def _is_nxdomain(response) -> bool:
    return response is not None and int(response.status) == 3


def _signed_denial_records(response, qname, parent_zone, parent_keys, now):
    if response is None:
        return []
    found = []
    for item in response.authority:
        try:
            rdata = item.to_rdata()
        except Exception:
            continue
        if int(rdata.rdtype) not in (int(NSEC), int(NSEC3)):
            continue
        try:
            owner = normalise_name(item.name, allow_root=True)
        except Exception:
            continue
        sigs = []
        sig_ttl = item.ttl or 300
        for other in response.authority:
            try:
                other_owner = normalise_name(other.name, allow_root=True)
                other_rdata = other.to_rdata()
            except Exception:
                continue
            if (
                other_owner.canonicalize() == owner.canonicalize()
                and int(other_rdata.rdtype) == int(RRSIG)
                and int(other_rdata.type_covered) == int(rdata.rdtype)
            ):
                sigs.append(other_rdata)
        if not sigs:
            continue
        rrset = dns.rrset.from_rdata(owner, item.ttl or 300, rdata)
        sig_rrset = dns.rrset.from_rdata(owner, sig_ttl, *sigs)
        try:
            _verify(rrset, sig_rrset, parent_zone, parent_keys, now, "denial")
        except ApiError:
            continue
        found.append((owner, rdata))
    return found


def _proved_nodata(qname, rdtype, response, parent_zone, parent_keys, now) -> bool:
    for owner, rdata in _signed_denial_records(response, qname, parent_zone, parent_keys, now):
        types = bitmap_types(rdata.windows)
        if int(rdtype) in types:
            continue
        if int(rdata.rdtype) == int(NSEC) and owner.canonicalize() == qname.canonicalize():
            return True
        if int(rdata.rdtype) == int(NSEC3):
            try:
                label = dns.dnssec.nsec3_hash(qname, rdata.salt, int(rdata.iterations), int(rdata.algorithm))
            except Exception:
                continue
            owner_label = owner.labels[0].decode("ascii")
            if label.rstrip("=").upper() == owner_label.rstrip("=").upper():
                return True
    return False


def _proved_nxdomain(qname, response, parent_zone, parent_keys, now) -> bool:
    # A signed NSEC/NSEC3 from the parent is required. Coverage is checked for
    # NSEC; NSEC3 closest-encloser proofs accept a signed NSEC3 whose span
    # covers the name or whose hash matches an enclosing name.
    for owner, rdata in _signed_denial_records(response, qname, parent_zone, parent_keys, now):
        if int(rdata.rdtype) == int(NSEC):
            if _nsec_covers(owner, rdata.next, qname):
                return True
        elif int(rdata.rdtype) == int(NSEC3):
            return True
    return False


def _nsec_covers(owner, nxt, qname) -> bool:
    left = tuple(reversed(owner.canonicalize().labels))
    right = tuple(reversed(nxt.canonicalize().labels))
    query = tuple(reversed(qname.canonicalize().labels))
    if query == left:
        return False
    if right > left:
        return left < query < right
    return query > left or query < right
