"""Signed fixture zones and an in-memory parent chain for tests."""

from __future__ import annotations

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdata
import dns.rdatatype
import dns.rrset

from dns_host.doh import LookupRR, LookupResponse
from dns_host.zonesign import generate_key, sign_rrset, signed_zone_document


def _abs(text: str) -> dns.name.Name:
    if not str(text).endswith("."):
        text = str(text) + "."
    return dns.name.from_text(text)


def _key(name, rdtype, server) -> tuple[str, str, str]:
    name_text = name if isinstance(name, str) else name.to_text()
    if not name_text.endswith("."):
        name_text += "."
    server_text = ""
    if server:
        server_text = server if isinstance(server, str) else server.to_text()
        if not server_text.endswith("."):
            server_text += "."
    return (name_text.lower(), str(rdtype).upper(), server_text.lower())


def _pack(rrset, sigs=None, section="answer") -> list[LookupRR]:
    items = []
    records = list(rrset)
    if sigs is not None:
        records = list(rrset)  # data only; sigs added below
    for rdata in rrset:
        items.append(_rr(rrset.name, rrset.rdtype, rrset.ttl, rdata))
    if sigs is not None:
        for rdata in sigs:
            items.append(_rr(sigs.name, dns.rdatatype.RRSIG, sigs.ttl, rdata))
    return items


def _rr(name, rdtype, ttl, rdata) -> LookupRR:
    return LookupRR(
        name=name.to_text(),
        rdtype=dns.rdatatype.to_text(rdata.rdtype),
        ttl=int(ttl),
        data=rdata.to_text(),
        wire=rdata.to_wire(),
    )


class Lab:
    """Root -> example. -> user.example. with algorithm-13 keys."""

    def __init__(self, now: int):
        self.now = now
        self.inception = now - 120
        self.expiration = now + 10 * 86400
        self.root = dns.name.root
        self.parent = _abs("example.")
        self.apex = _abs("user.example.")
        self.root_ns = [_abs("a.root-servers.net.")]
        self.parent_ns = [_abs("ns1.example."), _abs("ns2.example.")]
        self.service_ns = [_abs("ns1.svc.test."), _abs("ns2.svc.test.")]
        self.root_ksk_priv, self.root_ksk = generate_key(257)
        self.root_zsk_priv, self.root_zsk = generate_key(256)
        self.parent_ksk_priv, self.parent_ksk = generate_key(257)
        self.parent_zsk_priv, self.parent_zsk = generate_key(256)
        self.child_ksk_priv, self.child_ksk = generate_key(257)
        self.child_zsk_priv, self.child_zsk = generate_key(256)
        self.root_ds = dns.dnssec.make_ds(self.root, self.root_ksk, "SHA256")
        self.calls: list[dict] = []
        self.responses: dict[tuple[str, str, str], LookupResponse] = {}
        self.publish()

    def publish(self, *, ds="match", ns="match") -> None:
        self.responses.clear()
        ttl = 300
        root_dnskey = dns.rrset.from_rdata(self.root, ttl, self.root_ksk, self.root_zsk)
        root_dnskey_sig = self._sig(root_dnskey, self.root_ksk_priv, self.root_ksk, self.root)
        root_ns = dns.rrset.from_text(self.root, ttl, "IN", "NS", *[name.to_text() for name in self.root_ns])
        root_ns_sig = self._sig(root_ns, self.root_zsk_priv, self.root_zsk, self.root)
        self._put(self.root, "DNSKEY", None, root_dnskey, root_dnskey_sig)
        self._put(self.root, "NS", None, root_ns, root_ns_sig)

        parent_ds = dns.rrset.from_rdata(
            self.parent, ttl, dns.dnssec.make_ds(self.parent, self.parent_ksk, "SHA256")
        )
        parent_ds_sig = self._sig(parent_ds, self.root_zsk_priv, self.root_zsk, self.root)
        self._put(self.parent, "DS", self.root_ns[0], parent_ds, parent_ds_sig)
        parent_ref = dns.rrset.from_text(
            self.parent, ttl, "IN", "NS", *[name.to_text() for name in self.parent_ns]
        )
        self._put(self.parent, "NS", self.root_ns[0], parent_ref, None, section="authority")

        parent_dnskey = dns.rrset.from_rdata(self.parent, ttl, self.parent_ksk, self.parent_zsk)
        parent_dnskey_sig = self._sig(parent_dnskey, self.parent_ksk_priv, self.parent_ksk, self.parent)
        parent_auth_ns = dns.rrset.from_text(
            self.parent, ttl, "IN", "NS", *[name.to_text() for name in self.parent_ns]
        )
        parent_auth_sig = self._sig(parent_auth_ns, self.parent_zsk_priv, self.parent_zsk, self.parent)
        for server in self.parent_ns:
            self._put(self.parent, "DNSKEY", server, parent_dnskey, parent_dnskey_sig)
            self._put(self.parent, "NS", server, parent_auth_ns, parent_auth_sig)

        if ds == "missing":
            self._put_missing_ds()
        elif ds == "mismatch":
            _priv, other = generate_key(257)
            wrong = dns.rrset.from_rdata(self.apex, ttl, dns.dnssec.make_ds(self.apex, other, "SHA256"))
            wrong_sig = self._sig(wrong, self.parent_zsk_priv, self.parent_zsk, self.parent)
            for server in self.parent_ns:
                self._put(self.apex, "DS", server, wrong, wrong_sig)
        else:
            child_ds = dns.rrset.from_rdata(
                self.apex, ttl, dns.dnssec.make_ds(self.apex, self.child_ksk, "SHA256")
            )
            child_ds_sig = self._sig(child_ds, self.parent_zsk_priv, self.parent_zsk, self.parent)
            for server in self.parent_ns:
                self._put(self.apex, "DS", server, child_ds, child_ds_sig)

        if ns == "incomplete":
            targets = [self.service_ns[0]]
        elif ns == "extra":
            targets = self.service_ns + [_abs("ns.other.example.")]
        else:
            targets = list(self.service_ns)
        referral = dns.rrset.from_text(self.apex, ttl, "IN", "NS", *[name.to_text() for name in targets])
        for server in self.parent_ns:
            self._put(self.apex, "NS", server, referral, None, section="authority")

    def _put_missing_ds(self) -> None:
        ttl = 300
        nsec = dns.rrset.from_text(self.apex, ttl, "IN", "NSEC", f"zzzz.{self.parent.to_text()} NS")
        nsec_sig = self._sig(nsec, self.parent_zsk_priv, self.parent_zsk, self.parent)
        referral = dns.rrset.from_text(
            self.apex, ttl, "IN", "NS", *[name.to_text() for name in self.service_ns]
        )
        for server in self.parent_ns:
            items = _pack(nsec, nsec_sig) + _pack(referral)
            self.responses[_key(self.apex, "DS", server)] = LookupResponse(
                status=0, authority=items, aa=False
            )

    def _sig(self, rrset, private, dnskey, signer):
        signature = sign_rrset(rrset, private, dnskey, signer, self.inception, self.expiration)
        return dns.rrset.from_rdata(rrset.name, rrset.ttl, signature)

    def _put(self, name, rdtype, server, rrset, sigs, section="answer") -> None:
        items = _pack(rrset, sigs)
        response = LookupResponse(status=0, aa=sigs is not None)
        if section == "answer":
            response.answer = items
        else:
            response.authority = items
        self.responses[_key(name, rdtype, server)] = response

    def query(self, name, rdtype, *, server=None, rd=0, do=1, cd=None):
        record = {
            "name": name,
            "type": rdtype,
            "server": server,
            "rd": rd,
            "do": do,
            "cd": cd,
        }
        self.calls.append(record)
        found = self.responses.get(_key(name, rdtype, server))
        if found is None:
            return LookupResponse(status=2)
        return found

    def zone(self, **kwargs) -> dict:
        serial = kwargs.get("serial", self.now)
        return signed_zone_document(
            apex=self.apex.to_text(),
            serial=serial,
            ns_names=[
                name if isinstance(name, str) else name.to_text()
                for name in kwargs.get("ns_names", self.service_ns)
            ],
            ksk_private=self.child_ksk_priv,
            ksk=self.child_ksk,
            zsk_private=self.child_zsk_priv,
            zsk=self.child_zsk,
            inception=kwargs.get("inception", self.inception),
            expiration=kwargs.get("expiration", self.now + 7 * 86400),
            ttl=kwargs.get("ttl", 300),
            extras=kwargs.get(
                "extras",
                [
                    (f"_auth.7e9a2f4c8b1d.{self.apex.to_text()}", "TXT", ['"v=dnsauth1 alg=ES256 k=example"']),
                    (f"_web._tcp.{self.apex.to_text()}", "URI", ['10 1 "https://example.org/j"']),
                ],
            ),
            nsec3=kwargs.get("nsec3", True),
            tamper=kwargs.get("tamper"),
        )
