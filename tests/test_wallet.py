"""WALLET (type 262) uploads, including the RFC 3597 fallback."""

import dns.dnssec
import dns.name
import dns.query
import dns.rdata
import dns.rdatatype
import dns.rrset

from dns_host.dns_server import DnsServer
from dns_host.rrtypes import rdata_from_text
from dns_host.zonesign import generate_key, sign_rrset
from tests.conftest import post
from tests.test_axfr_grace import _records


def test_wallet_two_and_four_strings_and_apex_uri(env):
    apex = env.lab.apex.to_text()
    body = env.lab.zone(
        extras=[
            (apex, "URI", ['10 1 "https://example.org/j"']),
            (
                apex,
                "WALLET",
                [
                    '"btc" "bc1qexampleaddress"',
                    '"eth" "0xabc" "cold wallet" "20"',
                ],
            ),
        ]
    )
    response = post(env, body)
    assert response.status_code == 201, response.get_json()
    server = DnsServer(env.settings, env.store)
    server.start()
    try:
        messages = dns.query.xfr(
            "127.0.0.1",
            "user.example.",
            port=env.settings.dns_port,
            timeout=2,
            relativize=False,
        )
        records = _records(messages)
    finally:
        server.stop()
    wallets = [text for _name, rdtype, text in records if rdtype == "WALLET"]
    uris = [text for name, rdtype, text in records if rdtype == "URI" and name == apex]
    assert uris, records
    assert any("bc1qexampleaddress" in text for text in wallets)
    assert any("cold wallet" in text and "0xabc" in text for text in wallets)
    assert any('"20"' in text or text.endswith("20") for text in wallets)


def test_wallet_rejects_other_string_counts():
    for text in ('"only-one"', '"a" "b" "c"', '"a" "b" "c" "d" "e"'):
        try:
            rdata_from_text("WALLET", text)
        except ValueError as exc:
            assert "2" in str(exc) and "4" in str(exc)
        else:
            raise AssertionError(f"accepted {text}")


def test_generic_wallet_wire_matches_native_and_signs(monkeypatch):
    import dns_host.rrtypes as rrtypes

    monkeypatch.setattr(rrtypes, "_force_generic_wallet", True)
    samples = ['"btc" "bc1qexampleaddress"', '"eth" "0xabc" "cold wallet" "20"']
    generic = [rdata_from_text("WALLET", text) for text in samples]
    native = [dns.rdata.from_text("IN", "WALLET", text) for text in samples]
    assert all(isinstance(item, dns.rdata.GenericRdata) for item in generic)
    assert [item.to_wire() for item in generic] == [item.to_wire() for item in native]
    owner = dns.name.from_text("user.example.")
    rrset = dns.rrset.from_rdata(owner, 300, *generic)
    private, dnskey = generate_key(256)
    signature = sign_rrset(rrset, private, dnskey, owner, 1_700_000_000, 1_700_000_000 + 86400)
    dns.dnssec.validate(
        rrset,
        dns.rrset.from_rdata(owner, 300, signature),
        {owner: dns.rrset.from_rdata(owner, 300, dnskey)},
        now=1_700_000_100,
    )
    assert int(generic[0].rdtype) == 262
    assert dns.rdatatype.to_text(generic[0].rdtype) == "WALLET"
