"""AXFR access control, catalog contents, and grace-period retention."""

import base64
import os

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring

from dns_host.dns_server import DnsServer
from dns_host.maintenance import Maintenance
from tests.conftest import post


def _xfr(port, zone, keyring=None, keyname=None):
    kwargs = {"timeout": 2}
    if keyring is not None:
        kwargs["keyring"] = keyring
        kwargs["keyname"] = keyname
        kwargs["keyalgorithm"] = dns.tsig.HMAC_SHA256
    return list(dns.query.xfr("127.0.0.1", zone, port=port, **kwargs))


def _records(messages):
    found = []
    for message in messages:
        for rrset in message.answer:
            for rdata in rrset:
                found.append((rrset.name.to_text(), dns.rdatatype.to_text(rrset.rdtype), rdata.to_text()))
    return found


def test_axfr_allow_deny_and_catalog_member(env):
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()
    server = DnsServer(env.settings, env.store)
    port = server.start()
    try:
        member = _records(_xfr(port, "user.example."))
        assert any(rdtype == "SOA" for _name, rdtype, _text in member)
        assert any(rdtype == "TXT" for _name, rdtype, _text in member)
        catalog = _records(_xfr(port, "catalog.svc.test."))
        assert any(rdtype == "TXT" and text.strip('"') == "2" for _name, rdtype, text in catalog)
        assert any(rdtype == "PTR" and text == "user.example." for _name, rdtype, text in catalog)

        query = dns.message.make_query("user.example.", "IXFR")
        ixfr = dns.query.tcp(query, "127.0.0.1", port=port, timeout=2)
        assert ixfr.rcode() == dns.rcode.NOTIMP

        env.settings.secondaries = [("192.0.2.10", 53)]
        denied = dns.query.tcp(
            dns.message.make_query("user.example.", "AXFR"),
            "127.0.0.1",
            port=port,
            timeout=2,
        )
        assert denied.rcode() == dns.rcode.REFUSED

        secret = base64.b64encode(os.urandom(32)).decode()
        env.settings.tsig_key_name = "transfer.svc.test."
        env.settings.tsig_secret = secret
        keyring = dns.tsigkeyring.from_text({"transfer.svc.test.": secret})
        for name, key in list(keyring.items()):
            raw = key.secret if hasattr(key, "secret") else key
            keyring[name] = dns.tsig.Key(name, raw, dns.tsig.HMAC_SHA256)
        signed = _records(
            _xfr(port, "user.example.", keyring=keyring, keyname=dns.name.from_text("transfer.svc.test."))
        )
        assert any(rdtype == "SOA" for _name, rdtype, _text in signed)
    finally:
        server.stop()


def test_rrsig_expiry_keeps_zone_until_grace_ends(env):
    body = env.lab.zone(expiration=env.clock.t + 100)
    assert post(env, body).status_code == 201
    server = DnsServer(env.settings, env.store)
    server.start()
    maintenance = Maintenance(env.settings, env.store, lookup=env.lab, notifier=env.notifier)
    try:
        env.clock.t += 150
        maintenance.run_once()
        assert env.store.get_zone("user.example.") is not None
        records = _records(_xfr(env.settings.dns_port, "user.example."))
        assert any(rdtype == "SOA" for _name, rdtype, _text in records)
        env.clock.t = body_expiry(body) + env.settings.grace_seconds + 5
        env.notifier.zones.clear()
        maintenance.run_once()
        assert env.store.get_zone("user.example.") is None
        assert env.notifier.zones == ["catalog.svc.test."]
        catalog = _records(_xfr(env.settings.dns_port, "catalog.svc.test."))
        assert not any(rdtype == "PTR" for _name, rdtype, _text in catalog)
    finally:
        server.stop()


def body_expiry(body) -> int:
    import dns.rdatatype
    import dns.rdata
    import dns.rdataclass

    latest = 0
    for item in body["rrsets"]:
        if item["type"] != "RRSIG":
            continue
        for text in item["rrdatas"]:
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, text)
            latest = max(latest, int(rdata.expiration))
    return latest


def test_ds_withdraw_grace_then_restore_then_drop(env):
    assert post(env, env.lab.zone()).status_code == 201
    server = DnsServer(env.settings, env.store)
    server.start()
    maintenance = Maintenance(env.settings, env.store, lookup=env.lab, notifier=env.notifier)
    try:
        env.lab.publish(ds="missing")
        denied = post(env, env.lab.zone(serial=env.clock.t + 1))
        assert denied.status_code == 403
        assert denied.get_json()["error"] == "parent_ds_missing"
        assert _records(_xfr(env.settings.dns_port, "user.example."))
        maintenance.run_once()
        assert env.store.get_zone("user.example.").parent_drift_since == env.clock.t
        assert _records(_xfr(env.settings.dns_port, "user.example."))

        env.clock.t += env.settings.negative_cache_ttl_seconds + 5
        env.lab.publish()
        restored = post(env, env.lab.zone(serial=env.clock.t))
        assert restored.status_code == 200, restored.get_json()
        assert restored.get_json()["catalogUpdated"] is False

        env.lab.publish(ds="missing")
        env.clock.t += 1
        maintenance.run_once()
        drift = env.store.get_zone("user.example.").parent_drift_since
        env.clock.t = drift + env.settings.grace_seconds + 10
        maintenance.run_once()
        assert env.store.get_zone("user.example.") is None
        catalog = _records(_xfr(env.settings.dns_port, "catalog.svc.test."))
        assert not any(text == "user.example." for _name, rdtype, text in catalog if rdtype == "PTR")
    finally:
        server.stop()
