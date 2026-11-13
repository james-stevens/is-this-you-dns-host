"""Spec rules that the original suite did not cover."""

import json

import dns.name
import pytest

from dns_host.config import Secondary, Settings
from dns_host.dns_server import DnsServer
from dns_host.nsdconf import render_nsd
from dns_host.zonesign import generate_key
from tests.conftest import post
from tests.test_axfr_grace import _records, _xfr


def test_default_resolver_and_ports():
    settings = Settings()
    assert settings.resolver_base_url == "https://api.isthisyou.org/"
    assert settings.dns_bind == "127.0.0.1"
    assert settings.dns_port == 5353
    assert settings.nsd_port == 53
    assert settings.http_port == 80
    assert "web3dns.net" not in settings.resolver_base_url


def test_missing_config_refuses_without_service_ns(tmp_path):
    settings = Settings.load(tmp_path / "absent.yaml")
    assert settings.resolver_base_url == "https://api.isthisyou.org/"
    assert settings.service_ns == []
    with pytest.raises(SystemExit):
        settings.require_service_ns()


def test_algorithm_15_is_accepted(env):
    env.lab.child_ksk_priv, env.lab.child_ksk = generate_key(257, 15)
    env.lab.child_zsk_priv, env.lab.child_zsk = generate_key(256, 15)
    env.lab.publish()
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()


@pytest.mark.parametrize(
    ("rdtype", "rdata"),
    [
        ("HINFO", '"CPU" "OS"'),
        ("NULL", "\\# 0"),
        ("MD", "mail.example."),
        ("MF", "mail.example."),
        ("MB", "mail.example."),
        ("TYPE65280", "\\# 1 AA"),
    ],
)
def test_obsolete_and_private_types_are_rejected_before_signatures(env, rdtype, rdata):
    body = env.lab.zone()
    body["rrsets"].append(
        {
            "kind": "dns#resourceRecordSet",
            "name": "user.example.",
            "type": rdtype,
            "ttl": 300,
            "rrdatas": [rdata],
        }
    )
    response = post(env, body)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "type_not_allowed"
    assert env.lab.calls == []


def test_uri_and_wallet_are_apex_only(env):
    apex = env.lab.apex.to_text()
    uri = env.lab.zone(
        extras=[(f"_web._tcp.{apex}", "URI", ['10 1 "https://example.org/j"'])]
    )
    response = post(env, uri)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "type_not_allowed"
    assert env.lab.calls == []

    wallet = env.lab.zone(
        serial=env.clock.t + 1,
        extras=[(f"www.{apex}", "WALLET", ['"btc" "bc1qexampleaddress"'])],
    )
    response = post(env, wallet)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "type_not_allowed"
    assert env.lab.calls == []


def test_provide_xfr_and_notify_come_from_one_secondary_list():
    settings = Settings(
        secondaries=[
            Secondary("192.0.2.10", 53, tsig_key_name="one.example.", tsig_secret="c2VjcmV0MQ=="),
            Secondary("192.0.2.11", 5353),
        ],
        dns_port=5353,
        nsd_port=53,
        catalog_zone=dns.name.from_text("catalog.example.net."),
    )
    upload = {"tsig_secret": "from-the-zone-json", "secondaries": ["198.51.100.9"]}
    text = render_nsd(settings, ["catalog.example.net.", "user.example."])
    assert upload["tsig_secret"] not in text
    assert "198.51.100.9" not in text
    assert "request-xfr: 127.0.0.1@5353 NOKEY" in text
    provide = [
        line.split("provide-xfr:", 1)[1].strip()
        for line in text.splitlines()
        if line.strip().startswith("provide-xfr:")
    ]
    notify = [
        line.split("notify:", 1)[1].strip()
        for line in text.splitlines()
        if line.strip().startswith("notify:")
    ]
    assert provide == notify == ["192.0.2.10 one.example.", "192.0.2.11@5353 NOKEY"]
    assert text.count("provide-xfr:") == len(settings.secondaries)
    assert "c2VjcmV0MQ==" in text


def test_internal_drop_updates_the_catalogue(env):
    assert post(env, env.lab.zone()).status_code == 201
    env.notifier.zones.clear()
    response = env.client.post(
        "/int/zones/drop",
        json={"apexes": ["user.example."], "reason": "test"},
    )
    assert response.status_code == 200, response.get_json()
    assert env.store.get_zone("user.example.") is None
    assert env.notifier.zones == ["catalog.svc.test."]
    catalogue = json.loads((env.settings.data_dir / "zones" / "catalogue.json").read_text())
    assert catalogue["zones"] == []


def test_dns_serves_the_catalogue_file(env):
    assert post(env, env.lab.zone()).status_code == 201
    server = DnsServer(env.settings, env.store)
    server.start()
    try:
        assert any(rdtype == "SOA" for _name, rdtype, _text in _records(_xfr(server.port, "user.example.")))
        path = env.settings.data_dir / "zones" / "catalogue.json"
        data = json.loads(path.read_text())
        data["zones"] = []
        data["catalog_serial"] = int(data["catalog_serial"]) + 1
        path.write_text(json.dumps(data))
        catalog = _records(_xfr(server.port, "catalog.svc.test."))
        assert not any(rdtype == "PTR" for _name, rdtype, _text in catalog)
    finally:
        server.stop()
