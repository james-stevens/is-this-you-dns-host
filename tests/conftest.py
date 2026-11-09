"""Shared fixtures: a clock, a signed parent chain, and a Flask client."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from dns_host.app import create_app
from dns_host.config import Settings
from dns_host.names import normalise_name
from dns_host.notify import RecordingNotifier
from dns_host.storage import Store
from tests.support import Lab


class Clock:
    def __init__(self, start: int | None = None):
        self.t = int(start if start is not None else time.time())

    def __call__(self) -> int:
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def lab(clock):
    return Lab(clock.t)


@pytest.fixture
def settings(tmp_path: Path, clock, lab):
    return Settings(
        service_ns=list(lab.service_ns),
        secondaries=[("127.0.0.1", 9)],
        resolver_base_url="https://resolver.test/",
        catalog_zone=normalise_name("catalog.svc.test."),
        catalog_rname=normalise_name("hostmaster.svc.test."),
        data_dir=tmp_path,
        dns_port=0,
        trust_anchors=[lab.root_ds],
        type_allowlist=frozenset(
            item.strip().upper()
            for item in (
                "SOA,NS,A,AAAA,DNSKEY,RRSIG,NSEC3,NSEC3PARAM,NSEC,TXT,URI,CNAME,MX,SRV,"
                "TLSA,CAA,PTR,OPENPGPKEY,SVCB,HTTPS,SMIMEA,HINFO,NAPTR,SPF"
            ).split(",")
        ),
        health_check_dns=False,
        now_fn=clock,
        rate_limit_requests=100,
        parent_query_budget=100,
    )


@pytest.fixture
def env(tmp_path, clock, lab, settings):
    store = Store(tmp_path / "host.db")
    store.ensure_catalog(clock.t)
    notifier = RecordingNotifier()
    app = create_app(settings, lookup=lab, store=store, notifier=notifier)
    return type(
        "Env",
        (),
        {
            "clock": clock,
            "lab": lab,
            "settings": settings,
            "store": store,
            "notifier": notifier,
            "client": app.test_client(),
        },
    )()


def post(env, body, apex=None, ip="203.0.113.10", raw=None, content_type="application/json"):
    if apex is None:
        apex = str(body.get("apex", "user.example.")).rstrip(".")
    data = raw if raw is not None else __import__("json").dumps(body).encode()
    return env.client.post(
        f"/v1/zones/{apex}",
        data=data,
        headers={"Content-Type": content_type, "X-Real-IP": ip},
    )
