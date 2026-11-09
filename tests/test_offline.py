"""Cheap checks reject before any parent lookup."""

from tests.conftest import post


def test_oversized_body_does_not_query_parent(env):
    env.settings.max_body_bytes = 64
    response = post(env, {}, raw=b'{"apex":"user.example.","rrsets":[]}' + b" " * 80)
    assert response.status_code == 413
    assert response.get_json()["error"] == "payload_too_large"
    assert env.lab.calls == []


def test_bad_json_does_not_query_parent(env):
    response = post(env, {}, raw=b"{")
    assert response.status_code == 400
    assert response.get_json()["error"] == "bad_request"
    assert env.lab.calls == []


def test_rate_limit_is_per_real_ip(env):
    env.settings.rate_limit_requests = 1
    first = post(env, {}, raw=b"{", ip="203.0.113.5")
    second = post(env, {}, raw=b"{", ip="203.0.113.5")
    other = post(env, {}, raw=b"{", ip="203.0.113.6")
    assert first.status_code == 400
    assert second.status_code == 429
    assert second.get_json()["error"] == "rate_limited"
    assert other.status_code == 400
    assert env.lab.calls == []


def test_apex_ns_incomplete_is_offline(env):
    body = env.lab.zone(ns_names=[env.lab.service_ns[0].to_text()])
    response = post(env, body)
    assert response.status_code == 422
    assert response.get_json()["error"] == "apex_ns_incomplete"
    assert env.lab.calls == []


def test_glue_missing_is_offline(env):
    extra = env.lab.service_ns[0].to_text()
    in_bailiwick = "ns3." + env.lab.apex.to_text()
    body = env.lab.zone(ns_names=[name.to_text() for name in env.lab.service_ns] + [in_bailiwick])
    response = post(env, body)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "glue_missing"
    assert env.lab.calls == []
    assert extra


def test_serial_window_and_replay(env):
    stale = post(env, env.lab.zone(serial=env.clock.t - 7200))
    assert stale.status_code == 422
    assert stale.get_json()["error"] == "serial_stale"
    future = post(env, env.lab.zone(serial=env.clock.t + 3600))
    assert future.status_code == 422
    assert future.get_json()["error"] == "serial_in_future"
    assert env.lab.calls == []
    ok = post(env, env.lab.zone())
    assert ok.status_code == 201, ok.get_json()
    calls = len(env.lab.calls)
    replay = post(env, env.lab.zone(serial=env.clock.t))
    assert replay.status_code == 409
    assert replay.get_json()["error"] == "serial_not_increased"
    assert len(env.lab.calls) == calls


def test_name_type_ttl_and_dnskey_failures(env):
    outside = env.lab.zone()
    outside["rrsets"].append(
        {
            "kind": "dns#resourceRecordSet",
            "name": "other.example.",
            "type": "TXT",
            "ttl": 300,
            "rrdatas": ['"nope"'],
        }
    )
    response = post(env, outside)
    assert response.status_code == 422
    assert response.get_json()["error"] == "name_out_of_bailiwick"

    wild = env.lab.zone()
    wild["rrsets"].append(
        {
            "kind": "dns#resourceRecordSet",
            "name": "*.user.example.",
            "type": "TXT",
            "ttl": 300,
            "rrdatas": ['"nope"'],
        }
    )
    response = post(env, wild)
    assert response.status_code == 422
    assert response.get_json()["error"] == "bad_label"

    duplicate = env.lab.zone()
    txt = next(item for item in duplicate["rrsets"] if item["type"] == "TXT")
    duplicate["rrsets"].append(dict(txt))
    response = post(env, duplicate)
    assert response.status_code == 422
    assert response.get_json()["error"] == "duplicate_rrset"

    ttl = env.lab.zone()
    ttl["rrsets"][0]["ttl"] = 1
    response = post(env, ttl)
    assert response.status_code == 422
    assert response.get_json()["error"] == "ttl_out_of_range"

    denied = env.lab.zone()
    denied["rrsets"].append(
        {
            "kind": "dns#resourceRecordSet",
            "name": "user.example.",
            "type": "NULL",
            "ttl": 300,
            "rrdatas": ["\\# 0"],
        }
    )
    response = post(env, denied)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "type_not_allowed"

    keys = env.lab.zone()
    for item in keys["rrsets"]:
        if item["type"] == "DNSKEY":
            item["rrdatas"] = [rdata.replace("257 ", "256 ", 1) for rdata in item["rrdatas"]]
    response = post(env, keys)
    assert response.status_code == 422
    assert response.get_json()["error"] == "bad_dnskey"
    assert env.lab.calls == []


def test_rrsig_and_nsec3_failures_are_offline(env):
    long_lived = env.lab.zone(expiration=env.clock.t + 40 * 86400)
    response = post(env, long_lived)
    assert response.status_code == 422
    assert response.get_json()["error"] == "rrsig_window"

    broken = env.lab.zone()
    broken["rrsets"] = [
        item
        for item in broken["rrsets"]
        if item["type"] != "NSEC3"
    ]
    for item in broken["rrsets"]:
        if item["type"] == "RRSIG":
            item["rrdatas"] = [rdata for rdata in item["rrdatas"] if not rdata.startswith("NSEC3 ")]
    broken["rrsets"] = [item for item in broken["rrsets"] if item["type"] != "RRSIG" or item["rrdatas"]]
    response = post(env, broken)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "nsec3_chain_broken"

    param = env.lab.zone()
    for item in param["rrsets"]:
        if item["type"] == "NSEC3PARAM":
            item["rrdatas"] = ["1 0 1 -"]
    response = post(env, param)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "bad_nsec3param"
    assert env.lab.calls == []


def test_rrset_cap_is_413(env):
    env.settings.max_rrsets = 2
    response = post(env, env.lab.zone())
    assert response.status_code == 413
    assert response.get_json()["error"] == "payload_too_large"
    assert env.lab.calls == []
