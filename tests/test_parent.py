"""Parent DS/NS results and the hosting-side negative cache."""

from tests.conftest import post


def test_parent_ds_missing_is_cached(env):
    env.lab.publish(ds="missing")
    first = post(env, env.lab.zone())
    assert first.status_code == 403, first.get_json()
    assert first.get_json()["error"] == "parent_ds_missing"
    calls = len(env.lab.calls)
    assert calls > 0
    second = post(env, env.lab.zone(serial=env.clock.t + 1))
    assert second.status_code == 403
    assert second.get_json()["error"] == "parent_ds_missing"
    assert len(env.lab.calls) == calls


def test_parent_ds_mismatch(env):
    env.lab.publish(ds="mismatch")
    response = post(env, env.lab.zone())
    assert response.status_code == 403, response.get_json()
    assert response.get_json()["error"] == "parent_ds_mismatch"
    assert env.lab.calls


def test_parent_ns_incomplete(env):
    env.lab.publish(ns="incomplete")
    response = post(env, env.lab.zone())
    assert response.status_code == 403, response.get_json()
    assert response.get_json()["error"] == "parent_ns_incomplete"


def test_ns_set_mismatch(env):
    env.lab.publish(ns="extra")
    response = post(env, env.lab.zone())
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "ns_set_mismatch"


def test_bad_signature_runs_after_parent_and_ds(env):
    response = post(env, env.lab.zone(tamper=f"_auth.7e9a2f4c8b1d.{env.lab.apex.to_text()}"))
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "zone_validation_failed"
    assert any(call["type"] == "DS" and call["server"] for call in env.lab.calls)
