import json

from tests.conftest import post


def test_valid_zone_is_admitted_and_catalog_is_notified_first(env):
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["apex"] == "user.example."
    assert body["catalogUpdated"] is True
    assert body["serial"] == env.clock.t
    assert "nextExpireHint" in body
    assert env.notifier.zones == ["catalog.svc.test.", "user.example."]
    assert env.lab.calls, "parent lookup should run for a valid zone"
    assert any(call["server"] for call in env.lab.calls)
    assert all(call["rd"] == 0 and call["do"] == 1 for call in env.lab.calls)

    env.notifier.zones.clear()
    before = len(env.lab.calls)
    again = post(env, env.lab.zone(serial=env.clock.t + 10))
    assert again.status_code == 200, again.get_json()
    assert again.get_json()["catalogUpdated"] is False
    assert env.notifier.zones == ["user.example."]
    assert len(env.lab.calls) > before


def test_nsec_zone_is_accepted_for_experiments(env):
    response = post(env, env.lab.zone(nsec3=False, serial=env.clock.t + 3))
    assert response.status_code == 201, response.get_json()


def test_health_and_metrics(env):
    health = env.client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["dns"] == "skipped"
    assert health.get_json()["catalogZone"] == "catalog.svc.test."
    metrics = env.client.get("/metrics")
    assert metrics.status_code == 200
    assert "uploads_ok" in metrics.get_json()
