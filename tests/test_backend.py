import pytest
from fastapi.testclient import TestClient

from src.backend.main import app
from src.backend.network_engine import get_network_engine

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "model_name" in data


def test_model_info_endpoint():
    res = client.get("/api/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "best_model_name" in data
    assert "evaluation_metrics" in data
    assert data["evaluation_metrics"]["accuracy"] >= 0.95


def test_predict_endpoint_valid_url():
    res = client.post("/api/predict", json={"url": "https://www.google.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] in ["legitimate", "phishing"]
    assert "risk_score" in data
    assert "indicators" in data
    assert "is_firewall_blocked" in data
    assert "safety_report" in data
    assert "headline" in data["safety_report"]
    assert "observations" in data["safety_report"]
    assert "recommendation" in data["safety_report"]


def test_predict_endpoint_empty_and_invalid():
    res_empty = client.post("/api/predict", json={"url": ""})
    assert res_empty.status_code == 422

    res_missing = client.post("/api/predict", json={})
    assert res_missing.status_code == 422


def test_predict_endpoint_excessive_length():
    huge_url = "https://example.com/" + "a" * 3000
    res = client.post("/api/predict", json={"url": huge_url})
    assert res.status_code == 422


def test_dns_lookup_endpoint():
    res = client.get("/api/network/dns?domain=example.com")
    assert res.status_code == 200
    data = res.json()
    assert "hostname" in data
    assert "status" in data
    assert "lookup_duration_ms" in data
    assert data["lookup_duration_ms"] >= 0


def test_dns_lookup_empty_domain():
    res = client.get("/api/network/dns?domain=")
    assert res.status_code == 400


def test_simulated_firewall_lifecycle():
    engine = get_network_engine()

    rule_data = {"domain": "quarantine-phish-test.xyz", "reason": "Automated test block"}
    res_create = client.post("/api/firewall/rules", json=rule_data)
    assert res_create.status_code == 200
    rule = res_create.json()
    rule_id = rule["id"]
    assert rule["domain"] == "quarantine-phish-test.xyz"

    res_list = client.get("/api/firewall/rules")
    assert res_list.status_code == 200
    rules = res_list.json()
    assert any(r["id"] == rule_id for r in rules)

    res_pred = client.post("/api/predict", json={"url": "http://quarantine-phish-test.xyz/login"})
    assert res_pred.status_code == 200
    pred_data = res_pred.json()
    assert pred_data["is_firewall_blocked"] is True

    res_del = client.delete(f"/api/firewall/rules/{rule_id}")
    assert res_del.status_code == 200
    assert res_del.json()["success"] is True

    res_del_404 = client.delete("/api/firewall/rules/NONEXISTENT_RULE")
    assert res_del_404.status_code == 404


def test_network_stats_endpoint():
    res = client.get("/api/network/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_requests" in data
    assert "avg_latency_ms" in data
    assert data["total_requests"] > 0


def test_events_endpoint():
    res = client.get("/api/events?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    if len(data) > 0:
        event = data[0]
        assert "id" in event
        assert "type" in event
        assert "severity" in event
        assert "message" in event


def test_events_expiration_and_clear():
    engine = get_network_engine()
    engine.log_event("SYSTEM", "INFO", "Fresh event for expiration test")
    assert len(engine.events) > 0

    old_event = {
        "id": "old-test",
        "timestamp": "2020-01-01T00:00:00+00:00",
        "created_at_ts": 1000.0,
        "type": "SYSTEM",
        "severity": "INFO",
        "message": "Ancient event that should be purged",
        "details": {}
    }
    engine.events.append(old_event)
    assert any(e["id"] == "old-test" for e in engine.events)

    engine.clean_expired_events()
    assert not any(e["id"] == "old-test" for e in engine.events)

    res_del = client.delete("/api/events")
    assert res_del.status_code == 200
    assert res_del.json()["success"] is True

    res_empty = client.get("/api/events")
    assert res_empty.status_code == 200
    assert len(res_empty.json()) == 0
