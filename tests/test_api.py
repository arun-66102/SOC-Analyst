"""
tests/test_api.py
-----------------
Integration tests for the FastAPI REST backend endpoints (Phase 3 Member 2).

Endpoints tested:
  - GET  /health
  - POST /api/analyze
  - GET  /api/alerts
  - GET  /api/alerts/{alert_id}
  - POST /api/alerts/{alert_id}/action
  - GET  /api/incidents
  - GET  /api/stats
  - GET  /api/reports/{incident_id}

Author  : Member 2 — Phase 3
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.main import app
from database.store import get_store


@pytest.fixture(scope="module")
def client():
    """Reusable TestClient instance."""
    with TestClient(app) as c:
        yield c


def make_payload():
    return {
        "event": {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": "185.220.101.5",
            "dst_ip": "192.168.1.10",
            "src_port": 54321,
            "dst_port": 22,
            "protocol": "TCP",
            "flow_duration": 1500000.0,
            "total_fwd_packets": 600,
            "total_bwd_packets": 15,
            "threat_category": "BruteForce",
            "label": "SSH-Patator",
            "source_dataset": "synthetic",
        }
    }


class TestHealthEndpoint:
    def test_health_check_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert isinstance(data["agents"], list)
        assert len(data["agents"]) >= 4


class TestAnalyzeEndpoint:
    def test_analyze_event_success(self, client):
        payload = make_payload()
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200

        data = resp.json()
        assert data["event_id"] == payload["event"]["event_id"]
        assert data["pipeline_run_id"] is not None
        assert data["total_latency_ms"] is not None

        # Verify stages are populated
        assert data["triage"] is not None
        assert data["correlation"] is not None
        assert data["mitre"] is not None
        assert data["enrichment"] is not None

    def test_analyze_event_invalid_schema(self, client):
        # Missing required event_id or timestamp
        resp = client.post("/api/analyze", json={"event": {"src_ip": "invalid"}})
        assert resp.status_code == 422


class TestAlertsEndpoints:
    def test_list_alerts_returns_records(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "alerts" in data
        assert data["total"] >= 1

    def test_filter_alerts_by_severity(self, client):
        resp = client.get("/api/alerts?severity=High")
        assert resp.status_code == 200
        data = resp.json()
        for alert in data["alerts"]:
            assert alert["severity"].lower() == "high"

    def test_get_single_alert(self, client):
        # Fetch list to pick an existing ID
        list_resp = client.get("/api/alerts")
        alerts = list_resp.json()["alerts"]
        assert len(alerts) > 0

        target_id = alerts[0]["event_id"]
        resp = client.get(f"/api/alerts/{target_id}")
        assert resp.status_code == 200
        assert resp.json()["event_id"] == target_id

    def test_get_nonexistent_alert_returns_404(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/alerts/{fake_id}")
        assert resp.status_code == 404

    def test_analyst_action_on_alert(self, client):
        list_resp = client.get("/api/alerts")
        target_id = list_resp.json()["alerts"][0]["event_id"]

        action_payload = {
            "action": "escalate",
            "comment": "Confirmed brute-force attack from external IP. Escalating to Tier 2.",
            "analyst_id": "analyst-dhany",
        }
        resp = client.post(f"/api/alerts/{target_id}/action", json=action_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert_id"] == target_id
        assert data["action"] == "escalate"
        assert data["new_alert_status"] == "escalated"

        # Verify state updated in GET
        alert_resp = client.get(f"/api/alerts/{target_id}")
        assert alert_resp.json()["status"] == "escalated"

    def test_analyst_action_on_nonexistent_alert(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.post(f"/api/alerts/{fake_id}/action", json={"action": "dismiss"})
        assert resp.status_code == 404


class TestIncidentsAndStatsEndpoints:
    def test_get_incidents(self, client):
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_dashboard_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert "total_alerts" in stats
        assert "critical_count" in stats
        assert "high_count" in stats
        assert "active_incidents" in stats
        assert stats["total_alerts"] >= 1


class TestReportsEndpoint:
    def test_get_report_for_existing_or_correlated_incident(self, client):
        # Trigger analyze to create a correlated incident
        payload = make_payload()
        analyze_resp = client.post("/api/analyze", json=payload)
        corr_out = analyze_resp.json()["correlation"]["output"]
        incident_id = corr_out["incident_id"]

        report_resp = client.get(f"/api/reports/{incident_id}")
        assert report_resp.status_code == 200
        report = report_resp.json()
        assert report["incident_id"] == incident_id
        assert "executive_summary" in report
        assert "technical_analysis" in report
        assert "indicators_of_compromise" in report
        assert "risk_score" in report

    def test_get_report_nonexistent_returns_404(self, client):
        resp = client.get("/api/reports/INC-DOES-NOT-EXIST-999")
        assert resp.status_code == 404
