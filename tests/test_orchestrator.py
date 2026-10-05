"""
tests/test_orchestrator.py
--------------------------
Unit tests for the multi-agent pipeline Orchestrator (Phase 3 Member 2).

Tests:
  1. Default registration — verifies all available agents are loaded
  2. Health check — verifies health polling across registered stages
  3. Synchronous pipeline — verifies full pipeline execution on NormalizedEvent
  4. Asynchronous pipeline — verifies non-blocking async execution
  5. Progressive enrichment — verifies event mutation (severity, incident_id, mitre, threat intel)
  6. Latency tracking — verifies total_latency_ms is computed
  7. Storage persistence — verifies analyzed events are saved into AlertStore

Author  : Member 2 — Phase 3
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from agents.orchestrator import Orchestrator, get_orchestrator
from api.models import (
    AnalyzeResponse,
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
)
from database.store import get_store


def make_test_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        src_ip="185.220.101.5",
        dst_ip="192.168.1.10",
        dst_port=22,
        protocol="TCP",
        threat_category=ThreatCategory.BRUTE_FORCE,
        label="SSH-Patator",
        flow_duration=1500000.0,
        total_fwd_packets=450,
        total_bwd_packets=12,
    )


class TestOrchestratorInitialization:
    def test_default_registration(self):
        orch = Orchestrator(auto_register_defaults=True)
        assert orch._agents["triage"] is not None
        assert orch._agents["correlation"] is not None
        assert orch._agents["mitre"] is not None
        assert orch._agents["enrichment"] is not None

    def test_health_check_polls_all_stages(self):
        orch = Orchestrator(auto_register_defaults=True)
        health = orch.health_check()
        assert len(health) >= 4
        stages = [h["stage"] for h in health]
        assert "triage" in stages
        assert "correlation" in stages
        assert "mitre" in stages
        assert "enrichment" in stages


class TestPipelineExecution:
    def test_run_pipeline_sync(self):
        orch = Orchestrator(auto_register_defaults=True)
        event = make_test_event()

        response: AnalyzeResponse = orch.run_pipeline(event)

        assert response.event_id == event.event_id
        assert response.pipeline_run_id is not None
        assert response.total_latency_ms is not None
        assert response.total_latency_ms > 0

        # Stage results
        assert response.triage is not None
        assert response.correlation is not None
        assert response.mitre is not None
        assert response.enrichment is not None

        # Verify progressive enrichment on the event
        assert event.severity != SeverityLevel.UNKNOWN
        assert event.incident_id is not None
        assert isinstance(event.mitre_techniques, list)
        assert event.enrichment_data is not None

    @pytest.mark.asyncio
    async def test_run_pipeline_async(self):
        orch = Orchestrator(auto_register_defaults=True)
        event = make_test_event()

        response: AnalyzeResponse = await orch.run_pipeline_async(event)

        assert response.event_id == event.event_id
        assert response.triage is not None
        assert response.enrichment is not None
        assert event.incident_id is not None

    def test_pipeline_persists_to_store(self):
        orch = Orchestrator(auto_register_defaults=True)
        event = make_test_event()
        event_id = event.event_id

        orch.run_pipeline(event)

        store = get_store()
        saved = store.get_alert(event_id)
        assert saved is not None
        assert saved.event_id == event_id
        assert saved.severity == event.severity

    def test_custom_stage_skipping(self):
        orch = Orchestrator(auto_register_defaults=False)
        event = make_test_event()

        response = orch.run_pipeline(event)
        assert response.triage is None
        assert response.correlation is None
        assert response.mitre is None
        assert response.enrichment is None
