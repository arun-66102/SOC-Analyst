"""
tests/test_correlation.py
--------------------------
Unit tests for the Correlation Agent (Phase 2).

Tests:
  1. Incident ID generation — deterministic hashing from src_ip + category
  2. Time-window matching — events from same IP within window get same incident
  3. New incident creation — first event of a type creates a new incident
  4. Event registration — in-memory store updated correctly
  5. Text-to-embedding conversion — verifies event_to_text output
  6. AgentResult structure — mocked async pipeline
  7. Multi-event correlation scenario — 3 events from same IP

Author  : Member 2 — Phase 2
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.correlation_agent import CorrelationAgent, _incidents, _event_embeddings
from api.models import AgentResult, CorrelationOutput, NormalizedEvent, ThreatCategory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    src_ip: str = "10.0.0.1",
    threat_category: str = "BruteForce",
    label: str = "SSH-Patator",
    protocol: str = "TCP",
    dst_port: int = 22,
    offset_seconds: int = 0,
) -> NormalizedEvent:
    """Create a NormalizedEvent at a fixed timestamp + offset."""
    ts = datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=ts,
        src_ip=src_ip,
        dst_port=dst_port,
        protocol=protocol,
        threat_category=threat_category,
        label=label,
        source_dataset="synthetic",
    )


@pytest.fixture(autouse=True)
def clear_incident_store():
    """Clear the in-memory incident store before each test."""
    _incidents.clear()
    _event_embeddings.clear()
    yield
    _incidents.clear()
    _event_embeddings.clear()


# ---------------------------------------------------------------------------
# 1. Incident ID generation
# ---------------------------------------------------------------------------

class TestIncidentIDGeneration:

    def test_deterministic_from_same_ip_and_category(self):
        """Same src_ip + threat_category must always produce the same incident ID."""
        event = make_event(src_ip="192.168.1.1", threat_category="DDoS")
        id1 = CorrelationAgent._make_incident_id(event)
        id2 = CorrelationAgent._make_incident_id(event)
        assert id1 == id2

    def test_different_ips_produce_different_ids(self):
        """Different source IPs should produce different incident IDs."""
        e1 = make_event(src_ip="10.0.0.1")
        e2 = make_event(src_ip="10.0.0.2")
        assert CorrelationAgent._make_incident_id(e1) != CorrelationAgent._make_incident_id(e2)

    def test_incident_id_format(self):
        """Incident IDs must follow the INC-XXXXXXXX format."""
        event = make_event()
        inc_id = CorrelationAgent._make_incident_id(event)
        assert inc_id.startswith("INC-")
        assert len(inc_id) == 12  # "INC-" + 8 hex chars

    def test_none_src_ip_uses_event_id(self):
        """If src_ip is None, incident ID should still be generated without error."""
        event = make_event()
        event.src_ip = None
        inc_id = CorrelationAgent._make_incident_id(event)
        assert inc_id.startswith("INC-")


# ---------------------------------------------------------------------------
# 2. Time-window matching
# ---------------------------------------------------------------------------

class TestTimeWindowMatching:

    def test_same_ip_within_window_matches(self):
        """Two events from the same IP within 300s should get the same incident."""
        agent = CorrelationAgent(window_seconds=300)

        event1 = make_event(src_ip="10.0.0.5", offset_seconds=0)
        event2 = make_event(src_ip="10.0.0.5", offset_seconds=120)  # 2 min later

        # Register event1 manually
        inc_id1 = agent._make_incident_id(event1)
        agent._register_event(event1, inc_id1, None)

        # Search for event2
        found_id, related, sim = agent._find_incident_by_window(event2)
        assert found_id == inc_id1
        assert event1.event_id in related

    def test_same_ip_outside_window_no_match(self):
        """Event outside the time window should not match."""
        agent = CorrelationAgent(window_seconds=60)  # 1-minute window

        event1 = make_event(src_ip="10.0.0.5", offset_seconds=0)
        event2 = make_event(src_ip="10.0.0.5", offset_seconds=120)  # 2 min later

        inc_id1 = agent._make_incident_id(event1)
        agent._register_event(event1, inc_id1, None)

        found_id, related, sim = agent._find_incident_by_window(event2)
        assert found_id is None

    def test_different_ip_no_match(self):
        """Events from different IPs should not share an incident via window search."""
        agent = CorrelationAgent(window_seconds=300)

        event1 = make_event(src_ip="10.0.0.1", offset_seconds=0)
        event2 = make_event(src_ip="10.0.0.2", offset_seconds=10)

        inc_id1 = agent._make_incident_id(event1)
        agent._register_event(event1, inc_id1, None)

        found_id, related, sim = agent._find_incident_by_window(event2)
        assert found_id is None

    def test_none_src_ip_returns_no_match(self):
        """Events with no src_ip should return no match (cannot window-match)."""
        agent = CorrelationAgent()
        event = make_event()
        event.src_ip = None
        found_id, related, sim = agent._find_incident_by_window(event)
        assert found_id is None


# ---------------------------------------------------------------------------
# 3. New incident creation
# ---------------------------------------------------------------------------

class TestNewIncidentCreation:

    def test_first_event_creates_new_incident(self):
        """First event should create a new incident in the store."""
        agent = CorrelationAgent()
        event = make_event()
        inc_id = agent._make_incident_id(event)
        agent._register_event(event, inc_id, None)

        assert inc_id in _incidents
        assert event.event_id in _incidents[inc_id]["event_ids"]

    def test_second_event_same_ip_appends_to_incident(self):
        """Second event from the same IP is appended to the existing incident."""
        agent = CorrelationAgent()
        event1 = make_event(src_ip="192.168.0.1")
        event2 = make_event(src_ip="192.168.0.1")

        inc_id = agent._make_incident_id(event1)
        agent._register_event(event1, inc_id, None)
        agent._register_event(event2, inc_id, None)

        assert len(_incidents[inc_id]["event_ids"]) == 2


# ---------------------------------------------------------------------------
# 4. Event text conversion
# ---------------------------------------------------------------------------

class TestEventToText:

    def test_text_contains_category(self):
        event = make_event(threat_category="DDoS", label="DDoS")
        text = CorrelationAgent._event_to_text(event)
        assert "DDoS" in text

    def test_text_contains_protocol(self):
        event = make_event(protocol="UDP")
        text = CorrelationAgent._event_to_text(event)
        assert "UDP" in text

    def test_text_contains_port(self):
        event = make_event(dst_port=22)
        text = CorrelationAgent._event_to_text(event)
        assert "22" in text

    def test_text_is_non_empty(self):
        event = make_event()
        text = CorrelationAgent._event_to_text(event)
        assert len(text) > 5


# ---------------------------------------------------------------------------
# 5. AgentResult structure (mocked LLM)
# ---------------------------------------------------------------------------

class TestAgentResultStructure:

    @pytest.mark.asyncio
    async def test_process_async_returns_agent_result(self):
        """process_async() should return a valid AgentResult."""
        agent = CorrelationAgent()

        # Mock the LLM summary call
        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(return_value=MagicMock(
            text="Brute force incident detected from 10.0.0.1 on port 22.",
            input_tokens=50,
            output_tokens=30,
        ))
        agent._llm = mock_llm

        event = make_event()
        result = await agent.process_async(event)

        assert isinstance(result, AgentResult)
        assert result.status == "success"
        assert result.event_id == event.event_id
        assert "incident_id" in result.output
        assert "related_event_ids" in result.output
        assert "incident_summary" in result.output

    @pytest.mark.asyncio
    async def test_process_async_llm_failure_returns_fallback_summary(self):
        """LLM summary failure should not crash — fallback summary used."""
        agent = CorrelationAgent()

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(side_effect=Exception("LLM timeout"))
        agent._llm = mock_llm

        event = make_event()
        result = await agent.process_async(event)

        assert result.status == "success"
        assert "incident_summary" in result.output
        assert result.output["incident_summary"] is not None


# ---------------------------------------------------------------------------
# 6. Multi-event correlation scenario
# ---------------------------------------------------------------------------

class TestMultiEventCorrelation:
    """Simulate a brute-force attack: 3 events from the same IP within 5 minutes."""

    @pytest.mark.asyncio
    async def test_three_events_same_ip_same_incident(self):
        agent = CorrelationAgent(window_seconds=300)

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(return_value=MagicMock(
            text="Sustained brute force from 10.0.5.5.",
            input_tokens=40, output_tokens=20,
        ))
        agent._llm = mock_llm

        events = [
            make_event(src_ip="10.0.5.5", offset_seconds=i * 60)
            for i in range(3)
        ]

        results = []
        for event in events:
            result = await agent.process_async(event)
            results.append(result)

        # All events should be in the same incident
        incident_ids = {r.output["incident_id"] for r in results}
        assert len(incident_ids) == 1, "All 3 events should be in the same incident"

    @pytest.mark.asyncio
    async def test_events_from_different_ips_different_incidents(self):
        agent = CorrelationAgent(window_seconds=300)

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(return_value=MagicMock(
            text="Incident summary.",
            input_tokens=30, output_tokens=15,
        ))
        agent._llm = mock_llm

        events = [
            make_event(src_ip=f"10.0.0.{i}", offset_seconds=0)
            for i in range(3)
        ]

        results = []
        for event in events:
            result = await agent.process_async(event)
            results.append(result)

        incident_ids = {r.output["incident_id"] for r in results}
        assert len(incident_ids) == 3, "Each different IP should create its own incident"
