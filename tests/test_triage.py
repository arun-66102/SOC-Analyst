"""
tests/test_triage.py
---------------------
Unit tests for the Triage Agent (Phase 2).

Tests:
  1. Heuristic fallback — verifies correct severity for 5 labeled event types
     without requiring a live GROQ_API_KEY.
  2. Prompt builder — verifies the prompt contains the correct event fields.
  3. Response parser — verifies valid and malformed JSON handling.
  4. AgentResult structure — verifies all required fields are present.
  5. Health check — verifies dependency reporting.

Author  : Member 1 — Phase 2
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.triage_agent import TriageAgent
from agents.prompts.triage_prompts import build_triage_prompt, TRIAGE_SYSTEM_PROMPT
from api.models import (
    AgentResult,
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
    TriageOutput,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    threat_category: str = "DDoS",
    label: str = "DDoS",
    src_ip: str = "203.0.113.10",
    dst_port: int = 80,
    flow_bytes_per_sec: float = 2_500_000.0,
    flow_packets_per_sec: float = 45_000.0,
    total_fwd_packets: int = 12_000,
    total_bwd_packets: int = 50,
) -> NormalizedEvent:
    """Create a minimal NormalizedEvent for testing."""
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        dst_port=dst_port,
        protocol="TCP",
        threat_category=threat_category,
        label=label,
        flow_bytes_per_sec=flow_bytes_per_sec,
        flow_packets_per_sec=flow_packets_per_sec,
        total_fwd_packets=total_fwd_packets,
        total_bwd_packets=total_bwd_packets,
        source_dataset="synthetic",
    )


# ---------------------------------------------------------------------------
# 1. Heuristic fallback tests (no LLM needed)
# ---------------------------------------------------------------------------

class TestHeuristicFallback:
    """Verify the rule-based fallback produces correct severity for known categories."""

    @pytest.fixture(autouse=True)
    def agent(self):
        return TriageAgent()

    LABELED_CASES = [
        # (threat_category, label, expected_severity, expected_is_tp)
        ("DDoS",           "DDoS",        SeverityLevel.CRITICAL, True),
        ("BruteForce",     "SSH-Patator",  SeverityLevel.HIGH,     True),
        ("PortScan",       "PortScan",     SeverityLevel.HIGH,     True),
        ("DoS",            "DoS slowloris",SeverityLevel.MEDIUM,   True),
        ("Benign",         "BENIGN",       SeverityLevel.LOW,      False),
    ]

    @pytest.mark.parametrize("category,label,exp_sev,exp_tp", LABELED_CASES)
    def test_heuristic_severity(self, agent, category, label, exp_sev, exp_tp):
        """Heuristic fallback should return correct severity and TP verdict."""
        event = make_event(threat_category=category, label=label)
        result: TriageOutput = agent._heuristic_fallback(event)

        assert result.severity == exp_sev.value, (
            f"Expected severity {exp_sev} for {category}, got {result.severity}"
        )
        assert result.is_true_positive == exp_tp

    def test_heuristic_confidence_range(self, agent):
        """Heuristic confidence should always be in [0, 1]."""
        for category, label, _, _ in self.LABELED_CASES:
            event = make_event(threat_category=category, label=label)
            result = agent._heuristic_fallback(event)
            assert 0.0 <= result.confidence <= 1.0

    def test_heuristic_reasoning_non_empty(self, agent):
        """Heuristic reasoning should never be empty."""
        event = make_event(threat_category="DDoS", label="DDoS")
        result = agent._heuristic_fallback(event)
        assert isinstance(result.reasoning, str)
        assert len(result.reasoning) > 10


# ---------------------------------------------------------------------------
# 2. Prompt builder tests
# ---------------------------------------------------------------------------

class TestPromptBuilder:

    def test_prompt_contains_event_id(self):
        event = make_event()
        prompt = build_triage_prompt(event)
        assert event.event_id in prompt

    def test_prompt_contains_threat_category(self):
        event = make_event(threat_category="BruteForce")
        prompt = build_triage_prompt(event)
        assert "BruteForce" in prompt

    def test_prompt_contains_src_ip(self):
        event = make_event(src_ip="10.0.0.99")
        prompt = build_triage_prompt(event)
        assert "10.0.0.99" in prompt

    def test_prompt_contains_few_shot_examples(self):
        event = make_event()
        prompt = build_triage_prompt(event)
        assert "EXAMPLE 1" in prompt
        assert "EXAMPLE 5" in prompt

    def test_system_prompt_non_empty(self):
        assert len(TRIAGE_SYSTEM_PROMPT) > 100
        assert "SOC" in TRIAGE_SYSTEM_PROMPT
        assert "JSON" in TRIAGE_SYSTEM_PROMPT

    def test_prompt_with_enrichment_data(self):
        event = make_event()
        event.enrichment_data = {"is_malicious": True, "source": "VirusTotal"}
        prompt = build_triage_prompt(event)
        assert "Threat Intel Enrichment" in prompt


# ---------------------------------------------------------------------------
# 3. Response parser tests
# ---------------------------------------------------------------------------

class TestResponseParser:

    @pytest.fixture(autouse=True)
    def agent(self):
        return TriageAgent()

    def test_parse_valid_json(self, agent):
        """Well-formed JSON response should parse cleanly."""
        event = make_event()
        raw = json.dumps({
            "severity": "Critical",
            "is_true_positive": True,
            "confidence": 0.95,
            "reasoning": "DDoS confirmed by high packet rate.",
            "recommended_action": "Block IP at firewall.",
        })
        result = agent._parse_response(raw, event)
        assert result.severity == SeverityLevel.CRITICAL.value
        assert result.is_true_positive is True
        assert result.confidence == 0.95

    def test_parse_json_in_markdown_fence(self, agent):
        """JSON wrapped in ```json ... ``` should be extracted correctly."""
        event = make_event()
        raw = '```json\n{"severity":"High","is_true_positive":true,"confidence":0.8,"reasoning":"Brute force.","recommended_action":"Block."}\n```'
        result = agent._parse_response(raw, event)
        assert result.severity == SeverityLevel.HIGH.value

    def test_parse_lowercase_severity(self, agent):
        """Lowercase severity (e.g. 'critical') should be normalised."""
        event = make_event()
        raw = json.dumps({
            "severity": "critical",
            "is_true_positive": True,
            "confidence": 0.9,
            "reasoning": "Critical threat.",
            "recommended_action": "Isolate.",
        })
        result = agent._parse_response(raw, event)
        assert result.severity == SeverityLevel.CRITICAL.value

    def test_parse_malformed_json_uses_fallback(self, agent):
        """Malformed JSON should trigger heuristic fallback without raising."""
        event = make_event(threat_category="DDoS")
        result = agent._parse_response("not valid json at all", event)
        # Fallback should still return a valid TriageOutput
        assert result.severity in [s.value for s in SeverityLevel]
        assert isinstance(result.is_true_positive, bool)

    def test_parse_missing_fields_handled(self, agent):
        """Partial JSON should not raise — missing fields use defaults."""
        event = make_event()
        raw = json.dumps({"severity": "Low"})
        result = agent._parse_response(raw, event)
        assert result.severity == SeverityLevel.LOW.value
        assert isinstance(result.is_true_positive, bool)
        assert 0.0 <= result.confidence <= 1.0


# ---------------------------------------------------------------------------
# 4. AgentResult structure tests (mocked LLM)
# ---------------------------------------------------------------------------

class TestAgentResultStructure:
    """Test the full process() output structure using a mocked LLM."""

    @pytest.mark.asyncio
    async def test_process_async_returns_agent_result(self):
        """process_async() should return a valid AgentResult."""
        agent = TriageAgent()
        event = make_event(threat_category="BruteForce", label="SSH-Patator")

        # Mock the LLM client so no real API call is made
        mock_response = MagicMock()
        mock_response.text = json.dumps({
            "severity": "High",
            "is_true_positive": True,
            "confidence": 0.88,
            "reasoning": "SSH brute force detected.",
            "recommended_action": "Block source IP.",
        })
        mock_response.input_tokens = 100
        mock_response.output_tokens = 50

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(return_value=mock_response)
        agent._llm = mock_llm

        result = await agent.process_async(event)

        assert isinstance(result, AgentResult)
        assert result.status == "success"
        assert result.event_id == event.event_id
        assert result.output is not None
        assert "severity" in result.output
        assert "is_true_positive" in result.output
        assert "confidence" in result.output
        assert "reasoning" in result.output

    @pytest.mark.asyncio
    async def test_process_async_llm_failure_uses_fallback(self):
        """If LLM raises, process should still succeed via heuristic fallback."""
        agent = TriageAgent()
        event = make_event(threat_category="DDoS")

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(side_effect=Exception("LLM API error"))
        agent._llm = mock_llm

        result = await agent.process_async(event)
        # Fallback returns result via _parse_response which calls _heuristic_fallback
        assert result.status == "success"
        assert result.output["severity"] == SeverityLevel.CRITICAL.value


# ---------------------------------------------------------------------------
# 5. Health check test
# ---------------------------------------------------------------------------

class TestHealthCheck:

    def test_health_check_structure(self):
        agent = TriageAgent()
        health = agent.health_check()
        assert "agent" in health
        assert "healthy" in health
        assert "version" in health
        assert health["agent"] == "TriageAgent"

    def test_health_check_with_api_key(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "test-key-123")
        agent = TriageAgent()
        health = agent.health_check()
        assert health["groq_key_set"] is True

    def test_health_check_without_api_key(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        agent = TriageAgent()
        health = agent.health_check()
        assert health["groq_key_set"] is False
        assert health["healthy"] is False
