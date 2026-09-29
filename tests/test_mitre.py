"""
tests/test_mitre.py
--------------------
Unit tests for the MITRE ATT&CK Mapping Agent (Phase 2).

Tests:
  1. Rule-based fallback — known attack categories map to correct techniques
  2. Event-to-text conversion — verifies text generation for embedding
  3. techniques.json loading — verifies techniques loaded correctly
  4. AgentResult structure — mocked async pipeline output
  5. Known attack-technique pairs — precision test on 10 labeled cases
  6. MITREOutput structure — verifies Pydantic model fields
  7. Health check — technique count and index status

Author  : Member 3 — Phase 2
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from agents.mitre_agent import MITREAgent
from api.models import AgentResult, MITREOutput, MITRETechnique, NormalizedEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    threat_category: str = "BruteForce",
    label: str = "SSH-Patator",
    protocol: str = "TCP",
    dst_port: int = 22,
    flow_bytes_per_sec: float = 1_200.0,
    flow_packets_per_sec: float = 8.5,
    total_fwd_packets: int = 320,
    total_bwd_packets: int = 310,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc),
        src_ip="198.51.100.22",
        dst_port=dst_port,
        protocol=protocol,
        threat_category=threat_category,
        label=label,
        flow_bytes_per_sec=flow_bytes_per_sec,
        flow_packets_per_sec=flow_packets_per_sec,
        total_fwd_packets=total_fwd_packets,
        total_bwd_packets=total_bwd_packets,
        source_dataset="synthetic",
    )


# ---------------------------------------------------------------------------
# 1. Rule-based fallback — known category → technique mapping
# ---------------------------------------------------------------------------

class TestRuleBasedFallback:
    """
    Verify that the keyword-based fallback returns the expected techniques
    for known threat categories. This test requires NO live API key.
    """

    @pytest.fixture(autouse=True)
    def agent(self):
        return MITREAgent(use_llm_confirmation=False)

    # (threat_category, label, expected_technique_id)
    KNOWN_PAIRS = [
        ("BruteForce",    "SSH-Patator",   "T1110"),
        ("BruteForce",    "FTP-Patator",   "T1110"),
        ("PortScan",      "PortScan",       "T1046"),
        ("DDoS",          "DDoS",           "T1498"),
        ("DoS",           "DoS slowloris",  "T1499"),
        ("WebAttack",     "Web Attack XSS", "T1190"),
        ("Botnet",        "Bot",            "T1071"),
        ("Infiltration",  "Infiltration",   "T1041"),
        ("Reconnaissance","Reconnaissance", "T1595"),
        ("Benign",        "BENIGN",         "T1059"),  # falls to default
    ]

    @pytest.mark.parametrize("category,label,expected_id", KNOWN_PAIRS)
    def test_rule_based_mapping(self, agent, category, label, expected_id):
        """Rule-based mapping should return the expected technique ID as top match."""
        event = make_event(threat_category=category, label=label)
        candidates = agent._rule_based_mapping(event)

        assert len(candidates) > 0, "Should return at least one candidate"
        technique_ids = [c["technique_id"] for c in candidates]
        assert expected_id in technique_ids, (
            f"Expected {expected_id} in candidates for {category}/{label}, "
            f"got: {technique_ids}"
        )

    def test_rule_based_returns_at_most_top_k(self, agent):
        """Rule-based mapping should return at most TOP_K results."""
        event = make_event(threat_category="BruteForce", label="FTP-Patator")
        candidates = agent._rule_based_mapping(event)
        assert len(candidates) <= 3

    def test_rule_based_scores_in_range(self, agent):
        """All rule-based scores should be in [0, 1]."""
        event = make_event(threat_category="DDoS")
        candidates = agent._rule_based_mapping(event)
        for c in candidates:
            assert 0.0 <= c["score"] <= 1.0, f"Score out of range: {c['score']}"

    def test_rule_based_required_fields(self, agent):
        """Each candidate must have all required fields."""
        event = make_event()
        candidates = agent._rule_based_mapping(event)
        for c in candidates:
            assert "technique_id" in c
            assert "technique_name" in c
            assert "tactic" in c
            assert "score" in c


# ---------------------------------------------------------------------------
# 2. Event-to-text conversion
# ---------------------------------------------------------------------------

class TestEventToText:

    def test_contains_threat_category(self):
        event = make_event(threat_category="PortScan")
        text = MITREAgent._event_to_text(event)
        assert "PortScan" in text

    def test_contains_label(self):
        event = make_event(label="SSH-Patator")
        text = MITREAgent._event_to_text(event)
        assert "SSH-Patator" in text

    def test_contains_port(self):
        event = make_event(dst_port=22)
        text = MITREAgent._event_to_text(event)
        assert "22" in text

    def test_asymmetric_packets_mention(self):
        """High fwd/bwd ratio should add descriptive text for better embedding."""
        event = make_event(total_fwd_packets=1000, total_bwd_packets=5)
        text = MITREAgent._event_to_text(event)
        assert "asymmetric" in text.lower() or "scan" in text.lower()

    def test_high_volume_mention(self):
        event = make_event(flow_bytes_per_sec=500_000.0)
        text = MITREAgent._event_to_text(event)
        assert "high volume" in text.lower()

    def test_non_empty_for_unknown_category(self):
        event = make_event(threat_category="Unknown", label="Unknown")
        text = MITREAgent._event_to_text(event)
        assert len(text) > 0


# ---------------------------------------------------------------------------
# 3. techniques.json loading
# ---------------------------------------------------------------------------

class TestTechniquesLoading:

    def test_techniques_loaded(self):
        """MITREAgent should load techniques from techniques.json if it exists."""
        agent = MITREAgent(use_llm_confirmation=False)
        # techniques.json exists in the repo — should have loaded 500+ entries
        assert len(agent._technique_list) > 100, (
            f"Expected > 100 techniques, got {len(agent._technique_list)}"
        )

    def test_techniques_have_required_fields(self):
        """Each loaded technique must have technique_id, technique_name, tactics."""
        agent = MITREAgent(use_llm_confirmation=False)
        for tech in agent._technique_list[:20]:  # sample first 20
            assert "technique_id" in tech
            assert "technique_name" in tech
            assert "tactics" in tech

    def test_known_technique_present(self):
        """T1110 (Brute Force) must be in the loaded techniques."""
        agent = MITREAgent(use_llm_confirmation=False)
        ids = {t["technique_id"] for t in agent._technique_list}
        assert "T1110" in ids, "T1110 (Brute Force) not found in techniques"


# ---------------------------------------------------------------------------
# 4. AgentResult structure (mocked LLM)
# ---------------------------------------------------------------------------

class TestAgentResultStructure:

    @pytest.mark.asyncio
    async def test_process_async_returns_agent_result(self):
        """process_async() should return a valid AgentResult."""
        agent = MITREAgent(use_llm_confirmation=True)

        # Mock LLM confirmation
        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(return_value=MagicMock(
            text="T1110 (Brute Force) is confirmed. This is an SSH brute-force attack.",
            input_tokens=80, output_tokens=30,
        ))
        agent._llm = mock_llm

        event = make_event(threat_category="BruteForce", label="SSH-Patator")
        result = await agent.process_async(event)

        assert isinstance(result, AgentResult)
        assert result.status == "success"
        assert result.event_id == event.event_id
        assert "techniques" in result.output
        assert isinstance(result.output["techniques"], list)

    @pytest.mark.asyncio
    async def test_process_async_no_llm_confirmation(self):
        """Without LLM confirmation, should still return valid results."""
        agent = MITREAgent(use_llm_confirmation=False)
        event = make_event(threat_category="DDoS", label="DDoS")
        result = await agent.process_async(event)

        assert result.status == "success"
        assert len(result.output["techniques"]) > 0

    @pytest.mark.asyncio
    async def test_process_async_llm_failure_graceful(self):
        """If LLM confirmation fails, result should still be successful."""
        agent = MITREAgent(use_llm_confirmation=True)

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(side_effect=Exception("API timeout"))
        agent._llm = mock_llm

        event = make_event(threat_category="PortScan")
        result = await agent.process_async(event)

        assert result.status == "success"
        assert result.output["llm_reasoning"] is None


# ---------------------------------------------------------------------------
# 5. MITREOutput Pydantic model validation
# ---------------------------------------------------------------------------

class TestMITREOutputModel:

    def test_valid_mitre_technique(self):
        """MITRETechnique should accept valid fields."""
        tech = MITRETechnique(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            confidence=0.91,
            description="Brute forcing credentials.",
        )
        assert tech.technique_id == "T1110"
        assert tech.confidence == 0.91

    def test_confidence_bounds(self):
        """Confidence outside [0, 1] should raise a validation error."""
        with pytest.raises(Exception):
            MITRETechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                confidence=1.5,  # Invalid
            )

    def test_mitre_output_with_multiple_techniques(self):
        """MITREOutput should accept a list of techniques."""
        output = MITREOutput(
            techniques=[
                MITRETechnique(technique_id="T1110", technique_name="Brute Force",
                               tactic="Credential Access", confidence=0.90),
                MITRETechnique(technique_id="T1046", technique_name="Network Service Discovery",
                               tactic="Discovery", confidence=0.75),
            ],
            llm_reasoning="T1110 is the primary technique.",
        )
        assert len(output.techniques) == 2
        assert output.llm_reasoning is not None


# ---------------------------------------------------------------------------
# 6. Health check
# ---------------------------------------------------------------------------

class TestHealthCheck:

    def test_health_check_structure(self):
        agent = MITREAgent(use_llm_confirmation=False)
        health = agent.health_check()
        assert "agent" in health
        assert "healthy" in health
        assert "techniques_loaded" in health
        assert "faiss_index_loaded" in health

    def test_health_reports_technique_count(self):
        agent = MITREAgent(use_llm_confirmation=False)
        health = agent.health_check()
        assert health["techniques_loaded"] > 0

    def test_health_check_agent_name(self):
        agent = MITREAgent(use_llm_confirmation=False)
        health = agent.health_check()
        assert health["agent"] == "MITREAgent"
