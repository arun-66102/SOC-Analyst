"""
tests/test_enrichment.py
------------------------
Unit tests for the Threat Intelligence Enrichment Agent & Investigation Reasoning (Phase 3 Member 1).

Tests:
  1. Rate limiter — verifies sliding window call limiting
  2. Private IP detection — verifies RFC1918 & loopback IPs skip external lookups
  3. AbuseIPDB mock integration — verifies response parsing and score mapping
  4. VirusTotal mock integration — verifies engine detection counts and scores
  5. Backoff and retry logic — verifies recovery from transient 429/500 errors
  6. In-memory caching — verifies repeated IP queries use cached results
  7. Heuristic fallback — verifies offline threat scoring without API keys
  8. Chain-of-Thought reasoning — verifies 5-step CoT narrative generation
  9. AgentResult format — verifies compliance with EnrichmentOutput schema
  10. Health check — verifies configuration status reporting

Author  : Member 1 — Phase 3
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.enrichment_agent import EnrichmentAgent, RateLimiter
from api.models import (
    AgentResult,
    EnrichmentOutput,
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def make_event(
    src_ip: str = "185.220.101.5",
    threat_category: str = "BruteForce",
    label: str = "SSH-Patator",
    dst_port: int = 22,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip="192.168.1.10",
        dst_port=dst_port,
        protocol="TCP",
        threat_category=threat_category,
        label=label,
        flow_duration=1200000.0,
        total_fwd_packets=500,
        total_bwd_packets=10,
    )


# ---------------------------------------------------------------------------
# 1. RateLimiter Tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire_under_limit(self):
        limiter = RateLimiter(max_calls=3, period_seconds=1.0)
        start = time.monotonic()
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_acquire_blocks_when_limit_exceeded(self):
        limiter = RateLimiter(max_calls=2, period_seconds=0.2)
        start = time.monotonic()
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()  # should wait approx 0.2s
        elapsed = time.monotonic() - start
        assert elapsed >= 0.15


# ---------------------------------------------------------------------------
# 2. Private IP Detection Tests
# ---------------------------------------------------------------------------

class TestPrivateIPHandling:
    @pytest.mark.parametrize(
        "private_ip",
        ["192.168.1.50", "10.0.0.1", "172.16.5.20", "127.0.0.1"],
    )
    def test_private_ip_is_marked_safe(self, private_ip):
        agent = EnrichmentAgent(vt_api_key="mock", abuse_api_key="mock")
        event = make_event(src_ip=private_ip, threat_category="Benign", label="BENIGN")

        result = agent.run(event)
        assert result.status == "success"
        output = result.output
        assert output["is_malicious"] is False
        assert "Internal Network" in output["threat_labels"]
        assert output["abuseipdb_score"] == 0
        assert "Private IP" in output["virustotal_score"]

    def test_public_ip_not_flagged_as_private(self):
        agent = EnrichmentAgent()
        assert agent._is_private_ip("8.8.8.8") is False
        assert agent._is_private_ip("185.220.101.5") is False


# ---------------------------------------------------------------------------
# 3. AbuseIPDB Integration Tests
# ---------------------------------------------------------------------------

class TestAbuseIPDBIntegration:
    @pytest.mark.asyncio
    async def test_abuseipdb_mock_success(self):
        agent = EnrichmentAgent(abuse_api_key="mock_key", vt_api_key="")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "185.220.101.5",
                "abuseConfidenceScore": 88,
                "totalReports": 240,
                "countryCode": "NL",
                "isp": "Tor Exit Node",
                "usageType": "Data Center",
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            event = make_event(src_ip="185.220.101.5")
            result = await agent.process_async(event)

            assert result.status == "success"
            assert result.output["is_malicious"] is True
            assert result.output["abuseipdb_score"] == 88
            assert "AbuseIPDB" in result.output["sources"]
            assert "AbuseIPDB Flagged" in result.output["threat_labels"]


# ---------------------------------------------------------------------------
# 4. VirusTotal Integration Tests
# ---------------------------------------------------------------------------

class TestVirusTotalIntegration:
    @pytest.mark.asyncio
    async def test_virustotal_mock_success(self):
        agent = EnrichmentAgent(vt_api_key="mock_vt_key", abuse_api_key="")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 12,
                        "suspicious": 2,
                        "harmless": 70,
                        "undetected": 4,
                    },
                    "reputation": -35,
                    "tags": ["scanner", "c2"],
                    "as_owner": "Host Provider",
                    "country": "US",
                }
            }
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            event = make_event(src_ip="198.51.100.25")
            result = await agent.process_async(event)

            assert result.status == "success"
            assert result.output["is_malicious"] is True
            assert "12/88 engines" in result.output["virustotal_score"]
            assert "VirusTotal" in result.output["sources"]


# ---------------------------------------------------------------------------
# 5. Backoff & Retry Logic Tests
# ---------------------------------------------------------------------------

class TestBackoffAndRetry:
    @pytest.mark.asyncio
    async def test_retry_on_429_rate_limit(self):
        agent = EnrichmentAgent(abuse_api_key="mock_key", vt_api_key="")

        # First call returns 429, second call returns 200
        resp_429 = MagicMock(status_code=429)
        resp_200 = MagicMock(
            status_code=200,
            json=lambda: {"data": {"abuseConfidenceScore": 60, "totalReports": 50}},
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [resp_429, resp_200]
            data = await agent._query_abuseipdb_with_retry("203.0.113.88", initial_delay=0.01)

            assert data is not None
            assert data["abuseConfidenceScore"] == 60
            assert mock_get.call_count == 2


# ---------------------------------------------------------------------------
# 6. In-Memory Caching Tests
# ---------------------------------------------------------------------------

class TestEnrichmentCache:
    @pytest.mark.asyncio
    async def test_cache_avoids_duplicate_api_calls(self):
        agent = EnrichmentAgent(abuse_api_key="mock_key", vt_api_key="")
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {"data": {"abuseConfidenceScore": 95, "totalReports": 100}},
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            event1 = make_event(src_ip="198.51.100.99")
            event2 = make_event(src_ip="198.51.100.99")

            res1 = await agent.process_async(event1)
            res2 = await agent.process_async(event2)

            # API should be called exactly once
            assert mock_get.call_count == 1
            assert res1.output["abuseipdb_score"] == 95
            assert res2.output["cached"] is True


# ---------------------------------------------------------------------------
# 7. Heuristic Fallback Tests
# ---------------------------------------------------------------------------

class TestHeuristicFallback:
    @pytest.mark.parametrize(
        "cat,expected_malicious,min_abuse",
        [
            ("BruteForce", True, 50),
            ("DDoS", True, 70),
            ("PortScan", True, 40),
            ("Botnet", True, 70),
            ("Benign", False, 0),
        ],
    )
    def test_heuristic_enrichment_categories(self, cat, expected_malicious, min_abuse):
        # Initialized without API keys
        agent = EnrichmentAgent(vt_api_key="", abuse_api_key="")
        event = make_event(src_ip="203.0.113.12", threat_category=cat, label=cat)

        result = agent.run(event)
        assert result.status == "success"
        output = result.output
        assert output["is_malicious"] is expected_malicious
        assert output["abuseipdb_score"] >= min_abuse
        assert "Heuristic Threat Intel (Offline)" in output["sources"]


# ---------------------------------------------------------------------------
# 8. Chain-of-Thought Reasoning Tests
# ---------------------------------------------------------------------------

class TestChainOfThoughtReasoning:
    @pytest.mark.asyncio
    async def test_deterministic_cot_has_all_five_steps(self):
        agent = EnrichmentAgent(enable_llm_reasoning=False)
        event = make_event(src_ip="198.51.100.5", threat_category="BruteForce")

        result = await agent.process_async(event)
        cot = result.output.get("chain_of_thought", [])

        assert len(cot) == 5
        assert "Step 1: Telemetry Assessment" in cot[0]
        assert "Step 2: MITRE ATT&CK Context" in cot[1]
        assert "Step 3: Threat Intelligence Corroboration" in cot[2]
        assert "Step 4: Attack Hypothesis & Blast Radius" in cot[3]
        assert "Step 5: Containment & Remediation" in cot[4]
        assert len(result.output.get("recommended_containment", [])) > 0

    @pytest.mark.asyncio
    async def test_llm_cot_reasoning_mock(self):
        agent = EnrichmentAgent(enable_llm_reasoning=True)
        mock_llm_response = MagicMock()
        mock_llm_response.text = """
        {
          "verdict": "Malicious",
          "confidence": 0.95,
          "chain_of_thought": [
            "Step 1: Telemetry indicates high-frequency SSH attempts.",
            "Step 2: T1110 Brute Force identified.",
            "Step 3: Source IP has 90% abuse rating.",
            "Step 4: Probable credential stuffing campaign.",
            "Step 5: Drop IP at perimeter firewall."
          ],
          "investigation_narrative": "Host 185.220.101.5 launched automated SSH brute-force credential stuffing.",
          "recommended_containment": ["Block source IP", "Enforce fail2ban"]
        }
        """

        with patch("agents.enrichment_agent.get_llm_client") as mock_get_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.chat.return_value = mock_llm_response
            mock_get_client.return_value = mock_client_instance

            event = make_event(src_ip="185.220.101.5", threat_category="BruteForce")
            result = await agent.process_async(event)

            assert result.status == "success"
            assert "credential stuffing" in result.reasoning
            assert len(result.output["chain_of_thought"]) == 5


# ---------------------------------------------------------------------------
# 9. Health Check & Schema Tests
# ---------------------------------------------------------------------------

class TestHealthCheckAndSchema:
    def test_health_check_reporting(self):
        agent = EnrichmentAgent(vt_api_key="real_key", abuse_api_key="")
        status = agent.health_check()

        assert status["healthy"] is True
        assert status["agent"] == "EnrichmentAgent"
        assert status["virustotal_configured"] is True
        assert status["abuseipdb_configured"] is False
        assert "vt_rate_limit" in status

    def test_output_matches_enrichment_output_schema(self):
        agent = EnrichmentAgent()
        event = make_event()
        result = agent.run(event)

        # Ensure EnrichmentOutput can validate the output dict
        parsed_out = EnrichmentOutput(**result.output)
        assert parsed_out.ip_address == event.src_ip
        assert isinstance(parsed_out.is_malicious, bool)
