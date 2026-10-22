"""
tests/test_report.py
--------------------
Unit tests for the Report Generation Agent (Phase 3 Member 3).

Tests:
  1. Risk score — Critical severity returns score >= 70
  2. Risk score — Low severity returns score <= 30
  3. Risk score — enrichment confidence boosts score
  4. Risk score — AbuseIPDB > 80 applies bonus
  5. Risk score — unknown severity defaults to low base
  6. Risk score — always in [0, 100] range
  7. Build context — all required keys present
  8. Build context — severity string normalised (no enum prefix)
  9. Build context — incident_id falls back to event_id when None
  10. Build context — mitre_techniques list preserved
  11. Heuristic report — structure matches expected schema
  12. Heuristic report — contains source IP in evidence
  13. Health check — returns expected keys
  14. process() raises NotImplementedError
  15. AgentResult compliance — output has required fields
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.report_agent import ReportAgent
from api.models import (
    AgentResult,
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def agent():
    """Create a ReportAgent without writing to disk."""
    a = ReportAgent.__new__(ReportAgent)
    # Call BaseAgent init manually without touching the filesystem
    from agents.base_agent import BaseAgent
    BaseAgent.__init__(a, agent_name="ReportAgent", version="1.0.0")
    # Patch filesystem dirs
    from pathlib import Path
    a.template_path = Path("templates/report.html")
    a.output_dir = Path("/tmp/reports")
    return a


def make_event(
    severity=SeverityLevel.HIGH,
    threat_category=ThreatCategory.PORT_SCAN,
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    dst_port=22,
    protocol="TCP",
    mitre_techniques=None,
    enrichment_data=None,
    incident_id=None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-event-001",
        timestamp=datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        severity=severity,
        threat_category=threat_category,
        mitre_techniques=mitre_techniques or [],
        enrichment_data=enrichment_data,
        incident_id=incident_id,
    )


# ---------------------------------------------------------------------------
# 1-6. Risk score tests
# ---------------------------------------------------------------------------

def test_risk_score_critical_high(agent):
    """Critical severity should produce risk score >= 70."""
    event = make_event(severity=SeverityLevel.CRITICAL)
    score = agent._calculate_risk_score(event)
    assert score >= 70, f"Expected >= 70 for Critical, got {score}"


def test_risk_score_low_severity(agent):
    """Low severity without enrichment should produce score <= 30."""
    event = make_event(severity=SeverityLevel.LOW)
    score = agent._calculate_risk_score(event)
    assert score <= 30, f"Expected <= 30 for Low, got {score}"


def test_risk_score_confidence_boost(agent):
    """High enrichment confidence should raise the score above base."""
    event_no_enrich = make_event(severity=SeverityLevel.MEDIUM)
    event_with_enrich = make_event(
        severity=SeverityLevel.MEDIUM,
        enrichment_data={"confidence": 1.0},
    )
    base_score = agent._calculate_risk_score(event_no_enrich)
    boosted_score = agent._calculate_risk_score(event_with_enrich)
    assert boosted_score > base_score, "Confidence should boost the score"


def test_risk_score_abuseipdb_bonus(agent):
    """AbuseIPDB score > 80 should add a 5-point bonus."""
    event_low_abuse = make_event(
        severity=SeverityLevel.MEDIUM,
        enrichment_data={"confidence": 0.5, "abuseipdb_score": 50},
    )
    event_high_abuse = make_event(
        severity=SeverityLevel.MEDIUM,
        enrichment_data={"confidence": 0.5, "abuseipdb_score": 90},
    )
    score_low  = agent._calculate_risk_score(event_low_abuse)
    score_high = agent._calculate_risk_score(event_high_abuse)
    assert score_high == pytest.approx(score_low + 5.0, abs=0.1), (
        f"Expected +5 for AbuseIPDB > 80. Low={score_low}, High={score_high}"
    )


def test_risk_score_unknown_severity_defaults(agent):
    """Unknown severity should produce a low base score."""
    event = make_event(severity=SeverityLevel.UNKNOWN)
    score = agent._calculate_risk_score(event)
    assert score <= 20, f"Expected <= 20 for Unknown severity, got {score}"


def test_risk_score_always_in_range(agent):
    """Risk score must always be in [0, 100]."""
    for sev in SeverityLevel:
        for confidence in [0.0, 0.5, 1.0]:
            event = make_event(
                severity=sev,
                enrichment_data={"confidence": confidence, "abuseipdb_score": 95},
            )
            score = agent._calculate_risk_score(event)
            assert 0 <= score <= 100, f"Score {score} out of range for {sev}/{confidence}"


# ---------------------------------------------------------------------------
# 7-10. Build context tests
# ---------------------------------------------------------------------------

def test_build_context_required_keys(agent):
    """Context dict must contain all keys needed by the Jinja2 template."""
    required_keys = {
        "event_id", "incident_id", "timestamp", "generated_at",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "severity", "threat_category", "status",
        "is_true_positive", "correlation_summary",
        "mitre_techniques", "enrichment_data", "risk_score",
        "is_malicious", "virustotal_score", "abuseipdb_score", "threat_labels",
    }
    event = make_event(mitre_techniques=["T1046", "T1110"])
    ctx = agent._build_context(event)
    missing = required_keys - set(ctx.keys())
    assert not missing, f"Missing context keys: {missing}"


def test_build_context_severity_string_normalised(agent):
    """Severity should be a plain string, not 'SeverityLevel.High'."""
    event = make_event(severity=SeverityLevel.HIGH)
    ctx = agent._build_context(event)
    assert ctx["severity"] == "High", f"Unexpected severity: {ctx['severity']}"
    assert "." not in ctx["severity"], "Severity should not contain enum prefix"


def test_build_context_incident_id_fallback(agent):
    """incident_id should fall back to event_id when None."""
    event = make_event(incident_id=None)
    ctx = agent._build_context(event)
    assert ctx["incident_id"] == event.event_id


def test_build_context_mitre_techniques_preserved(agent):
    """Mitre techniques should be passed through unmodified."""
    techniques = ["T1046", "T1110", "T1059"]
    event = make_event(mitre_techniques=techniques)
    ctx = agent._build_context(event)
    assert ctx["mitre_techniques"] == techniques


# ---------------------------------------------------------------------------
# 11-12. Heuristic fallback tests
# ---------------------------------------------------------------------------

def test_heuristic_report_schema(agent):
    """Heuristic report must have required keys with correct types."""
    event = make_event(severity=SeverityLevel.HIGH, mitre_techniques=["T1046"])
    ctx   = agent._build_context(event)
    report = agent._heuristic_report(ctx)

    assert "summary"             in report
    assert "evidence"            in report
    assert "risk_level"          in report
    assert "recommended_actions" in report
    assert isinstance(report["summary"],             str)
    assert isinstance(report["evidence"],            list)
    assert isinstance(report["recommended_actions"], list)
    assert len(report["evidence"])            >= 1
    assert len(report["recommended_actions"]) >= 1


def test_heuristic_report_contains_src_ip(agent):
    """Heuristic report evidence should reference the source IP."""
    event = make_event(src_ip="172.16.5.99")
    ctx   = agent._build_context(event)
    report = agent._heuristic_report(ctx)
    evidence_text = " ".join(report["evidence"])
    assert "172.16.5.99" in evidence_text, (
        f"Source IP not found in evidence: {report['evidence']}"
    )


# ---------------------------------------------------------------------------
# 13. Health check
# ---------------------------------------------------------------------------

def test_health_check_keys(agent):
    """health_check() must return required status keys."""
    result = agent.health_check()
    assert "healthy"         in result
    assert "agent"           in result
    assert "version"         in result
    assert "groq_key_set"    in result
    assert "jinja2_available" in result
    assert result["agent"]   == "ReportAgent"
    assert result["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# 14. process() raises NotImplementedError
# ---------------------------------------------------------------------------

def test_process_raises_not_implemented(agent):
    """process() must raise NotImplementedError — use process_async()."""
    event = make_event()
    with pytest.raises(NotImplementedError):
        agent.process(event)


# ---------------------------------------------------------------------------
# 15. process_async() returns valid AgentResult
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_async_agent_result_schema(agent, tmp_path):
    """process_async() should return a valid AgentResult with required fields."""
    agent.output_dir = tmp_path  # avoid touching real FS

    mock_report = {
        "summary":             "Suspicious port scan detected from internal host.",
        "evidence":            ["Source IP: 192.168.1.10", "Dst Port: 22 (SSH)"],
        "risk_level":          "High",
        "recommended_actions": ["Block source IP.", "Rotate SSH keys."],
    }

    event = make_event(
        severity=SeverityLevel.HIGH,
        mitre_techniques=["T1046"],
        enrichment_data={"confidence": 0.7, "is_malicious": True},
        incident_id="INC-001",
    )

    with patch.object(agent, "_generate_report_content", return_value=mock_report), \
         patch.object(agent, "_render_html", return_value=""):

        result = await agent.process_async(event)

    assert isinstance(result, AgentResult)
    assert result.status  == "success"
    assert result.event_id == event.event_id
    assert 0.0 <= result.confidence <= 1.0

    output = result.output or {}
    assert "incident_id"         in output
    assert "risk_score"          in output
    assert "risk_level"          in output
    assert "summary"             in output
    assert "evidence"            in output
    assert "recommended_actions" in output
    assert output["incident_id"] == "INC-001"