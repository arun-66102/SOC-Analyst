from datetime import datetime, timezone

from agents.report_agent import ReportAgent
from api.models import (
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
)


def test_report_risk_score():

    agent = ReportAgent()

    event = NormalizedEvent(
        event_id="report-test-001",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        protocol="TCP",
        severity=SeverityLevel.HIGH,
        threat_category=ThreatCategory.PORT_SCAN,
        enrichment_data={
            "confidence": 0.8
        }
    )

    score = agent._calculate_risk_score(event)

    assert 0 <= score <= 100
    assert score > 0


def test_report_context():

    agent = ReportAgent()

    event = NormalizedEvent(
        event_id="report-test-002",
        severity=SeverityLevel.MEDIUM,
        threat_category=ThreatCategory.DOS,
        mitre_techniques=["T1046"]
    )

    context = agent._build_context(event)

    assert context["event_id"] == "report-test-002"
    assert context["severity"] == "Medium"
    assert "T1046" in context["mitre_techniques"]
    assert "risk_score" in context