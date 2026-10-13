"""
report_agent.py
---------------
Investigation Report Generation Agent — produces structured
investigation reports from fully processed incidents.

Phase 3 — Member 3 Implementation:
  - Takes correlated incident (triage + MITRE + enrichment data)
  - Generates executive summary, technical analysis, MITRE techniques,
    IOCs, risk score, and recommended response actions
  - Saves report to AlertStore

Author  : Member 3 — Phase 3
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any

from agents.base_agent import BaseAgent
from api.models import AgentResult, NormalizedEvent, SeverityLevel


class ReportAgent(BaseAgent):
    """Report Generation Agent — Phase 3 implementation."""

    def __init__(self) -> None:
        super().__init__(agent_name="ReportAgent", version="1.0.0")
        self._llm = None

    def _check_dependencies(self) -> dict[str, Any]:
        import os
        key = os.getenv("GROQ_API_KEY", "")
        return {"healthy": True, "groq_key_set": bool(key)}

    def process(self, event: NormalizedEvent) -> AgentResult:
        """Synchronous entry point — delegates to async."""
        return asyncio.run(self.process_async(event))

    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        """Generate a structured investigation report for the event/incident."""
        self.log_info(f"Generating report for event {event.event_id} (incident={event.incident_id})")

        report = self._compile_report(event)

        # Optionally persist to AlertStore
        try:
            from database.store import get_store
            if event.incident_id:
                get_store().save_report(event.incident_id, report)
        except Exception as exc:
            self.log_warning(f"Failed to persist report: {exc}")

        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=report.get("risk_score", 50) / 100.0,
            reasoning=report.get("executive_summary", ""),
            output=report,
        )

    def _compile_report(self, event: NormalizedEvent) -> dict[str, Any]:
        """Build the structured investigation report from available event data."""
        enrichment = event.enrichment_data or {}
        sev_str = str(event.severity).replace("SeverityLevel.", "")
        if hasattr(event.severity, "value"):
            sev_str = event.severity.value

        # Risk score based on severity + true positive status
        base_scores = {"Critical": 92, "High": 75, "Medium": 50, "Low": 20, "Unknown": 40}
        risk_score = base_scores.get(sev_str, 50)
        if event.is_true_positive:
            risk_score = min(98, risk_score + 6)

        # IOCs
        iocs: dict[str, Any] = {
            "source_ips": [event.src_ip] if event.src_ip else [],
            "destination_ips": [event.dst_ip] if event.dst_ip else [],
            "targeted_ports": [event.dst_port] if event.dst_port else [],
            "protocols": [event.protocol] if event.protocol else [],
        }

        # Enrichment threat intel
        threat_intel = {
            "is_malicious": enrichment.get("is_malicious", False),
            "virustotal_score": enrichment.get("virustotal_score", "N/A"),
            "abuseipdb_score": enrichment.get("abuseipdb_score", 0),
            "threat_labels": enrichment.get("threat_labels", []),
            "sources": enrichment.get("sources", []),
        }

        # Recommended actions
        recommended_actions = enrichment.get("recommended_containment", [])
        if not recommended_actions:
            recommended_actions = self._default_actions(sev_str, event)

        # Investigation narrative from investigation agent result
        narrative = enrichment.get("investigation_narrative", "")
        if not narrative:
            narrative = (
                f"Security event categorized as {event.threat_category} with {sev_str} severity was detected "
                f"{'and confirmed as a True Positive' if event.is_true_positive else '(potential False Positive)'}. "
                f"Source: {event.src_ip or 'unknown'} → Destination: {event.dst_ip or 'unknown'}:{event.dst_port or 'N/A'}. "
                f"Protocol: {event.protocol or 'unknown'}. "
                f"MITRE ATT&CK techniques identified: {', '.join(event.mitre_techniques) or 'None detected'}. "
                f"Incident ID: {event.incident_id or 'standalone event'}."
            )

        report: dict[str, Any] = {
            "report_id": f"REP-{event.event_id[:8].upper()}",
            "incident_id": event.incident_id or event.event_id,
            "event_id": event.event_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "severity": sev_str,
            "threat_category": str(event.threat_category).replace("ThreatCategory.", ""),
            "risk_score": risk_score,
            "is_true_positive": event.is_true_positive,
            "executive_summary": (
                f"A {sev_str} severity security incident ({event.threat_category}) was detected and analyzed. "
                f"Risk score: {risk_score}/100. "
                f"{'Immediate response required.' if risk_score >= 75 else 'Monitor and investigate further.'}"
            ),
            "technical_analysis": narrative,
            "attack_timeline": [
                {
                    "timestamp": str(event.timestamp),
                    "event_id": event.event_id,
                    "description": f"Initial {event.threat_category} activity detected from {event.src_ip or 'unknown'}",
                    "severity": sev_str,
                }
            ],
            "mitre_techniques": event.mitre_techniques,
            "indicators_of_compromise": iocs,
            "threat_intelligence": threat_intel,
            "recommended_actions": recommended_actions,
            "source_dataset": event.source_dataset,
        }

        return report

    @staticmethod
    def _default_actions(severity: str, event: NormalizedEvent) -> list[str]:
        """Generate default response actions based on severity and category."""
        actions = []
        cat = str(event.threat_category).lower()

        if severity in ("Critical", "High"):
            actions.append(f"Immediately block source IP {event.src_ip or 'suspicious source'} at perimeter firewall")
            actions.append("Escalate to Tier 2/3 SOC analyst and Incident Response team")
            actions.append("Isolate affected endpoint(s) from the network")

        if "brute" in cat:
            actions.append("Reset credentials for all targeted accounts")
            actions.append("Implement account lockout and MFA enforcement")
        elif "exfiltration" in cat:
            actions.append("Immediately block all outbound traffic from compromised host")
            actions.append("Conduct data breach assessment and notify DPO if required")
        elif "malware" in cat or "botnet" in cat:
            actions.append("Run full AV/EDR scan on affected system")
            actions.append("Preserve forensic image of compromised host")
        elif "port_scan" in cat or "portscan" in cat or "reconnaissance" in cat:
            actions.append("Review and harden exposed service configurations")
            actions.append("Enable geo-blocking for suspicious source countries")

        actions.append("Document incident timeline in ticketing system")
        actions.append("Update threat intelligence feeds with observed IOCs")

        return actions[:6]  # Cap at 6 actions
