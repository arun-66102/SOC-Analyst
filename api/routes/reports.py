"""Report retrieval endpoint. Report generation itself belongs to Member 3."""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, HTTPException
"""
api/routes/reports.py
----------------------
Report-retrieval and compilation REST endpoints.

Endpoints:
  GET /api/reports/{incident_id} — fetch or compile the investigation report for an incident

Author  : Member 2 — Phase 3
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from database.store import get_store

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/reports/{incident_id}", summary="Get investigation report")
async def get_report(incident_id: str) -> dict:
    from database.db import fetch_report
    report = await asyncio.to_thread(fetch_report, incident_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"No report found for incident '{incident_id}'. ReportAgent is implemented by Phase 3 Member 3.")
    return report
# ---------------------------------------------------------------------------
# GET /api/reports/{incident_id}
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{incident_id}",
    summary="Get investigation report",
    description="Returns the comprehensive investigation report for a correlated incident group.",
)
async def get_report(incident_id: str) -> JSONResponse:
    """Retrieve or dynamically synthesize an investigation report for an incident."""
    logger.info("GET /api/reports/%s", incident_id)
    store = get_store()

    # 1. Check if a pre-compiled report is already stored
    cached_report = store.get_report(incident_id)
    if cached_report:
        return JSONResponse(content=cached_report)

    # 2. Check if incident exists
    incident = store.get_incident(incident_id)

    # Find related alerts
    all_alerts, _ = store.list_alerts(limit=500)
    related_alerts = [a for a in all_alerts if a.incident_id == incident_id]

    if not incident and not related_alerts:
        raise HTTPException(
            status_code=404,
            detail=f"No incident or report found for ID '{incident_id}'.",
        )

    # 3. Dynamically compile investigation report
    event_count = len(related_alerts) if related_alerts else (len(incident.get("event_ids", [])) if incident else 1)
    sample_alert = related_alerts[0] if related_alerts else None

    # Severities and categories
    severities = [str(a.severity) for a in related_alerts]
    highest_sev = "Critical" if any("critical" in s.lower() for s in severities) else (
        "High" if any("high" in s.lower() for s in severities) else "Medium"
    )

    threat_categories = list({str(a.threat_category) for a in related_alerts if a.threat_category})
    threat_category = threat_categories[0] if threat_categories else "Intrusion Activity"

    # Unique IOCs
    iocs_ips = list({a.src_ip for a in related_alerts if a.src_ip})
    dst_ports = list({a.dst_port for a in related_alerts if a.dst_port})
    mitre_techs = list(
        {tech for a in related_alerts for tech in a.mitre_techniques if tech}
    )

    # Threat intel & CoT
    enrichment = sample_alert.enrichment_data if sample_alert else None
    narrative = ""
    cot_steps = []
    actions = [
        f"Block source indicator(s) {', '.join(iocs_ips) or 'suspicious IPs'} at edge perimeter firewall",
        f"Inspect inbound connection traffic targeting destination port(s) {', '.join(map(str, dst_ports)) or 'exposed services'}",
        "Trigger endpoint credential rotation and review authentication audit logs",
    ]

    if enrichment:
        narrative = enrichment.get("investigation_narrative", "")
        cot_steps = enrichment.get("chain_of_thought", [])
        if enrichment.get("recommended_containment"):
            actions = enrichment["recommended_containment"]

    if not narrative:
        narrative = (
            f"Correlated incident {incident_id} comprises {event_count} security event(s) exhibiting "
            f"characteristic signatures of {threat_category}. Observed traffic originated from {', '.join(iocs_ips) or 'external sources'} "
            f"targeting network services on port(s) {', '.join(map(str, dst_ports))}. "
            f"Immediate automated containment and perimeter filtering are advised."
        )

    # Quantitative risk score (0 - 100)
    base_scores = {"critical": 90, "high": 75, "medium": 50, "low": 25}
    risk_score = base_scores.get(highest_sev.lower(), 50)
    if any(a.is_true_positive for a in related_alerts):
        risk_score = min(98, risk_score + 8)

    report_payload = {
        "report_id": f"REP-{incident_id}",
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": event_count,
        "severity": highest_sev,
        "threat_category": threat_category,
        "risk_score": risk_score,
        "executive_summary": (
            f"Anomalous intrusion activity classified as {highest_sev} severity was detected and correlated "
            f"under Incident {incident_id}. Automated threat analysis confirmed {event_count} related telemetry event(s)."
        ),
        "technical_analysis": narrative,
        "chain_of_thought": cot_steps,
        "mitre_techniques": mitre_techs,
        "indicators_of_compromise": {
            "source_ips": iocs_ips,
            "targeted_ports": dst_ports,
        },
        "threat_intelligence": {
            "is_malicious": enrichment.get("is_malicious", True) if enrichment else True,
            "virustotal_score": enrichment.get("virustotal_score", "N/A") if enrichment else "N/A",
            "abuseipdb_score": enrichment.get("abuseipdb_score", 0) if enrichment else 0,
            "threat_labels": enrichment.get("threat_labels", []) if enrichment else [],
        },
        "recommended_actions": actions,
    }

    # Store for future queries
    store.save_report(incident_id, report_payload)

    return JSONResponse(content=report_payload)
