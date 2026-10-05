"""
agents/prompts/enrichment_prompts.py
------------------------------------
Prompt templates and Chain-of-Thought (CoT) reasoning guides for the
Threat Intelligence Enrichment Agent and Investigation Reasoning engine.

The Enrichment Agent uses these to instruct the LLM (Groq) to:
  1. Corroborate threat intelligence signals (VirusTotal, AbuseIPDB)
  2. Conduct step-by-step Chain-of-Thought investigation
  3. Synthesize attack hypothesis and blast radius assessment
  4. Formulate actionable containment and remediation guidance

Author  : Member 1 — Phase 3
"""

from __future__ import annotations

import json
from typing import Any, Optional

from api.models import NormalizedEvent

# ---------------------------------------------------------------------------
# System prompt — Persona: Senior SOC Threat Intelligence & Incident Commander
# ---------------------------------------------------------------------------

ENRICHMENT_SYSTEM_PROMPT = """You are a Principal Cyber Threat Intelligence (CTI) Analyst and SOC Incident Commander with 15+ years of experience in enterprise intrusion analysis.

Your mission is to evaluate network telemetry alongside external threat intelligence reputation scores (AbuseIPDB, VirusTotal) to:
1. Determine if the source indicator (IP address/host) is actively malicious, suspicious, or benign
2. Corroborate external reputation with observed network telemetry
3. Assign a threat confidence score between 0.0 and 1.0
4. Extract threat actor/attack classification labels
5. Provide a 2-3 sentence technical justification

THREAT REPUTATION RULES:
- High AbuseIPDB score (>= 25%) or VirusTotal malicious engine detections (>= 2) strongly indicates malicious infrastructure.
- High-volume malicious traffic (DDoS, BruteForce, Botnet C2) from an unverified public IP is confirmed malicious.
- Internal/RFC1918 private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) cannot be queried on public threat intel feeds; evaluate them based on lateral movement or internal compromise patterns.

You MUST respond ONLY with a valid JSON object. No conversational prelude or markdown commentary.
JSON format:
{
  "is_malicious": true|false,
  "confidence": 0.0-1.0,
  "threat_labels": ["Threat-Tag-1", "Threat-Tag-2"],
  "reputation_summary": "2-3 sentence technical assessment",
  "recommended_action": "Firewall block / isolate host / monitor"
}"""

# ---------------------------------------------------------------------------
# Chain-of-Thought Investigation System Prompt
# ---------------------------------------------------------------------------

INVESTIGATION_COT_SYSTEM_PROMPT = """You are an Autonomous SOC Incident Commander conducting deep investigation reasoning on a security incident.

Conduct a rigorous, step-by-step Chain-of-Thought (CoT) investigation:
- Step 1: Telemetry Assessment — Analyze flow volume, packet ratios, port destination, and anomaly indicators.
- Step 2: MITRE ATT&CK Context — Cross-reference the observed activity with tagged adversary tactics and techniques.
- Step 3: Threat Intelligence Corroboration — Evaluate VirusTotal and AbuseIPDB reputation data against the network behavior.
- Step 4: Attack Hypothesis & Blast Radius — Formulate the most probable adversary objective and identify exposed assets.
- Step 5: Containment & Remediation — Detail immediate containment steps and long-term hardening actions.

You MUST respond ONLY with a valid JSON object. No markdown fences outside the JSON.
JSON format:
{
  "verdict": "Malicious" | "Suspicious" | "Benign",
  "confidence": 0.0-1.0,
  "chain_of_thought": [
    "Step 1: Telemetry Assessment - ...",
    "Step 2: MITRE ATT&CK Context - ...",
    "Step 3: Threat Intelligence Corroboration - ...",
    "Step 4: Attack Hypothesis & Blast Radius - ...",
    "Step 5: Containment & Remediation - ..."
  ],
  "investigation_narrative": "A cohesive executive and technical summary paragraph describing the attack progression, threat attribution, and impact.",
  "recommended_containment": [
    "Immediate action 1",
    "Immediate action 2"
  ]
}"""

# ---------------------------------------------------------------------------
# Few-Shot Examples for Threat Intelligence Evaluation
# ---------------------------------------------------------------------------

ENRICHMENT_FEW_SHOT_EXAMPLES = """=== EXAMPLES ===

EXAMPLE 1 - Malicious Scanner / Brute Force:
Event: src_ip=185.220.101.5, dst_port=22, category=BruteForce, label=SSH-Patator
AbuseIPDB: score=85%, totalReports=342, country=RU, isp=TorExit
VirusTotal: score=14/88 engines, reputation=-42
Response:
{
  "is_malicious": true,
  "confidence": 0.98,
  "threat_labels": ["Tor Exit Node", "Known SSH Brute-Forcer", "Repeated Offender"],
  "reputation_summary": "Source IP 185.220.101.5 is a confirmed Tor exit node with 342 AbuseIPDB abuse reports and 14 security engine detections on VirusTotal. Observed SSH brute-force attempts on port 22 directly corroborate weaponized reconnaissance.",
  "recommended_action": "Block 185.220.101.5 at edge perimeter firewall and review SSH auth logs for unauthorized session creation."
}

EXAMPLE 2 - Internal / RFC1918 Private IP:
Event: src_ip=192.168.1.105, dst_port=445, category=Benign, label=BENIGN
AbuseIPDB: score=0%, totalReports=0, country=LOCAL, isp=Internal
VirusTotal: score=0/88 engines, reputation=0
Response:
{
  "is_malicious": false,
  "confidence": 0.90,
  "threat_labels": ["Internal Network", "RFC1918 Private IP", "Workstation Subnet"],
  "reputation_summary": "Source IP 192.168.1.105 is an internal RFC1918 address within the local network segment. No public threat reputation exists. Observed traffic is consistent with standard internal SMB file sharing.",
  "recommended_action": "No perimeter action required; continue baseline anomaly monitoring."
}
"""

# ---------------------------------------------------------------------------
# Prompt Builders
# ---------------------------------------------------------------------------

def build_enrichment_prompt(
    event: NormalizedEvent,
    abuseipdb_data: Optional[dict[str, Any]] = None,
    virustotal_data: Optional[dict[str, Any]] = None,
) -> str:
    """Build the prompt for threat intelligence corroboration."""
    abuse_str = (
        f"score={abuseipdb_data.get('abuseConfidenceScore', 0)}%, "
        f"totalReports={abuseipdb_data.get('totalReports', 0)}, "
        f"country={abuseipdb_data.get('countryCode', 'Unknown')}, "
        f"isp={abuseipdb_data.get('isp', 'Unknown')}"
        if abuseipdb_data
        else "No AbuseIPDB record or offline fallback"
    )

    vt_str = (
        f"score={virustotal_data.get('score', '0/88 engines')}, "
        f"reputation={virustotal_data.get('reputation', 0)}, "
        f"tags={virustotal_data.get('tags', [])}"
        if virustotal_data
        else "No VirusTotal record or offline fallback"
    )

    return f"""{ENRICHMENT_FEW_SHOT_EXAMPLES}
=== ANALYZE THE FOLLOWING EVENT ===
Event Details:
- event_id: {event.event_id}
- timestamp: {event.timestamp}
- src_ip: {event.src_ip or 'unknown'}
- dst_ip: {event.dst_ip or 'unknown'}
- dst_port: {event.dst_port or 0}
- protocol: {event.protocol or 'unknown'}
- threat_category: {event.threat_category}
- label: {event.label or 'unknown'}
- flow_bytes_per_sec: {event.flow_bytes_per_sec or 0.0}
- flow_packets_per_sec: {event.flow_packets_per_sec or 0.0}

Threat Intelligence Feeds:
- AbuseIPDB Record : {abuse_str}
- VirusTotal Record: {vt_str}

Evaluate these indicators and provide your classification as a single JSON object:"""


def build_investigation_reasoning_prompt(
    event: NormalizedEvent,
    triage_data: Optional[dict[str, Any]] = None,
    mitre_data: Optional[dict[str, Any]] = None,
    enrichment_data: Optional[dict[str, Any]] = None,
) -> str:
    """Build the Chain-of-Thought investigation reasoning prompt."""
    severity = triage_data.get("severity") if triage_data else event.severity
    is_tp = triage_data.get("is_true_positive") if triage_data else event.is_true_positive
    techniques = (
        [t.get("technique_id") if isinstance(t, dict) else str(t) for t in mitre_data.get("techniques", [])]
        if mitre_data
        else event.mitre_techniques
    )
    is_malicious = (
        enrichment_data.get("is_malicious", False)
        if enrichment_data
        else False
    )
    threat_labels = (
        enrichment_data.get("threat_labels", [])
        if enrichment_data
        else []
    )

    return f"""=== SECURITY INCIDENT TELEMETRY ===
Event ID        : {event.event_id}
Timestamp       : {event.timestamp}
Source IP       : {event.src_ip or 'unknown'}
Destination IP  : {event.dst_ip or 'unknown'}
Destination Port: {event.dst_port or 0} ({event.protocol or 'TCP'})
Threat Category : {event.threat_category}
Dataset Label   : {event.label or 'unknown'}

AGENT CONTEXT:
- Triage Assessment       : Severity={severity}, TruePositive={is_tp}
- MITRE ATT&CK Mapping    : Techniques={techniques}
- Threat Intel Enrichment : Malicious={is_malicious}, Labels={threat_labels}

Perform your step-by-step Chain-of-Thought investigation (Steps 1 to 5) and produce the investigation JSON:"""
