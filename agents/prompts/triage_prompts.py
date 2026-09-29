"""
agents/prompts/triage_prompts.py
---------------------------------
Prompt templates and few-shot examples for the Alert Triage Agent.

The Triage Agent uses these to instruct the LLM (Groq) to classify
each incoming security event as:
  - Severity  : Critical / High / Medium / Low
  - Verdict   : True Positive / False Positive
  - Reasoning : 2-3 sentence explanation
  - Action    : Recommended response action

Author  : Member 1 — Phase 2
"""

# ---------------------------------------------------------------------------
# System prompt — sets the LLM persona and output contract
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst with 10+ years of experience triaging cybersecurity alerts.

Your job is to analyze incoming network security events and:
1. Classify the SEVERITY level as one of: Critical, High, Medium, Low
2. Determine if the event is a TRUE POSITIVE or FALSE POSITIVE
3. Provide a confidence score between 0.0 and 1.0
4. Explain your reasoning in 2-3 sentences
5. Recommend an immediate action

SEVERITY GUIDELINES:
- Critical : Active breach, data exfiltration in progress, ransomware, C2 communication confirmed
- High     : Brute force attacks (sustained), port scans on critical ports, confirmed malware indicators
- Medium   : Suspicious traffic patterns, unusual protocols, moderate scan activity
- Low      : Informational anomalies, single failed login, known benign scanner traffic

FALSE POSITIVE INDICATORS:
- Traffic from known internal scanners (e.g., Nessus, Qualys)
- Automated backup or monitoring traffic
- Very low packet counts with benign port destinations
- BENIGN label from dataset with no suspicious indicators

You MUST respond ONLY with a valid JSON object. No extra text before or after.
JSON format:
{
  "severity": "Critical|High|Medium|Low",
  "is_true_positive": true|false,
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation",
  "recommended_action": "Specific action to take"
}"""


# ---------------------------------------------------------------------------
# Few-shot examples embedded in the user prompt
# ---------------------------------------------------------------------------

FEW_SHOT_EXAMPLES = """
=== EXAMPLES ===

EXAMPLE 1 - DDoS Attack:
Event: src_ip=203.0.113.45, dst_port=80, protocol=TCP, flow_bytes_per_sec=2500000.0,
       flow_packets_per_sec=45000.0, total_fwd_packets=12000, total_bwd_packets=50,
       label=DDoS, threat_category=DDoS, flow_duration=5000000
Response:
{
  "severity": "Critical",
  "is_true_positive": true,
  "confidence": 0.97,
  "reasoning": "Extremely high packet rate (45,000 pkt/s) with minimal backward traffic (50 packets) strongly indicates a volumetric DDoS flood targeting port 80. The 50:1 forward-to-backward packet ratio is a definitive DDoS signature. Immediate mitigation is required.",
  "recommended_action": "Block source IP at perimeter firewall. Activate DDoS mitigation. Alert network team immediately."
}

EXAMPLE 2 - Brute Force SSH:
Event: src_ip=198.51.100.22, dst_port=22, protocol=TCP, flow_bytes_per_sec=1200.0,
       flow_packets_per_sec=8.5, total_fwd_packets=320, total_bwd_packets=310,
       label=SSH-Patator, threat_category=BruteForce, flow_duration=180000000
Response:
{
  "severity": "High",
  "is_true_positive": true,
  "confidence": 0.91,
  "reasoning": "Sustained SSH traffic (320 forward, 310 backward packets) over 180 seconds to port 22 is consistent with automated SSH brute-force using Patator or similar tool. The near-equal packet ratio suggests repeated authentication handshakes. Account lockout and IP block are required.",
  "recommended_action": "Block source IP. Enable SSH account lockout. Review auth logs for compromised accounts."
}

EXAMPLE 3 - Benign Traffic:
Event: src_ip=10.0.0.15, dst_port=443, protocol=TCP, flow_bytes_per_sec=85000.0,
       flow_packets_per_sec=62.0, total_fwd_packets=450, total_bwd_packets=420,
       label=BENIGN, threat_category=Benign, flow_duration=60000000
Response:
{
  "severity": "Low",
  "is_true_positive": false,
  "confidence": 0.95,
  "reasoning": "Normal HTTPS traffic with balanced forward/backward packet ratio (450:420) at reasonable rates. Internal source IP (10.0.0.15) with benign label and typical web browsing traffic pattern. No suspicious indicators present.",
  "recommended_action": "No action required. Log for baseline traffic profiling."
}

EXAMPLE 4 - Port Scan:
Event: src_ip=172.16.0.99, dst_port=0, protocol=TCP, flow_bytes_per_sec=340.0,
       flow_packets_per_sec=125.0, total_fwd_packets=890, total_bwd_packets=12,
       label=PortScan, threat_category=PortScan, flow_duration=42000000
Response:
{
  "severity": "High",
  "is_true_positive": true,
  "confidence": 0.89,
  "reasoning": "Very high forward packet count (890) with minimal responses (12 backward packets) across a short duration indicates systematic port scanning. The 74:1 packet ratio is a classic SYN-scan signature. The source is an internal IP which may indicate lateral movement post-compromise.",
  "recommended_action": "Investigate host 172.16.0.99 immediately. Check for unauthorized software. Isolate if compromise confirmed."
}

EXAMPLE 5 - Data Exfiltration:
Event: src_ip=10.10.5.44, dst_ip=45.77.65.211, dst_port=443, protocol=TCP,
       flow_bytes_per_sec=95000.0, flow_packets_per_sec=22.0,
       total_length_fwd_packets=850000, total_length_bwd_packets=1200,
       label=Infiltration, threat_category=Infiltration, flow_duration=90000000
Response:
{
  "severity": "Critical",
  "is_true_positive": true,
  "confidence": 0.93,
  "reasoning": "Internal host transferring 850KB outbound to an external IP (45.77.65.211) with only 1.2KB inbound is a strong exfiltration indicator. The asymmetric data ratio (708:1 outbound) combined with HTTPS port usage to evade detection matches infiltration signatures. Immediate containment required.",
  "recommended_action": "Isolate source host immediately. Block external IP. Capture packet dump. Initiate IR playbook for data breach."
}

=== END EXAMPLES ===
"""


# ---------------------------------------------------------------------------
# Main prompt builder
# ---------------------------------------------------------------------------

def build_triage_prompt(event) -> str:
    """
    Build the full user prompt for the Triage Agent.

    Parameters
    ----------
    event : NormalizedEvent
        The security event to triage.

    Returns
    -------
    str
        The complete prompt string to send to the LLM.
    """
    event_summary = f"""
SECURITY EVENT TO ANALYZE:
===========================
Event ID        : {event.event_id}
Source IP       : {event.src_ip or 'Unknown'}
Destination IP  : {event.dst_ip or 'Unknown'}
Source Port     : {event.src_port or 'Unknown'}
Destination Port: {event.dst_port or 'Unknown'}
Protocol        : {event.protocol or 'Unknown'}
Threat Category : {event.threat_category}
Dataset Label   : {event.label or 'Unknown'}

Network Flow Metrics:
  Flow Duration         : {event.flow_duration or 'N/A'} microseconds
  Total Fwd Packets     : {event.total_fwd_packets or 'N/A'}
  Total Bwd Packets     : {event.total_bwd_packets or 'N/A'}
  Fwd Payload Bytes     : {event.total_length_fwd_packets or 'N/A'}
  Bwd Payload Bytes     : {event.total_length_bwd_packets or 'N/A'}
  Flow Bytes/sec        : {event.flow_bytes_per_sec or 'N/A'}
  Flow Packets/sec      : {event.flow_packets_per_sec or 'N/A'}
"""

    if event.enrichment_data:
        event_summary += f"\nThreat Intel Enrichment:\n  {event.enrichment_data}\n"

    return FEW_SHOT_EXAMPLES + event_summary + "\nAnalyze the above event and respond with ONLY the JSON object:"
