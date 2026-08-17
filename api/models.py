"""
models.py
---------
Pydantic schemas shared across the entire SOC Analyst system.

This module defines the canonical data structures that flow between:
  - The ingestion pipeline  (raw logs → NormalizedEvent)
  - All AI agents           (NormalizedEvent → AgentResult / specialised outputs)
  - The FastAPI REST API    (request / response bodies)
  - The PostgreSQL database (persisted records)

Author  : Member 1 — Project Lead  (schema owner)
          Member 3 — API skeleton   (adds route-specific models)
Phase   : 1
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ===========================================================================
# Enumerations
# ===========================================================================


class SeverityLevel(str, Enum):
    """Alert severity levels — used by the Triage Agent."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


# LLM provider is Groq Cloud — configured via GROQ_API_KEY / GROQ_MODEL in .env
LLM_PROVIDER = "groq"


class ThreatCategory(str, Enum):
    """Top-level attack category labels derived from CICIDS2017 / UNSW-NB15."""
    BENIGN = "Benign"
    BRUTE_FORCE = "BruteForce"
    DOS = "DoS"
    DDOS = "DDoS"
    PORT_SCAN = "PortScan"
    INFILTRATION = "Infiltration"
    WEB_ATTACK = "WebAttack"
    BOTNET = "Botnet"
    MALWARE = "Malware"
    EXFILTRATION = "Exfiltration"
    BACKDOOR = "Backdoor"
    RECONNAISSANCE = "Reconnaissance"
    UNKNOWN = "Unknown"


class AlertStatus(str, Enum):
    """Lifecycle status of an alert as tracked in the database."""
    NEW = "new"
    TRIAGED = "triaged"
    CORRELATED = "correlated"
    ENRICHED = "enriched"
    REPORTED = "reported"
    ESCALATED = "escalated"
    DISMISSED = "dismissed"
    CLOSED = "closed"


class AnalystAction(str, Enum):
    """Actions an analyst can take on an alert from the dashboard."""
    APPROVE = "approve"
    ESCALATE = "escalate"
    DISMISS = "dismiss"


# ===========================================================================
# Core event schema — the universal format all agents consume
# ===========================================================================


class NormalizedEvent(BaseModel):
    """
    Canonical security event format shared by ALL components.

    Raw dataset rows (CICIDS2017 / UNSW-NB15) and synthetic log entries
    are converted into this schema by ``ingestion/normalizer.py`` before
    being passed to any agent.
    """

    # ------ Identity -------------------------------------------------------
    event_id: str = Field(
        description="Unique event identifier (UUID v4)."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event occurrence time (UTC).",
    )

    # ------ Network context ------------------------------------------------
    src_ip: Optional[str] = Field(None, description="Source IP address.")
    dst_ip: Optional[str] = Field(None, description="Destination IP address.")
    src_port: Optional[int] = Field(None, ge=0, le=65535, description="Source port.")
    dst_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination port.")
    protocol: Optional[str] = Field(None, description="Network protocol (TCP/UDP/ICMP …).")

    # ------ Flow / traffic features ----------------------------------------
    flow_duration: Optional[float] = Field(None, description="Flow duration in microseconds.")
    total_fwd_packets: Optional[int] = Field(None, description="Total forward packets.")
    total_bwd_packets: Optional[int] = Field(None, description="Total backward packets.")
    total_length_fwd_packets: Optional[float] = Field(None)
    total_length_bwd_packets: Optional[float] = Field(None)
    flow_bytes_per_sec: Optional[float] = Field(None)
    flow_packets_per_sec: Optional[float] = Field(None)

    # ------ Classification -------------------------------------------------
    label: Optional[str] = Field(
        None,
        description="Ground-truth attack label from the dataset (e.g. 'DDoS', 'BENIGN').",
    )
    threat_category: ThreatCategory = Field(
        default=ThreatCategory.UNKNOWN,
        description="Normalised threat category enum.",
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.UNKNOWN,
        description="Alert severity — initially UNKNOWN, set by Triage Agent.",
    )
    status: AlertStatus = Field(
        default=AlertStatus.NEW,
        description="Alert lifecycle status.",
    )

    # ------ Agent outputs (populated progressively) -----------------------
    incident_id: Optional[str] = Field(
        None, description="Set by Correlation Agent when event is grouped into an incident."
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. ['T1110', 'T1046']).",
    )
    is_true_positive: Optional[bool] = Field(
        None, description="Triage Agent's true/false positive verdict."
    )
    enrichment_data: Optional[dict[str, Any]] = Field(
        None, description="Threat intel enrichment results (VirusTotal / AbuseIPDB)."
    )

    # ------ Raw payload ----------------------------------------------------
    raw_payload: Optional[dict[str, Any]] = Field(
        None,
        description="Original unmodified row from the source dataset or log generator.",
    )
    source_dataset: Optional[str] = Field(
        None,
        description="Source of this event: 'cicids2017' | 'unsw_nb15' | 'synthetic'.",
    )

    # ------ Validators -----------------------------------------------------
    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    class Config:
        use_enum_values = True
        json_encoders = {datetime: lambda dt: dt.isoformat()}


# ===========================================================================
# Agent result schema
# ===========================================================================


class AgentResult(BaseModel):
    """
    Standardised output container returned by every agent's `run()` method.

    The orchestrator collects AgentResult objects from each stage of the
    pipeline and persists them to PostgreSQL.
    """

    run_id: Optional[str] = Field(None, description="Unique identifier for this agent run.")
    agent_name: Optional[str] = Field(None, description="Name of the agent that produced this result.")
    event_id: str = Field(description="ID of the NormalizedEvent that was processed.")
    status: str = Field(default="success", description="'success' or 'error'.")
    error_message: Optional[str] = Field(None, description="Populated when status='error'.")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Agent confidence score [0,1].")
    reasoning: Optional[str] = Field(None, description="Free-text explanation / CoT reasoning from the LLM.")
    output: Optional[dict[str, Any]] = Field(
        None, description="Agent-specific structured output (varies per agent type)."
    )
    latency_ms: Optional[float] = Field(None, description="Agent processing time in milliseconds.")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of when this result was produced.",
    )


# ===========================================================================
# Triage-specific output
# ===========================================================================


class TriageOutput(BaseModel):
    """Structured output from the Triage Agent (stored in AgentResult.output)."""
    severity: SeverityLevel
    is_true_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: Optional[str] = None


# ===========================================================================
# Correlation-specific output
# ===========================================================================


class CorrelationOutput(BaseModel):
    """Structured output from the Correlation Agent."""
    incident_id: str
    related_event_ids: list[str]
    time_window_seconds: float
    similarity_score: Optional[float] = None
    incident_summary: Optional[str] = None


# ===========================================================================
# MITRE ATT&CK mapping output
# ===========================================================================


class MITRETechnique(BaseModel):
    """A single MITRE ATT&CK technique match."""
    technique_id: str = Field(description="e.g. 'T1110'")
    technique_name: str = Field(description="e.g. 'Brute Force'")
    tactic: str = Field(description="ATT&CK tactic (e.g. 'Credential Access')")
    confidence: float = Field(ge=0.0, le=1.0)
    description: Optional[str] = None


class MITREOutput(BaseModel):
    """Structured output from the MITRE Mapping Agent."""
    techniques: list[MITRETechnique]
    llm_reasoning: Optional[str] = None


# ===========================================================================
# Enrichment output
# ===========================================================================


class EnrichmentOutput(BaseModel):
    """Structured output from the Enrichment Agent."""
    ip_address: Optional[str] = None
    is_malicious: bool = False
    threat_labels: list[str] = Field(default_factory=list)
    virustotal_score: Optional[str] = None   # e.g. "5/89 engines"
    abuseipdb_score: Optional[int] = None    # abuse confidence % [0,100]
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)


# ===========================================================================
# FastAPI request / response models
# ===========================================================================


class AnalyzeRequest(BaseModel):
    """POST /api/analyze — trigger the agent pipeline on a raw event."""
    event: NormalizedEvent


class AnalyzeResponse(BaseModel):
    """Response body returned by POST /api/analyze."""
    event_id: str
    pipeline_run_id: str
    triage: Optional[AgentResult] = None
    correlation: Optional[AgentResult] = None
    mitre: Optional[AgentResult] = None
    enrichment: Optional[AgentResult] = None
    report: Optional[AgentResult] = None
    total_latency_ms: Optional[float] = None


class AlertListResponse(BaseModel):
    """Response body for GET /api/alerts."""
    total: int
    alerts: list[NormalizedEvent]


class IncidentSummary(BaseModel):
    """Lightweight incident summary for GET /api/incidents."""
    incident_id: str
    event_count: int
    severity: SeverityLevel
    start_time: datetime
    end_time: Optional[datetime] = None
    mitre_techniques: list[str] = Field(default_factory=list)
    status: AlertStatus


class DashboardStats(BaseModel):
    """Response body for GET /api/stats — powers the dashboard overview."""
    total_alerts: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    true_positives: int
    false_positives: int
    active_incidents: int
    avg_triage_latency_ms: Optional[float] = None
    top_mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)


class AnalystActionRequest(BaseModel):
    """POST /api/alerts/{id}/action — analyst approve/escalate/dismiss."""
    action: AnalystAction
    comment: Optional[str] = None
    analyst_id: Optional[str] = None


class HealthResponse(BaseModel):
    """Response body for GET /health."""
    status: str = "ok"
    version: str
    agents: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
