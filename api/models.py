"""Pydantic schemas shared across the SOC Analyst system."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


LLM_PROVIDER = "groq"


class ThreatCategory(str, Enum):
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
    NEW = "new"
    TRIAGED = "triaged"
    CORRELATED = "correlated"
    ENRICHED = "enriched"
    REPORTED = "reported"
    ESCALATED = "escalated"
    DISMISSED = "dismissed"
    CLOSED = "closed"


class AnalystAction(str, Enum):
    APPROVE = "approve"
    ESCALATE = "escalate"
    DISMISS = "dismiss"


class NormalizedEvent(BaseModel):
    event_id: str = Field(description="Unique event identifier (UUID v4).")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    flow_duration: Optional[float] = None
    total_fwd_packets: Optional[int] = None
    total_bwd_packets: Optional[int] = None
    total_length_fwd_packets: Optional[float] = None
    total_length_bwd_packets: Optional[float] = None
    flow_bytes_per_sec: Optional[float] = None
    flow_packets_per_sec: Optional[float] = None
    label: Optional[str] = None
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    status: AlertStatus = AlertStatus.NEW
    incident_id: Optional[str] = None
    correlation_summary: Optional[str] = None
    mitre_techniques: list[str] = Field(default_factory=list)
    is_true_positive: Optional[bool] = None
    enrichment_data: Optional[dict[str, Any]] = None
    raw_payload: Optional[dict[str, Any]] = None
    source_dataset: Optional[str] = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    class Config:
        use_enum_values = True
        json_encoders = {datetime: lambda dt: dt.isoformat()}


class AgentResult(BaseModel):
    run_id: Optional[str] = None
    agent_name: Optional[str] = None
    event_id: str
    status: str = "success"
    error_message: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    reasoning: Optional[str] = None
    output: Optional[dict[str, Any]] = None
    latency_ms: Optional[float] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TriageOutput(BaseModel):
    severity: SeverityLevel
    is_true_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: Optional[str] = None


class CorrelationOutput(BaseModel):
    incident_id: str
    related_event_ids: list[str]
    time_window_seconds: float
    similarity_score: Optional[float] = None
    incident_summary: Optional[str] = None


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    description: Optional[str] = None


class MITREOutput(BaseModel):
    techniques: list[MITRETechnique]
    llm_reasoning: Optional[str] = None


class EnrichmentOutput(BaseModel):
    ip_address: Optional[str] = None
    is_malicious: bool = False
    threat_labels: list[str] = Field(default_factory=list)
    virustotal_score: Optional[str] = None
    abuseipdb_score: Optional[int] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationOutput(BaseModel):
    summary: str
    evidence: list[str] = Field(default_factory=list)
    risk_level: SeverityLevel = SeverityLevel.UNKNOWN
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AnalyzeRequest(BaseModel):
    event: NormalizedEvent


class AnalyzeResponse(BaseModel):
    event_id: str
    pipeline_run_id: str
    triage: Optional[AgentResult] = None
    correlation: Optional[AgentResult] = None
    mitre: Optional[AgentResult] = None
    enrichment: Optional[AgentResult] = None
    investigation: Optional[AgentResult] = None
    report: Optional[AgentResult] = None
    total_latency_ms: Optional[float] = None


class AlertListResponse(BaseModel):
    total: int
    alerts: list[NormalizedEvent]


class IncidentSummary(BaseModel):
    incident_id: str
    event_count: int
    severity: SeverityLevel
    start_time: datetime
    end_time: Optional[datetime] = None
    mitre_techniques: list[str] = Field(default_factory=list)
    status: AlertStatus


class DashboardStats(BaseModel):
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
    action: AnalystAction
    comment: Optional[str] = None
    analyst_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    agents: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
