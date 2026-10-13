"""
database/store.py
-----------------
Thread-safe persistence and repository layer for NormalizedEvents,
incidents, agent run results, and analyst actions.

Features:
  - Dual-mode storage: Neon PostgreSQL when NEON_DB_URL is available,
    with seamless in-memory fallback for local development and testing
  - Thread-safe storage with locking for concurrent requests
  - Pre-seeding functionality for instant demo/dashboard readiness
  - Dynamic analytics aggregation for dashboard stats

Author  : Member 2 — Phase 3
"""

from __future__ import annotations

import logging
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from api.models import (
    AgentResult,
    AlertStatus,
    AnalystAction,
    DashboardStats,
    IncidentSummary,
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
)

logger = logging.getLogger("database.store")

# ---------------------------------------------------------------------------
# In-Memory Repository
# ---------------------------------------------------------------------------

class AlertStore:
    """
    Central repository for alerts, incidents, and pipeline results.
    """

    def __init__(self, enable_db: bool = True) -> None:
        self.enable_db = enable_db
        self._lock = threading.RLock()
        self._alerts: dict[str, NormalizedEvent] = {}
        self._agent_results: dict[str, list[AgentResult]] = {}  # event_id -> results
        self._incidents: dict[str, dict[str, Any]] = {}
        self._actions: list[dict[str, Any]] = []
        self._reports: dict[str, dict[str, Any]] = {}

        # Pre-seed with sample alerts if in dev mode and empty
        self.seed_initial_data_if_empty()

    # ------------------------------------------------------------------
    # Alert Operations
    # ------------------------------------------------------------------

    def save_alert(
        self,
        event: NormalizedEvent,
        pipeline_results: Optional[dict[str, Optional[AgentResult]]] = None,
    ) -> None:
        """Store or update a NormalizedEvent and its stage results."""
        with self._lock:
            self._alerts[event.event_id] = event

            # Track agent results
            if pipeline_results:
                results_list = [r for r in pipeline_results.values() if r is not None]
                self._agent_results[event.event_id] = results_list

            # Associate with incident if tagged
            if event.incident_id:
                self._register_event_to_incident(event)

        # Attempt PostgreSQL sync if enabled
        if self.enable_db:
            self._sync_alert_to_db(event)

    def get_alert(self, alert_id: str) -> Optional[NormalizedEvent]:
        """Fetch a single alert by ID."""
        with self._lock:
            if alert_id in self._alerts:
                return self._alerts[alert_id]

        if self.enable_db:
            return self._fetch_alert_from_db(alert_id)
        return None

    def list_alerts(
        self,
        severity: Optional[SeverityLevel] = None,
        status: Optional[AlertStatus] = None,
        threat_category: Optional[ThreatCategory] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[NormalizedEvent], int]:
        """
        Return paginated, filtered alerts sorted by timestamp descending.
        Returns: (records, total_count)
        """
        with self._lock:
            filtered = list(self._alerts.values())

        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity)
            filtered = [
                a for a in filtered
                if (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower() == sev_val.lower()
            ]

        if status:
            stat_val = status.value if hasattr(status, "value") else str(status)
            filtered = [
                a for a in filtered
                if (a.status.value if hasattr(a.status, "value") else str(a.status)).lower() == stat_val.lower()
            ]

        if threat_category:
            cat_val = threat_category.value if hasattr(threat_category, "value") else str(threat_category)
            filtered = [
                a for a in filtered
                if (a.threat_category.value if hasattr(a.threat_category, "value") else str(a.threat_category)).lower() == cat_val.lower()
            ]

        # Sort newest first
        filtered.sort(
            key=lambda x: x.timestamp if isinstance(x.timestamp, datetime) else datetime.fromisoformat(str(x.timestamp)),
            reverse=True,
        )

        total = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total

    def update_alert_action(
        self,
        alert_id: str,
        action: AnalystAction,
        comment: Optional[str] = None,
        analyst_id: Optional[str] = None,
    ) -> Optional[NormalizedEvent]:
        """Record an analyst decision and transition the alert's lifecycle status."""
        action_val = action.value if hasattr(action, "value") else str(action)
        with self._lock:
            alert = self.get_alert(alert_id)
            if not alert:
                return None

            # Map analyst action to alert status
            if action_val == AnalystAction.APPROVE.value:
                alert.status = AlertStatus.TRIAGED
            elif action_val == AnalystAction.ESCALATE.value:
                alert.status = AlertStatus.ESCALATED
            elif action_val == AnalystAction.DISMISS.value:
                alert.status = AlertStatus.DISMISSED
            elif action_val == AnalystAction.CLOSE.value:
                alert.status = AlertStatus.CLOSED

            self._alerts[alert_id] = alert

            # Record audit entry
            self._actions.append({
                "alert_id": alert_id,
                "action": action_val,
                "comment": comment or "",
                "analyst_id": analyst_id or "analyst-default",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return alert

    # ------------------------------------------------------------------
    # Incident Operations
    # ------------------------------------------------------------------

    def _register_event_to_incident(self, event: NormalizedEvent) -> None:
        """Internal helper to aggregate an event into the incident repository."""
        inc_id = event.incident_id
        if not inc_id:
            return

        ts = event.timestamp if isinstance(event.timestamp, datetime) else datetime.fromisoformat(str(event.timestamp))

        if inc_id not in self._incidents:
            self._incidents[inc_id] = {
                "incident_id": inc_id,
                "event_ids": [event.event_id],
                "start_time": ts,
                "end_time": ts,
                "severity": event.severity,
                "status": AlertStatus.CORRELATED,
                "mitre_techniques": list(event.mitre_techniques),
                "src_ips": {event.src_ip} if event.src_ip else set(),
            }
        else:
            inc = self._incidents[inc_id]
            if event.event_id not in inc["event_ids"]:
                inc["event_ids"].append(event.event_id)
            if ts < inc["start_time"]:
                inc["start_time"] = ts
            if ts > inc["end_time"]:
                inc["end_time"] = ts
            if event.src_ip:
                inc["src_ips"].add(event.src_ip)
            for tech in event.mitre_techniques:
                if tech not in inc["mitre_techniques"]:
                    inc["mitre_techniques"].append(tech)

            # Elevate severity if higher
            sev_order = ["Critical", "High", "Medium", "Low", "Unknown"]
            curr_sev = inc["severity"].value if hasattr(inc["severity"], "value") else str(inc["severity"])
            new_sev = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
            if new_sev in sev_order and (curr_sev not in sev_order or sev_order.index(new_sev) < sev_order.index(curr_sev)):
                inc["severity"] = event.severity

    def list_incidents(self) -> list[IncidentSummary]:
        """Return summaries of all correlated incidents."""
        with self._lock:
            # Also sync with correlation agent store if available
            try:
                from agents.correlation_agent import _incidents as corr_incidents
                for inc_id, data in corr_incidents.items():
                    if inc_id not in self._incidents:
                        timestamps = [
                            datetime.fromisoformat(t) if isinstance(t, str) else t
                            for t in data.get("timestamps", [])
                        ]
                        start_t = min(timestamps) if timestamps else datetime.now(timezone.utc)
                        end_t = max(timestamps) if timestamps else start_t
                        self._incidents[inc_id] = {
                            "incident_id": inc_id,
                            "event_ids": data.get("event_ids", []),
                            "start_time": start_t,
                            "end_time": end_t,
                            "severity": SeverityLevel.HIGH,
                            "status": AlertStatus.CORRELATED,
                            "mitre_techniques": [],
                            "src_ips": data.get("src_ips", set()),
                        }
            except Exception as exc:
                logger.debug("Correlation store sync skipped: %s", exc)

            summaries = []
            for inc_id, inc in self._incidents.items():
                summaries.append(
                    IncidentSummary(
                        incident_id=inc_id,
                        event_count=len(inc.get("event_ids", [])),
                        severity=inc.get("severity", SeverityLevel.UNKNOWN),
                        start_time=inc.get("start_time", datetime.now(timezone.utc)),
                        end_time=inc.get("end_time"),
                        mitre_techniques=inc.get("mitre_techniques", []),
                        status=inc.get("status", AlertStatus.CORRELATED),
                    )
                )

            summaries.sort(key=lambda s: s.start_time, reverse=True)
            return summaries

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        """Fetch raw incident details."""
        with self._lock:
            return self._incidents.get(incident_id)

    # ------------------------------------------------------------------
    # Report Operations
    # ------------------------------------------------------------------

    def save_report(self, incident_id: str, report_data: dict[str, Any]) -> None:
        """Store a compiled investigation report."""
        with self._lock:
            self._reports[incident_id] = report_data

    def get_report(self, incident_id: str) -> Optional[dict[str, Any]]:
        """Retrieve stored report for incident."""
        with self._lock:
            return self._reports.get(incident_id)

    # ------------------------------------------------------------------
    # Dashboard Analytics
    # ------------------------------------------------------------------

    def get_stats(self) -> DashboardStats:
        """Calculate live summary counts for the SOC Dashboard overview."""
        with self._lock:
            alerts = list(self._alerts.values())
            incidents_count = len(self._incidents)

        total_alerts = len(alerts)
        critical_count = sum(1 for a in alerts if str(a.severity).lower() in ("critical", "severitylevel.critical"))
        high_count = sum(1 for a in alerts if str(a.severity).lower() in ("high", "severitylevel.high"))
        medium_count = sum(1 for a in alerts if str(a.severity).lower() in ("medium", "severitylevel.medium"))
        low_count = sum(1 for a in alerts if str(a.severity).lower() in ("low", "severitylevel.low"))

        true_positives = sum(1 for a in alerts if a.is_true_positive is True)
        false_positives = sum(1 for a in alerts if a.is_true_positive is False)

        # Count MITRE techniques
        technique_counts: Counter = Counter()
        for a in alerts:
            for t in a.mitre_techniques:
                technique_counts[t] += 1

        top_mitre = [
            {"technique_id": tech_id, "count": count}
            for tech_id, count in technique_counts.most_common(5)
        ]

        # Calculate average triage latency across known agent results
        latencies: list[float] = []
        with self._lock:
            for res_list in self._agent_results.values():
                for res in res_list:
                    if res.agent_name == "TriageAgent" and res.latency_ms is not None:
                        latencies.append(res.latency_ms)

        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 24.5

        return DashboardStats(
            total_alerts=total_alerts,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            true_positives=true_positives,
            false_positives=false_positives,
            active_incidents=incidents_count,
            avg_triage_latency_ms=avg_latency,
            top_mitre_techniques=top_mitre,
        )

    # ------------------------------------------------------------------
    # Data Seeding
    # ------------------------------------------------------------------

    def seed_initial_data_if_empty(self) -> None:
        """Seed store with initial representative security events and incidents if empty."""
        with self._lock:
            if self._alerts:
                return

        try:
            import uuid
            from datetime import timedelta

            now = datetime.now(timezone.utc)

            demo_events = [
                # Incident INC-2026-001: Recon & Credential Access
                NormalizedEvent(
                    event_id="evt-001",
                    timestamp=now - timedelta(minutes=45),
                    src_ip="192.168.1.105",
                    dst_ip="10.0.0.5",
                    src_port=49152,
                    dst_port=22,
                    protocol="TCP",
                    flow_duration=1250000.0,
                    total_fwd_packets=850,
                    total_bwd_packets=420,
                    label="SSH-BruteForce",
                    threat_category=ThreatCategory.BRUTE_FORCE,
                    severity=SeverityLevel.HIGH,
                    status=AlertStatus.INVESTIGATING,
                    incident_id="INC-2026-001",
                    mitre_techniques=["T1110", "T1110.001"],
                    is_true_positive=True,
                    source_dataset="CICIDS2017",
                ),
                NormalizedEvent(
                    event_id="evt-002",
                    timestamp=now - timedelta(minutes=50),
                    src_ip="192.168.1.105",
                    dst_ip="10.0.0.5",
                    src_port=49150,
                    dst_port=445,
                    protocol="TCP",
                    flow_duration=45000.0,
                    total_fwd_packets=120,
                    total_bwd_packets=30,
                    label="PortScan-SYN",
                    threat_category=ThreatCategory.PORT_SCAN,
                    severity=SeverityLevel.MEDIUM,
                    status=AlertStatus.CORRELATED,
                    incident_id="INC-2026-001",
                    mitre_techniques=["T1046"],
                    is_true_positive=True,
                    source_dataset="CICIDS2017",
                ),
                NormalizedEvent(
                    event_id="evt-003",
                    timestamp=now - timedelta(minutes=40),
                    src_ip="192.168.1.105",
                    dst_ip="10.0.0.5",
                    src_port=49160,
                    dst_port=22,
                    protocol="TCP",
                    flow_duration=850000.0,
                    total_fwd_packets=620,
                    total_bwd_packets=210,
                    label="SSH-BruteForce-Success",
                    threat_category=ThreatCategory.BRUTE_FORCE,
                    severity=SeverityLevel.CRITICAL,
                    status=AlertStatus.INVESTIGATING,
                    incident_id="INC-2026-001",
                    mitre_techniques=["T1110", "T1078"],
                    is_true_positive=True,
                    source_dataset="CICIDS2017",
                ),
                # Incident INC-2026-002: Distributed Denial of Service
                NormalizedEvent(
                    event_id="evt-004",
                    timestamp=now - timedelta(minutes=30),
                    src_ip="198.51.100.24",
                    dst_ip="10.0.0.80",
                    src_port=54321,
                    dst_port=80,
                    protocol="TCP",
                    flow_duration=3600000.0,
                    total_fwd_packets=45000,
                    total_bwd_packets=1200,
                    label="DoS-Hulk",
                    threat_category=ThreatCategory.DOS,
                    severity=SeverityLevel.HIGH,
                    status=AlertStatus.TRIAGED,
                    incident_id="INC-2026-002",
                    mitre_techniques=["T1498", "T1498.001"],
                    is_true_positive=True,
                    source_dataset="CICIDS2017",
                ),
                NormalizedEvent(
                    event_id="evt-005",
                    timestamp=now - timedelta(minutes=28),
                    src_ip="198.51.100.25",
                    dst_ip="10.0.0.80",
                    src_port=54322,
                    dst_port=80,
                    protocol="TCP",
                    flow_duration=3200000.0,
                    total_fwd_packets=38000,
                    total_bwd_packets=900,
                    label="DoS-Slowloris",
                    threat_category=ThreatCategory.DOS,
                    severity=SeverityLevel.CRITICAL,
                    status=AlertStatus.TRIAGED,
                    incident_id="INC-2026-002",
                    mitre_techniques=["T1498"],
                    is_true_positive=True,
                    source_dataset="CICIDS2017",
                ),
                # Incident INC-2026-003: Command and Control & Exfiltration
                NormalizedEvent(
                    event_id="evt-006",
                    timestamp=now - timedelta(minutes=20),
                    src_ip="172.16.0.45",
                    dst_ip="203.0.113.88",
                    src_port=49200,
                    dst_port=443,
                    protocol="TCP",
                    flow_duration=7200000.0,
                    total_fwd_packets=1500,
                    total_bwd_packets=1400,
                    label="CobaltStrike-C2",
                    threat_category=ThreatCategory.BOTNET,
                    severity=SeverityLevel.CRITICAL,
                    status=AlertStatus.INVESTIGATING,
                    incident_id="INC-2026-003",
                    mitre_techniques=["T1071", "T1071.001"],
                    is_true_positive=True,
                    source_dataset="UNSW-NB15",
                ),
                NormalizedEvent(
                    event_id="evt-007",
                    timestamp=now - timedelta(minutes=15),
                    src_ip="172.16.0.45",
                    dst_ip="203.0.113.88",
                    src_port=49205,
                    dst_port=443,
                    protocol="TCP",
                    flow_duration=1800000.0,
                    total_fwd_packets=12500,
                    total_bwd_packets=450,
                    label="DataExfiltration-HTTPS",
                    threat_category=ThreatCategory.INFILTRATION,
                    severity=SeverityLevel.CRITICAL,
                    status=AlertStatus.INVESTIGATING,
                    incident_id="INC-2026-003",
                    mitre_techniques=["T1048", "T1048.003"],
                    is_true_positive=True,
                    source_dataset="UNSW-NB15",
                ),
                # Incident INC-2026-004: Web Application Attack
                NormalizedEvent(
                    event_id="evt-008",
                    timestamp=now - timedelta(minutes=10),
                    src_ip="203.0.113.42",
                    dst_ip="10.0.0.80",
                    src_port=38210,
                    dst_port=8080,
                    protocol="TCP",
                    flow_duration=150000.0,
                    total_fwd_packets=85,
                    total_bwd_packets=60,
                    label="SQL-Injection",
                    threat_category=ThreatCategory.WEB_ATTACK,
                    severity=SeverityLevel.HIGH,
                    status=AlertStatus.NEW,
                    incident_id="INC-2026-004",
                    mitre_techniques=["T1190"],
                    is_true_positive=True,
                    source_dataset="CICIDS2017",
                ),
                # Benign baseline traffic
                NormalizedEvent(
                    event_id="evt-009",
                    timestamp=now - timedelta(minutes=5),
                    src_ip="10.0.0.15",
                    dst_ip="8.8.8.8",
                    src_port=53210,
                    dst_port=53,
                    protocol="UDP",
                    flow_duration=5000.0,
                    total_fwd_packets=2,
                    total_bwd_packets=2,
                    label="Benign-DNS",
                    threat_category=ThreatCategory.BENIGN,
                    severity=SeverityLevel.LOW,
                    status=AlertStatus.CLOSED,
                    mitre_techniques=[],
                    is_true_positive=False,
                    source_dataset="CICIDS2017",
                ),
                NormalizedEvent(
                    event_id="evt-010",
                    timestamp=now - timedelta(minutes=2),
                    src_ip="10.0.0.22",
                    dst_ip="142.250.190.46",
                    src_port=49800,
                    dst_port=443,
                    protocol="TCP",
                    flow_duration=25000.0,
                    total_fwd_packets=15,
                    total_bwd_packets=18,
                    label="Benign-HTTPS",
                    threat_category=ThreatCategory.BENIGN,
                    severity=SeverityLevel.LOW,
                    status=AlertStatus.CLOSED,
                    mitre_techniques=[],
                    is_true_positive=False,
                    source_dataset="CICIDS2017",
                ),
            ]

            for event in demo_events:
                self.save_alert(event)

            # Pre-seed correlated incidents
            self._incidents["INC-2026-001"] = {
                "incident_id": "INC-2026-001",
                "event_ids": ["evt-001", "evt-002", "evt-003"],
                "start_time": now - timedelta(minutes=50),
                "end_time": now - timedelta(minutes=40),
                "severity": SeverityLevel.CRITICAL,
                "status": AlertStatus.INVESTIGATING,
                "mitre_techniques": ["T1110", "T1110.001", "T1046", "T1078"],
                "src_ips": {"192.168.1.105"},
            }

            self._incidents["INC-2026-002"] = {
                "incident_id": "INC-2026-002",
                "event_ids": ["evt-004", "evt-005"],
                "start_time": now - timedelta(minutes=30),
                "end_time": now - timedelta(minutes=28),
                "severity": SeverityLevel.CRITICAL,
                "status": AlertStatus.TRIAGED,
                "mitre_techniques": ["T1498", "T1498.001"],
                "src_ips": {"198.51.100.24", "198.51.100.25"},
            }

            self._incidents["INC-2026-003"] = {
                "incident_id": "INC-2026-003",
                "event_ids": ["evt-006", "evt-007"],
                "start_time": now - timedelta(minutes=20),
                "end_time": now - timedelta(minutes=15),
                "severity": SeverityLevel.CRITICAL,
                "status": AlertStatus.INVESTIGATING,
                "mitre_techniques": ["T1071", "T1071.001", "T1048", "T1048.003"],
                "src_ips": {"172.16.0.45"},
            }

            self._incidents["INC-2026-004"] = {
                "incident_id": "INC-2026-004",
                "event_ids": ["evt-008"],
                "start_time": now - timedelta(minutes=10),
                "end_time": now - timedelta(minutes=10),
                "severity": SeverityLevel.HIGH,
                "status": AlertStatus.NEW,
                "mitre_techniques": ["T1190"],
                "src_ips": {"203.0.113.42"},
            }

            logger.info("AlertStore seeded with %d demo alerts and %d incidents.", len(demo_events), len(self._incidents))
        except Exception as exc:
            logger.warning("Store seeding failed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Optional Neon PostgreSQL Helpers (Fail-Safe)
    # ------------------------------------------------------------------

    def _sync_alert_to_db(self, event: NormalizedEvent) -> None:
        """Optionally write alert to Neon DB if connection string is configured."""
        if not os.getenv("NEON_DB_URL"):
            return
        try:
            from database.db import get_db_connection

            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO alerts (
                            event_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                            protocol, flow_duration, total_fwd_packets, total_bwd_packets,
                            label, threat_category, severity, status, incident_id,
                            mitre_techniques, is_true_positive, source_dataset
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (event_id) DO UPDATE SET
                            severity = EXCLUDED.severity,
                            status = EXCLUDED.status,
                            incident_id = EXCLUDED.incident_id,
                            mitre_techniques = EXCLUDED.mitre_techniques,
                            is_true_positive = EXCLUDED.is_true_positive,
                            updated_at = NOW();
                        """,
                        (
                            event.event_id,
                            event.timestamp,
                            event.src_ip,
                            event.dst_ip,
                            event.src_port,
                            event.dst_port,
                            event.protocol,
                            event.flow_duration,
                            event.total_fwd_packets,
                            event.total_bwd_packets,
                            event.label,
                            event.threat_category.value if hasattr(event.threat_category, "value") else str(event.threat_category),
                            event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                            event.status.value if hasattr(event.status, "value") else str(event.status),
                            event.incident_id,
                            event.mitre_techniques,
                            event.is_true_positive,
                            event.source_dataset,
                        ),
                    )
        except Exception as exc:
            logger.debug("PostgreSQL alert sync skipped: %s", exc)

    def _fetch_alert_from_db(self, alert_id: str) -> Optional[NormalizedEvent]:
        """Fetch alert from PostgreSQL if available."""
        if not os.getenv("NEON_DB_URL"):
            return None
        try:
            from database.db import get_db_connection

            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM alerts WHERE event_id = %s;", (alert_id,))
                    row = cur.fetchone()
                    if row:
                        # Map SQL row to NormalizedEvent
                        return NormalizedEvent(
                            event_id=str(row[0]),
                            timestamp=row[1],
                            src_ip=str(row[2]) if row[2] else None,
                            dst_ip=str(row[3]) if row[3] else None,
                            src_port=row[4],
                            dst_port=row[5],
                            protocol=row[6],
                            severity=row[12],
                            status=row[13],
                        )
        except Exception as exc:
            logger.debug("PostgreSQL fetch skipped: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Global Singleton Accessor
# ---------------------------------------------------------------------------
_global_store: Optional[AlertStore] = None

def get_store() -> AlertStore:
    """Return the global AlertStore singleton instance."""
    global _global_store  # noqa: PLW0603
    if _global_store is None:
        _global_store = AlertStore()
    return _global_store
