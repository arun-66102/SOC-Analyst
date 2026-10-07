"""Neon PostgreSQL helpers used by Phase 3 API and pipeline persistence."""
from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator

from dotenv import load_dotenv

load_dotenv()

import psycopg2
import psycopg2.pool

logger = logging.getLogger("database")
DATABASE_URL = os.getenv("NEON_DB_URL", "").strip()
_POOL_MIN_CONN = int(os.getenv("DB_POOL_MIN", "1"))
_POOL_MAX_CONN = int(os.getenv("DB_POOL_MAX", "5"))
_sync_pool: psycopg2.pool.SimpleConnectionPool | None = None
_async_pool = None


def _get_sync_pool() -> psycopg2.pool.SimpleConnectionPool:
    global _sync_pool
    if _sync_pool is None:
        if not DATABASE_URL:
            raise RuntimeError("NEON_DB_URL is not set.")
        _sync_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=_POOL_MIN_CONN, maxconn=_POOL_MAX_CONN, dsn=DATABASE_URL
        )
    return _sync_pool


@contextmanager
def get_db_connection() -> Generator:
    pool = _get_sync_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


async def init_async_pool() -> None:
    global _async_pool
    if not DATABASE_URL:
        return
    import asyncpg
    if _async_pool is None:
        _async_pool = await asyncpg.create_pool(
            dsn=DATABASE_URL, min_size=_POOL_MIN_CONN, max_size=_POOL_MAX_CONN
        )


async def close_async_pool() -> None:
    global _async_pool
    if _async_pool is not None:
        await _async_pool.close()
        _async_pool = None


# Compatibility names used by api/main.py.
async def init_db() -> None:
    await init_async_pool()


async def close_db() -> None:
    await close_async_pool()


@asynccontextmanager
async def get_async_db_connection() -> AsyncGenerator:
    if _async_pool is None:
        raise RuntimeError("Async database pool is not initialised.")
    async with _async_pool.acquire() as conn:
        yield conn


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _json(value: Any) -> Any:
    if value is None:
        return None
    return json.loads(json.dumps(value, default=str))


def persist_pipeline(event, pipeline_run_id: str, results: dict[str, Any]) -> None:
    """Persist the event, incident and every completed AgentResult."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (
                    event_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                    flow_duration, total_fwd_packets, total_bwd_packets,
                    flow_bytes_per_sec, flow_packets_per_sec, label, threat_category,
                    severity, status, incident_id, mitre_techniques, is_true_positive,
                    enrichment_data, raw_payload, source_dataset
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::threat_category,
                          %s::severity_level,%s::alert_status,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (event_id) DO UPDATE SET
                    timestamp=EXCLUDED.timestamp, src_ip=EXCLUDED.src_ip, dst_ip=EXCLUDED.dst_ip,
                    severity=EXCLUDED.severity, status=EXCLUDED.status, incident_id=EXCLUDED.incident_id,
                    mitre_techniques=EXCLUDED.mitre_techniques, is_true_positive=EXCLUDED.is_true_positive,
                    enrichment_data=EXCLUDED.enrichment_data, raw_payload=EXCLUDED.raw_payload,
                    source_dataset=EXCLUDED.source_dataset
                """,
                (
                    event.event_id, event.timestamp, event.src_ip, event.dst_ip,
                    event.src_port, event.dst_port, event.protocol, event.flow_duration,
                    event.total_fwd_packets, event.total_bwd_packets,
                    event.flow_bytes_per_sec, event.flow_packets_per_sec, event.label,
                    _enum_value(event.threat_category), _enum_value(event.severity), _enum_value(event.status),
                    event.incident_id, event.mitre_techniques, event.is_true_positive,
                    _json(event.enrichment_data), _json(event.raw_payload), event.source_dataset,
                ),
            )

            corr = results.get("correlation")
            if corr and corr.status == "success" and event.incident_id:
                out = corr.output or {}
                cur.execute(
                    """
                    INSERT INTO incidents (incident_id,start_time,end_time,event_count,severity,status,mitre_techniques,incident_summary)
                    VALUES (%s,%s,%s,1,%s::severity_level,'correlated'::alert_status,%s,%s)
                    ON CONFLICT (incident_id) DO UPDATE SET
                      end_time=GREATEST(COALESCE(incidents.end_time, EXCLUDED.end_time), EXCLUDED.end_time),
                      event_count=incidents.event_count+1,
                      severity=EXCLUDED.severity,
                      mitre_techniques=EXCLUDED.mitre_techniques,
                      incident_summary=EXCLUDED.incident_summary
                    """,
                    (
                        event.incident_id, event.timestamp, event.timestamp, _enum_value(event.severity),
                        event.mitre_techniques, out.get("incident_summary"),
                    ),
                )

            for result in results.values():
                if not result:
                    continue
                cur.execute(
                    """
                    INSERT INTO agent_results
                    (run_id,agent_name,event_id,status,error_message,confidence,reasoning,output,latency_ms,timestamp)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        result.run_id or pipeline_run_id, result.agent_name or "unknown",
                        event.event_id, result.status, result.error_message, result.confidence,
                        result.reasoning, _json(result.output), result.latency_ms, result.timestamp,
                    ),
                )


def _row_to_event(row: dict) -> dict:
    row["mitre_techniques"] = list(row.get("mitre_techniques") or [])
    return row


def fetch_alerts(severity: str | None, status: str | None, limit: int, offset: int) -> tuple[int, list[dict]]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = %s::severity_level"); params.append(severity)
    if status:
        clauses.append("status = %s::alert_status"); params.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM alerts{where}", params)
        total = cur.fetchone()[0]
        cur.execute(
            f"SELECT event_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flow_duration,total_fwd_packets,total_bwd_packets,flow_bytes_per_sec,flow_packets_per_sec,label,threat_category,severity,status,incident_id,mitre_techniques,is_true_positive,enrichment_data,raw_payload,source_dataset FROM alerts{where} ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        columns = [d[0] for d in cur.description]
        return total, [_row_to_event(dict(zip(columns, r))) for r in cur.fetchall()]


def fetch_alert(alert_id: str) -> dict | None:
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT event_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flow_duration,total_fwd_packets,total_bwd_packets,flow_bytes_per_sec,flow_packets_per_sec,label,threat_category,severity,status,incident_id,mitre_techniques,is_true_positive,enrichment_data,raw_payload,source_dataset FROM alerts WHERE event_id=%s", (alert_id,))
        row = cur.fetchone()
        if not row: return None
        cols = [d[0] for d in cur.description]
        return _row_to_event(dict(zip(cols, row)))


def fetch_incidents() -> list[dict]:
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT incident_id,event_count,severity,start_time,end_time,mitre_techniques,status FROM incidents ORDER BY start_time DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def fetch_stats() -> dict:
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*),
              COUNT(*) FILTER (WHERE severity='Critical'), COUNT(*) FILTER (WHERE severity='High'),
              COUNT(*) FILTER (WHERE severity='Medium'), COUNT(*) FILTER (WHERE severity='Low'),
              COUNT(*) FILTER (WHERE is_true_positive=true), COUNT(*) FILTER (WHERE is_true_positive=false)
            FROM alerts
        """)
        total, critical, high, medium, low, tp, fp = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('correlated','enriched','reported','escalated')")
        active = cur.fetchone()[0]
        cur.execute("SELECT AVG(latency_ms) FROM agent_results WHERE agent_name='TriageAgent' AND status='success'")
        avg = cur.fetchone()[0]
        cur.execute("SELECT technique, COUNT(*) AS count FROM (SELECT unnest(mitre_techniques) AS technique FROM alerts) x GROUP BY technique ORDER BY count DESC LIMIT 10")
        top = [{"technique": r[0], "count": r[1]} for r in cur.fetchall()]
        return dict(total_alerts=total, critical_count=critical, high_count=high, medium_count=medium,
                    low_count=low, true_positives=tp, false_positives=fp,
                    active_incidents=active, avg_triage_latency_ms=float(avg) if avg is not None else None,
                    top_mitre_techniques=top)


def record_analyst_action(alert_id: str, action: str, comment: str | None, analyst_id: str | None) -> None:
    status_map = {"approve": "closed", "escalate": "escalated", "dismiss": "dismissed"}
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO analyst_actions(event_id,action,comment,analyst_id) VALUES(%s,%s,%s,%s)", (alert_id, action, comment, analyst_id))
        cur.execute("UPDATE alerts SET status=%s::alert_status WHERE event_id=%s", (status_map[action], alert_id))


def fetch_report(incident_id: str) -> dict | None:
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT report_id,incident_id,report_html,report_pdf_path,risk_score,generated_at FROM investigation_reports WHERE incident_id=%s ORDER BY generated_at DESC LIMIT 1", (incident_id,))
        row = cur.fetchone()
        if not row: return None
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))


def ping_database() -> dict:
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT version();")
            return {"healthy": True, "db_version": cur.fetchone()[0]}
    except Exception as exc:
        return {"healthy": False, "error": str(exc)}
