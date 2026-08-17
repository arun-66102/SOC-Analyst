-- =============================================================================
-- schema.sql
-- ----------
-- PostgreSQL schema for the SOC Analyst system.
-- Run this once against your Neon PostgreSQL database to initialise tables.
--
-- How to run:
--   psql $NEON_DB_URL -f database/schema.sql
--
-- Author  : Member 1 — Project Lead
-- Phase   : 1
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";    -- uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";      -- trigram indexes for text search

-- ---------------------------------------------------------------------------
-- Enums (mirrors api/models.py enums)
-- ---------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM ('Critical', 'High', 'Medium', 'Low', 'Unknown');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE threat_category AS ENUM (
        'Benign', 'BruteForce', 'DoS', 'DDoS', 'PortScan', 'Infiltration',
        'WebAttack', 'Botnet', 'Malware', 'Exfiltration', 'Backdoor',
        'Reconnaissance', 'Unknown'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE alert_status AS ENUM (
        'new', 'triaged', 'correlated', 'enriched', 'reported',
        'escalated', 'dismissed', 'closed'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------------------------------------------------------------------------
-- alerts — one row per NormalizedEvent
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    -- Identity
    event_id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Network context
    src_ip              INET,
    dst_ip              INET,
    src_port            SMALLINT    CHECK (src_port >= 0 AND src_port <= 65535),
    dst_port            SMALLINT    CHECK (dst_port >= 0 AND dst_port <= 65535),
    protocol            VARCHAR(16),

    -- Flow features (subset — full features stored in raw_payload)
    flow_duration           DOUBLE PRECISION,
    total_fwd_packets       INTEGER,
    total_bwd_packets       INTEGER,
    flow_bytes_per_sec      DOUBLE PRECISION,
    flow_packets_per_sec    DOUBLE PRECISION,

    -- Classification
    label               VARCHAR(64),
    threat_category     threat_category     NOT NULL DEFAULT 'Unknown',
    severity            severity_level      NOT NULL DEFAULT 'Unknown',
    status              alert_status        NOT NULL DEFAULT 'new',

    -- Agent outputs (populated progressively)
    incident_id         UUID,
    mitre_techniques    TEXT[]              NOT NULL DEFAULT '{}',
    is_true_positive    BOOLEAN,
    enrichment_data     JSONB,

    -- Raw payload
    raw_payload         JSONB,
    source_dataset      VARCHAR(32),

    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp       ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity        ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status          ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip          ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id     ON alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_category ON alerts (threat_category);

-- ---------------------------------------------------------------------------
-- incidents — one row per correlated incident group
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    start_time          TIMESTAMPTZ NOT NULL,
    end_time            TIMESTAMPTZ,
    event_count         INTEGER     NOT NULL DEFAULT 1,
    severity            severity_level NOT NULL DEFAULT 'Unknown',
    status              alert_status   NOT NULL DEFAULT 'correlated',
    mitre_techniques    TEXT[]      NOT NULL DEFAULT '{}',
    incident_summary    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_start_time ON incidents (start_time DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents (severity);

-- ---------------------------------------------------------------------------
-- agent_results — stores every AgentResult for traceability
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_results (
    id              BIGSERIAL   PRIMARY KEY,
    run_id          UUID        NOT NULL,
    agent_name      VARCHAR(64) NOT NULL,
    event_id        UUID        NOT NULL REFERENCES alerts(event_id) ON DELETE CASCADE,
    status          VARCHAR(16) NOT NULL DEFAULT 'success',
    error_message   TEXT,
    confidence      DOUBLE PRECISION CHECK (confidence >= 0 AND confidence <= 1),
    reasoning       TEXT,
    output          JSONB,
    latency_ms      DOUBLE PRECISION,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_results_event_id   ON agent_results (event_id);
CREATE INDEX IF NOT EXISTS idx_agent_results_agent_name ON agent_results (agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_results_run_id     ON agent_results (run_id);

-- ---------------------------------------------------------------------------
-- investigation_reports — generated PDF/HTML reports
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_reports (
    report_id       UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id     UUID        NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    report_html     TEXT,
    report_pdf_path VARCHAR(512),
    risk_score      SMALLINT    CHECK (risk_score >= 0 AND risk_score <= 100),
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_incident_id ON investigation_reports (incident_id);

-- ---------------------------------------------------------------------------
-- analyst_actions — audit log of approve/escalate/dismiss actions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analyst_actions (
    id          BIGSERIAL   PRIMARY KEY,
    event_id    UUID        NOT NULL REFERENCES alerts(event_id) ON DELETE CASCADE,
    action      VARCHAR(16) NOT NULL,           -- 'approve' | 'escalate' | 'dismiss'
    comment     TEXT,
    analyst_id  VARCHAR(128),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analyst_actions_event_id ON analyst_actions (event_id);

-- ---------------------------------------------------------------------------
-- updated_at auto-update trigger
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alerts_updated_at   ON alerts;
CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trg_incidents_updated_at ON incidents;
CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
