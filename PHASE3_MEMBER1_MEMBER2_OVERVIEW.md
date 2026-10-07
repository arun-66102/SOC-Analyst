# Phase 3: Member 1 & Member 2 Complete Overview & Architecture

> **Project:** Agentic AI-Powered Autonomous SOC Analyst  
> **Status:** ✅ Phase 3 (Member 1 & Member 2) Fully Implemented & Verified  
> **Test Suite:** ✅ **232 tests passed, 0 failures** across the entire project  
> **Stack:** Python 3.12 · FastAPI · Groq Cloud LLM · AbuseIPDB API · VirusTotal API · FAISS · Pydantic v2 · Uvicorn  

---

## 🗺️ Architectural Pipeline: Phase 3 Integration

```
                 Incoming Security Event (NormalizedEvent)
                                     │
                                     ▼
           ┌──────────────────────────────────────────────────┐
           │                ORCHESTRATOR PIPELINE             │
           │                                                  │
           │  1. Triage Agent (Phase 2 - Member 1)            │
           │     • Severity: Critical/High/Medium/Low         │
           │     • Verdict: True Positive / False Positive    │
           │                                                  │
           │  2. Correlation Agent (Phase 2 - Member 2)       │
           │     • Sliding time-window + IP matching          │
           │     • Unique incident_id grouping                │
           │                                                  │
           │  3. MITRE Mapping Agent (Phase 2 - Member 3)     │
           │     • ATT&CK Technique embedding similarity      │
           │     • Maps T1110, T1046, T1498, etc.             │
           │                                                  │
           │  4. Threat Intel Enrichment Agent (Phase 3 - M1) │
           │     • RFC1918 Private vs Public IP detection     │
           │     • AbuseIPDB & VirusTotal reputation APIs     │
           │     • RateLimiter (4 req/min) & Backoff retries  │
           │     • Chain-of-Thought (CoT) Investigation       │
           │                                                  │
           │  5. Alert Storage & Persistence (Phase 3 - M2)   │
           │     • Dual-mode: Neon PostgreSQL + AlertStore    │
           │     • Tracks incidents, alerts & audit actions   │
           └──────────────────────────────────────────────────┘
                                     │
                                     ▼
           ┌──────────────────────────────────────────────────┐
           │                FASTAPI REST BACKEND              │
           │                                                  │
           │  • POST /api/analyze         (Pipeline Trigger)  │
           │  • GET  /api/alerts          (Paginated Feed)    │
           │  • GET  /api/alerts/{id}     (Alert Detail)      │
           │  • POST /api/alerts/{id}/action (Analyst Action) │
           │  • GET  /api/incidents       (Incident List)     │
           │  • GET  /api/reports/{id}    (Investigation Rep) │
           │  • GET  /api/stats           (Dashboard Metrics) │
           │  • GET  /health              (Liveness Probes)   │
           │  • /docs                     (Interactive UI)    │
           └──────────────────────────────────────────────────┘
```

---

## 👤 Phase 3 — Member 1: Threat Intelligence Enrichment Agent & Reasoning

### Objective
Enrich each incoming security alert with external cyber threat intelligence (CTI) from VirusTotal and AbuseIPDB, identify internal private IPs, handle API rate limits and network errors with exponential backoff, and conduct step-by-step Chain-of-Thought (CoT) investigation reasoning to synthesize adversary hypotheses and containment guidance.

### Files Delivered
- [`agents/enrichment_agent.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/agents/enrichment_agent.py)
- [`agents/prompts/enrichment_prompts.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/agents/prompts/enrichment_prompts.py)
- [`tests/test_enrichment.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/tests/test_enrichment.py)

### Technical Implementations & Features

1. **RFC1918 & Local IP Filtering**
   - Implements strict CIDR evaluation against private address allocations:
     - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`.
   - Prevents sending internal LAN queries to external threat databases.
   - Automatically labels internal traffic as `["Internal Network", "RFC1918 Private IP"]` with `is_malicious=False`.

2. **AbuseIPDB Integration**
   - Endpoint: `https://api.abuseipdb.com/api/v2/check`
   - Queries IP abuse reports within the last 90 days.
   - Parses `abuseConfidenceScore` (0–100%), total reports, usage type, country code, and ISP.
   - Automatically flags IPs with confidence scores $\ge 25\%$ as malicious.

3. **VirusTotal Integration & Sliding-Window Rate Limiter**
   - Endpoint: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
   - Enforces the VirusTotal Free Tier limit of **4 requests per minute** using an asynchronous sliding-window `RateLimiter`.
   - Calculates the engine detection ratio (e.g. `14/88 engines`) and extracts community reputation and tags.

4. **Exponential Backoff and Retries**
   - Protects against transient HTTP network errors (429 Rate Limited, 500, 502, 503, 504).
   - Retries up to 3 attempts with exponential delay backoff ($0.5s \rightarrow 1.0s \rightarrow 2.0s$).

5. **In-Memory Cache (TTL: 3600s)**
   - Caches enrichment outputs per IP address.
   - Identical IPs processed within the correlation time window reuse the cached reputation, eliminating redundant API consumption.

6. **Deterministic Heuristic Offline Mode**
   - If API keys are not present in `.env` or external networks are unavailable, activates an offline threat reputation matrix.
   - Accurately classifies attack signatures (`BruteForce`, `DDoS`, `PortScan`, `Botnet`, `WebAttack`, etc.) with realistic confidence scores, allowing 100% offline testing.

7. **Chain-of-Thought (CoT) Investigation Reasoning Engine**
   - Synthesizes all agent outputs into a structured 5-step investigative narrative:
     - **Step 1: Telemetry Assessment** (packet rates, port, protocol, flow duration)
     - **Step 2: MITRE ATT&CK Context** (adversary tactic & technique cross-reference)
     - **Step 3: Threat Intelligence Corroboration** (AbuseIPDB + VirusTotal reputation)
     - **Step 4: Attack Hypothesis & Blast Radius** (adversary goal & targeted assets)
     - **Step 5: Containment & Remediation** (firewall drop rules, credential rotation)

---

## 👤 Phase 3 — Member 2: Agent Orchestrator & FastAPI Backend

### Objective
Wire the complete multi-agent pipeline into an end-to-end controller, build persistent data storage (with Neon PostgreSQL and in-memory fail-safe), implement all REST API endpoints for alerts, actions, incidents, reports, and statistics, and provide interactive Swagger UI and Postman documentation.

### Files Delivered
- [`agents/orchestrator.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/agents/orchestrator.py)
- [`database/store.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/database/store.py)
- [`database/db.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/database/db.py) (init_db/close_db aliases)
- [`api/routes/alerts.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/api/routes/alerts.py)
- [`api/routes/agents.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/api/routes/agents.py)
- [`api/routes/reports.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/api/routes/reports.py)
- [`api/main.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/api/main.py) (MITREAgent health check mapping)
- [`postman_collection.json`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/postman_collection.json)
- [`tests/test_orchestrator.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/tests/test_orchestrator.py)
- [`tests/test_api.py`](file:///d:/KPR/FINAL%20YEAR%20PROJECT/SOC-Analyst/tests/test_api.py)

### Technical Implementations & Features

1. **Auto-Registering Pipeline Orchestrator**
   - Automatically initializes and wires:
     - `TriageAgent` (Stage 1)
     - `CorrelationAgent` (Stage 2)
     - `MITREAgent` (Stage 3)
     - `EnrichmentAgent` (Stage 4)
     - `ReportAgent` (Stage 5)
   - Supports both `run_pipeline(event)` (synchronous) and `run_pipeline_async(event)` (asynchronous for FastAPI).
   - Measures end-to-end pipeline latency in milliseconds.
   - Automatically saves each analyzed alert and its results into the persistence store.

2. **Dual-Layer Persistence (`AlertStore`)**
   - Thread-safe repository supporting concurrent read/write operations.
   - Writes to Neon PostgreSQL when `NEON_DB_URL` is set, with an immediate, crash-resilient in-memory fallback.
   - Automatically pre-seeds with representative security scenarios on startup if empty, so the dashboard and API always have data ready to inspect.

3. **Complete REST Endpoints**

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | `GET` | System liveness probe + health status of all registered agents |
| `/api/analyze` | `POST` | Submits a `NormalizedEvent` to trigger the multi-agent pipeline |
| `/api/alerts` | `GET` | Paginated alert feed with filtering by severity, status, and category |
| `/api/alerts/{alert_id}` | `GET` | Fetches a single alert with complete multi-agent analysis |
| `/api/alerts/{alert_id}/action` | `POST` | Records analyst decision (`approve`, `escalate`, `dismiss`, `close`) and updates status |
| `/api/incidents` | `GET` | Lists correlated multi-event incident summaries |
| `/api/reports/{incident_id}` | `GET` | Fetches or dynamically compiles executive & technical incident reports |
| `/api/stats` | `GET` | Computes live dashboard metrics (severity distribution, active incidents, top MITRE techniques) |
| `/docs` | `GET` | Interactive OpenAPI Swagger UI documentation |

4. **Postman Collection (`postman_collection.json`)**
   - Full Postman v2.1.0 schema with pre-configured request samples, environment variables (`baseUrl`, `alert_id`, `incident_id`), and response test scripts.

---

## 🧪 Verification & Test Results

The test suite was run with `pytest` on Python 3.12:

```bash
python -m pytest
```

### Result:
```text
======================= 232 passed, 2 warnings in 4.40s =======================
```

### Breakdown by Module:
1. `tests/test_enrichment.py` — **20 passed** (Rate limiter, private IPs, AbuseIPDB, VirusTotal, retries, caching, heuristics, CoT reasoning, health check)
2. `tests/test_orchestrator.py` — **6 passed** (Auto-registration, health polling, sync pipeline, async pipeline, persistence, stage skipping)
3. `tests/test_api.py` — **13 passed** (Health check, /analyze, /alerts filtering & pagination, analyst action, /incidents, /stats, /reports)
4. `tests/test_triage.py` — **20 passed** (Heuristics, prompt construction, JSON parsing, result schemas)
5. `tests/test_correlation.py` — **21 passed** (Sliding time window, event embeddings, incident generation)
6. `tests/test_mitre.py` — **21 passed** (ATT&CK technique search, top-K selection, confidence calculation)
7. `tests/test_normalizer.py` — **42 passed** (CICIDS2017 & UNSW-NB15 normalization, label mappings)
8. `tests/test_log_generator.py` — **46 passed** (Synthetic event creation across 12 attack vectors)
9. `tests/test_dataset_loader.py` — **43 passed** (CSV ingestion and sample batching)

---

## 🚀 How to Run the Backend Locally

### 1. Launch FastAPI Backend
```bash
uvicorn api.main:app --reload --port 8000
```
- API Base: `http://localhost:8000`
- Interactive Swagger UI Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

### 2. Import into Postman
1. Open Postman.
2. Click **Import** $\rightarrow$ select `postman_collection.json`.
3. Set the `baseUrl` variable to `http://localhost:8000`.
4. Run requests to analyze alerts, view incidents, and review generated reports!
