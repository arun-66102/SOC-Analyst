# Agentic AI-Powered Autonomous SOC Analyst — Implementation Plan

**Scope:** College Final Year Research Prototype

| | |
|---|---|
| Project | Agentic AI-Powered SOC Analyst |
| Team Size | 4 Members |
| Methodology | Agile (Phase-based Delivery) |
| Total Phases | 4 |
| Progress | Phase 1 (25%) to Phase 4 (100%) |
| Stack | Python, FastAPI, React, Gemini API, Public Datasets, Vercel |

---

## 1. Project Overview

This project builds an Agentic AI-powered SOC Analyst prototype that autonomously triages security alerts, correlates events, maps threats to the MITRE ATT&CK framework, and generates investigation reports — all without requiring a real enterprise SIEM. Instead, it ingests public cybersecurity datasets (CICIDS2017, UNSW-NB15, MITRE ATT&CK STIX) and simulated log data. Four specialized AI agents (Triage, Correlation, MITRE Mapping, and Report Generation) are powered by the Google Gemini API / OpenAI API, orchestrated by a central controller, and visualized through a React-based SOC Dashboard.

**Academic Framing:** "A Multi-Agent LLM Framework for Autonomous Alert Triage and MITRE ATT&CK Mapping in SOC Environments" — suitable for IEEE / ICACCI paper submission.

---

## 2. Roadmap at a Glance

| Phase | Theme | Completion | Key Deliverables |
|---|---|---|---|
| Phase 1 | Environment, Data & Base Framework | 25% | Project scaffold, datasets, base agent class, synthetic log generator |
| Phase 2 | Core AI Agents | 50% | Triage Agent, Correlation Agent, MITRE Mapping Agent |
| Phase 3 | Intelligence Layer & API | 75% | Enrichment Agent, Report Agent, FastAPI backend, agent pipeline |
| Phase 4 | SOC Dashboard & Submission | 100% | React dashboard, testing, paper, demo video |

---

## 3. Enterprise to College Scope Mapping

| Enterprise Plan (Dropped) | College Prototype (Replaced With) |
|---|---|
| Kafka / RabbitMQ streaming | In-memory Python queue / JSON file input |
| Splunk / CrowdStrike / EDR connectors | Public datasets: CICIDS2017, UNSW-NB15 |
| Kubernetes + cloud deployment | Vercel (frontend + backend serverless via vercel.json) |
| Fine-tuned / self-hosted LLM | Gemini 1.5 Flash API or OpenAI GPT-4o API |
| Neo4j entity knowledge graph | NetworkX + matplotlib graph visualization |
| SOAR platform integration | Mock playbook recommendations (JSON rules) |
| HashiCorp Vault secrets manager | Vercel Environment Variables (dashboard secrets) |
| AWS / Azure / GCP cloud | Vercel free tier (frontend + API) + Neon free PostgreSQL |
| Elasticsearch + PostgreSQL | Neon free PostgreSQL + FAISS (vector store) |
| WebSocket real-time streaming | REST API polling (5-second refresh) |

---

## 4. Public Datasets (No Real SIEM Needed)

| Dataset | Use Case | Link |
|---|---|---|
| CICIDS 2017 | Network intrusion detection logs | https://www.unb.ca/cic/datasets/ids-2017.html |
| UNSW-NB15 | Multi-category attack dataset | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| MITRE ATT&CK STIX 2.1 | Threat technique mappings | https://github.com/mitre/cti |
| Elastic Detection Rules | Real-world SIEM alert rules | https://github.com/elastic/detection-rules |
| Synthetic Log Generator | Built in Phase 1 by Member 4 | Custom script |

---

## 5. Tech Stack (College Edition)

| Category | Tool / Library |
|---|---|
| AI / LLM | Google Gemini 1.5 Flash API or OpenAI GPT-4o API |
| Agent Framework | Custom Python base class |
| Data Processing | Pandas, NumPy, Scikit-learn |
| NLP / Embeddings | sentence-transformers, FAISS |
| Backend API | FastAPI + Uvicorn (serverless on Vercel) |
| Frontend | React.js + Recharts + Tailwind CSS (deployed on Vercel) |
| Database | Neon free PostgreSQL + FAISS (vector search) |
| Graph Visualization | NetworkX + Pyvis |
| Threat Intel | VirusTotal Free API, AbuseIPDB Free API |
| Deployment | Vercel (free tier) + vercel.json config |
| Testing | pytest |
| Report Generation | ReportLab (PDF) or Jinja2 (HTML) |

---

## 6. Project Folder Structure

```
SOC-Analyst/
├── agents/
│   ├── base_agent.py
│   ├── triage_agent.py
│   ├── correlation_agent.py
│   ├── mitre_agent.py
│   ├── enrichment_agent.py
│   ├── report_agent.py
│   └── orchestrator.py
├── ingestion/
│   ├── dataset_loader.py
│   ├── normalizer.py
│   └── log_generator.py
├── data/
│   ├── cicids2017/
│   ├── unsw_nb15/
│   ├── mitre_stix/
│   └── processed/
├── api/
│   ├── main.py
│   ├── routes/
│   │   ├── alerts.py
│   │   ├── agents.py
│   │   └── reports.py
│   └── models.py
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── App.jsx
│   └── package.json
├── database/
│   ├── db.py            # Neon PostgreSQL connection (psycopg2)
│   └── schema.sql
├── tests/
│   ├── test_triage.py
│   ├── test_correlation.py
│   └── test_mitre.py
├── notebooks/
├── paper/
├── vercel.json            # Vercel deployment config (routes frontend + backend)
├── requirements.txt
├── .env.example            # All API keys documented (set as Vercel Env Vars in prod)
└── README.md
```

---

## 7. Phase 1 — Environment, Data & Base Framework

**Overall Project Completion: 25%**

Goal: Set up the project, load and normalize public datasets, build the base agent class, and create the synthetic log generator.

### 7.1 Member 1 — Project Lead & Base Agent Framework

**Responsibilities:**
- Scaffold the full project directory structure
- Write the abstract BaseAgent class — defines `process()`, `health_check()`, and `log()` methods
- Define the NormalizedEvent Pydantic schema — unified log format all agents share
- Write the `orchestrator.py` skeleton — routes events to agents
- Set up Neon free PostgreSQL database — create project at neon.tech, copy the connection string into `.env`
- Configure `.env` / `.env.example` for API keys (Groq / VirusTotal / AbuseIPDB / Neon DB URL)
- Write `vercel.json` to route `/api/*` to FastAPI and `/*` to the React frontend
- Build `agents/llm_client.py` — unified Groq Cloud client with task-specific model selection

**Deliverables:**
- [x] Full project folder scaffold
- [x] `base_agent.py` — abstract agent class
- [x] NormalizedEvent Pydantic schema (`api/models.py`)
- [x] Neon PostgreSQL schema and `db.py` connection module (psycopg2 / asyncpg)
- [x] `vercel.json` — Vercel routing configuration
- [x] `.env.example` with all required keys documented
- [x] `agents/llm_client.py` — Groq Cloud client with `GroqTask` enum (task-specific models)
- [x] `requirements.txt` — all Python dependencies
- [x] `orchestrator.py` — full pipeline skeleton (5 agent slots)
- [x] All agent placeholder stubs (`triage`, `correlation`, `mitre`, `enrichment`, `report`)

### 7.2 Member 2 — Dataset Loading & Normalization Pipeline

**Responsibilities:**
- Download CICIDS 2017 and UNSW-NB15 datasets and store in `data/`
- Write `dataset_loader.py` to load CSV files using Pandas
- Write `normalizer.py` to convert raw dataset rows into NormalizedEvent schema
- Download and parse MITRE ATT&CK STIX 2.1 JSON files — extract technique IDs, names, descriptions, and tactics into `techniques.json`
- Write a Jupyter notebook for exploratory data analysis (EDA)

**Deliverables:**
- [ ] `dataset_loader.py` — loads CICIDS2017 + UNSW-NB15 CSVs
- [ ] `normalizer.py` — maps raw columns to NormalizedEvent
- [ ] `data/mitre_stix/techniques.json` — parsed ATT&CK technique lookup table
- [ ] `notebooks/eda.ipynb` — EDA notebook with charts

### 7.3 Member 3 — Vercel Setup & API Skeleton

**Responsibilities:**
- Write `vercel.json` to route all `/api/*` requests to FastAPI serverless functions and `/*` to the React frontend
- Write `api/main.py` — FastAPI app with CORS, health-check endpoint, and route registration
- Define all Pydantic request/response models for the API
- Set up FAISS as the vector store for semantic alert similarity search
- Connect FastAPI to Neon PostgreSQL using psycopg2 / asyncpg
- Write `requirements.txt` with all Python dependencies
- Set up local dev script (`run_dev.sh` / `run_dev.bat`) that starts FastAPI + React locally without Docker

**vercel.json Structure:**

```json
{
  "version": 2,
  "builds": [
    { "src": "api/main.py", "use": "@vercel/python" },
    { "src": "frontend/package.json", "use": "@vercel/static-build", "config": { "distDir": "dist" } }
  ],
  "routes": [
    { "src": "/api/(.*)", "dest": "api/main.py" },
    { "src": "/(.*)", "dest": "frontend/dist/$1" }
  ]
}
```

**Deliverables:**
- [x] `vercel.json` — complete Vercel routing configuration
- [x] `api/main.py` — FastAPI skeleton with `/health` endpoint
- [x] `api/models.py` — all Pydantic schemas
- [x] FAISS index initialization script (`ingestion/faiss_store.py`)
- [x] `requirements.txt`
- [x] `run_dev.bat` / `run_dev.sh` — local dev startup script (no Docker needed)

### 7.4 Member 4 — Synthetic Log Generator & Testing Setup

**Responsibilities:**
- Build `ingestion/log_generator.py` — generates realistic fake security events (brute-force, port scan, data exfiltration, malware C2) as NormalizedEvent JSON
- Configure pytest with fixtures and sample test data
- Write sample unit tests for the normalizer and loader modules
- Set up GitHub repository with `.gitignore`, branch strategy, and README

**Deliverables:**
- [x] `log_generator.py` — generates 1000+ synthetic events across 12 attack types
- [x] `tests/` — pytest setup (`pytest.ini`, `conftest.py`) + 3 test modules (`test_log_generator.py`, `test_normalizer.py`, `test_dataset_loader.py`)
- [x] GitHub repo with README, `.gitignore`, and branch strategy documented

---

## 8. Phase 2 — Core AI Agents

**Overall Project Completion: 50%**

Goal: Build and test the three core AI agents: Alert Triage, Log Correlation, and MITRE ATT&CK Mapping.

### 8.1 Member 1 — Alert Triage Agent

**What it does:** Classifies each incoming security event as Critical / High / Medium / Low severity and decides if it is a true positive or likely false positive.

**How it works:**
- Takes a NormalizedEvent as input
- Sends structured prompt to Gemini API with event details and few-shot examples
- Returns severity level, confidence score, and reasoning text
- Saves result to Neon PostgreSQL

**Prompt Strategy:** "You are a SOC analyst. Analyze the following security event and classify it. Event: {event details}. Classify severity as Critical / High / Medium / Low. Is this a True Positive or False Positive? Explain your reasoning in 2-3 sentences."

**Deliverables:**
- [ ] `agents/triage_agent.py` — full triage agent implementation
- [ ] Prompt templates in `agents/prompts/triage_prompts.py`
- [ ] `tests/test_triage.py` — unit tests with 5 labeled events
- [ ] Accuracy report: tested on 100 labeled CICIDS2017 events

### 8.2 Member 2 — Log Correlation Engine

**What it does:** Groups multiple related security events into a single incident by detecting temporal patterns and semantic similarity.

**How it works:**
- Sliding time-window algorithm: groups events within a configurable window (e.g. 5 min) from the same source IP
- Uses sentence-transformers embeddings stored in a FAISS index to find semantically similar past alerts
- Assigns a unique `incident_id` to correlated event groups
- Asks Gemini to write a one-paragraph summary of the correlated incident

**Deliverables:**
- [ ] `agents/correlation_agent.py` — time-window + semantic correlation
- [ ] FAISS index + embedding pipeline for alert similarity
- [ ] `tests/test_correlation.py` — unit tests
- [ ] Correlation report: tested on CICIDS2017 multi-step attack scenarios

### 8.3 Member 3 — MITRE ATT&CK Mapping Agent

**What it does:** Maps each security event or incident to one or more MITRE ATT&CK techniques (e.g. T1110 Brute Force, T1046 Network Service Discovery).

**How it works:**
- Uses the parsed `techniques.json` from Phase 1
- Embeds technique descriptions using sentence-transformers
- Computes cosine similarity between event description and all technique embeddings
- Returns the top 3 matching techniques with confidence scores
- Optionally asks Gemini to confirm / refine the mapping with reasoning

**Deliverables:**
- [ ] `agents/mitre_agent.py` — embedding-based + LLM-confirmed MITRE mapping
- [ ] Pre-computed embeddings for all 700+ ATT&CK techniques stored in a FAISS flat index
- [ ] `tests/test_mitre.py` — unit tests with known attack-technique pairs
- [ ] Precision/recall evaluation on 50 labeled test cases

### 8.4 Member 4 — Agent Evaluation & Visualization Prototype

**Responsibilities:**
- Build a simple Streamlit prototype to visualize triage, correlation, and MITRE mapping outputs during development
- Design the evaluation dataset — label 200 events from CICIDS2017 with correct severity and ATT&CK technique
- Run accuracy benchmarks for all 3 agents and document results in a table
- Maintain sprint documentation and update README with Phase 2 architecture

**Deliverables:**
- [ ] Streamlit dev visualization tool
- [ ] 200-event labeled evaluation dataset (`data/eval_dataset.csv`)
- [ ] Benchmark results table (accuracy, precision, recall for each agent)
- [ ] Updated README and Phase 2 wiki notes

---

## 9. Phase 3 — Intelligence Layer & API

**Overall Project Completion: 75%**

Goal: Add threat enrichment, investigation reasoning, report generation, and expose the full agent pipeline through a FastAPI REST API.

### 9.1 Member 1 — Threat Intelligence Enrichment Agent & Reasoning

**Enrichment Agent:**
- Takes IPs, domains, and file hashes from a NormalizedEvent
- Queries VirusTotal Free API and AbuseIPDB Free API for threat reputation data
- Returns enriched event with `is_malicious`, `confidence`, and `threat_labels` fields
- Implements rate limiting (VirusTotal free = 4 requests/min)

**Investigation Reasoning:**
- Takes the full correlated incident (triage + MITRE mapping + enrichment data)
- Sends to Gemini with a Chain-of-Thought prompt asking it to reason step-by-step
- Generates a structured investigation narrative

**Deliverables:**
- [ ] `agents/enrichment_agent.py` — VirusTotal + AbuseIPDB integration
- [ ] Rate limiter and retry logic for API calls
- [ ] Chain-of-Thought investigation reasoning prompt + output parser
- [ ] `tests/test_enrichment.py`

### 9.2 Member 2 — Agent Orchestrator & FastAPI Backend

**Orchestrator:** Runs the full pipeline: Load Event → Triage Agent → Correlation Agent → MITRE Agent → Enrichment Agent → Report Agent

**FastAPI Endpoints:**
- `GET /api/alerts` — list all normalized events
- `GET /api/alerts/{id}` — get single alert with all agent outputs
- `POST /api/analyze` — trigger full agent pipeline on a new event
- `GET /api/incidents` — list correlated incidents
- `GET /api/reports/{incident_id}` — get investigation report
- `GET /api/stats` — dashboard summary stats

**Deliverables:**
- [ ] `agents/orchestrator.py` — full end-to-end pipeline
- [ ] All FastAPI routes implemented and tested
- [ ] Swagger UI auto-documentation at `/docs`
- [ ] Postman collection for all endpoints

### 9.3 Member 3 — Report Generation Agent

**Report Sections:**
1. Executive Summary (non-technical, business impact)
2. Technical Analysis (event timeline, attack chain)
3. ATT&CK Techniques Identified
4. Indicators of Compromise (IOCs) — IPs, hashes, domains
5. Risk Score (calculated from severity + enrichment confidence)
6. Recommended Response Actions (mock playbook suggestions)

**Deliverables:**
- [ ] `agents/report_agent.py`
- [ ] Jinja2 HTML report template (`templates/report.html`)
- [ ] PDF export using ReportLab or WeasyPrint
- [ ] Sample report generated from CICIDS2017 test incident

### 9.4 Member 4 — Testing, Performance & Phase 4 Planning

**Responsibilities:**
- Write integration tests that run the full pipeline end-to-end on 10 test events
- Measure and document pipeline latency per agent (average response time per event)
- Define acceptance criteria for the SOC dashboard (Phase 4)
- Prepare the research paper outline

**Deliverables:**
- [ ] End-to-end integration test suite (`tests/test_pipeline.py`)
- [ ] Pipeline latency benchmark report
- [ ] Phase 4 dashboard wireframes
- [ ] Research paper outline (1-2 pages)

---

## 10. Phase 4 — SOC Dashboard & Submission

**Overall Project Completion: 100%**

Goal: Build the React SOC Dashboard, finalize testing, write the research paper, and prepare the demo.

### 10.1 Member 1 — SOC Dashboard Lead (React Frontend)

**Dashboard Pages:**
1. Overview Page — live alert feed, severity pie chart, active incidents count
2. Alert Detail Page — single alert with triage result, MITRE tags, enrichment data, reasoning narrative
3. Incidents Page — list of correlated incidents with timeline view
4. MITRE ATT&CK Page — heatmap showing which techniques were detected
5. Reports Page — download generated PDF/HTML investigation reports
6. Analyst Action Panel — Approve / Escalate / Dismiss alert with comment

**Tech:** React + Recharts + Tailwind CSS + Axios

**Deliverables:**
- [ ] React dashboard with all 5 pages
- [ ] Real-time polling from FastAPI (5-sec refresh on alert feed)
- [ ] Severity color-coded alert cards (Critical=Red, High=Orange, Medium=Yellow, Low=Green)
- [ ] MITRE ATT&CK heatmap grid
- [ ] Report download button
- [ ] Analyst approve/dismiss action with comment saved to DB

### 10.2 Member 2 — Full System Testing & Vercel Deployment

**Responsibilities:**
- Run full QA test pass across all agents and dashboard
- Deploy the React frontend to Vercel — connect GitHub repo, set environment variables in Vercel dashboard
- Deploy the FastAPI backend as Vercel serverless functions via `vercel.json`
- Verify all environment variables are set correctly in Vercel dashboard (Gemini key, Neon DB URL, VirusTotal key, AbuseIPDB key)
- Fix all integration bugs found during QA
- Write the user manual — how to set up and run the system locally and how to deploy to Vercel

**Vercel Deployment Steps:**
1. Push code to GitHub
2. Go to vercel.com → Import Project → Select GitHub repo
3. Add all environment variables from `.env.example` in Vercel dashboard
4. Vercel auto-detects `vercel.json` and builds frontend + backend
5. Get live public URL — share it in the paper and demo video

**Deliverables:**
- [ ] Live Vercel deployment URL (e.g. soc-analyst.vercel.app)
- [ ] All environment variables configured in Vercel dashboard
- [ ] QA test report (all endpoints, all agents, all dashboard pages)
- [ ] Bug fix log
- [ ] `SETUP.md` — local dev guide + Vercel deployment guide

### 10.3 Member 3 — Research Paper Writing

**Paper Title (Suggested):** MAS-SOC: A Multi-Agent LLM System for Autonomous Alert Triage and MITRE ATT&CK Mapping in Security Operations

**Paper Sections:**
1. Abstract
2. Introduction — problem statement, SOC analyst workload challenge
3. Related Work — existing SIEM tools, AI in cybersecurity, LLM agents
4. System Architecture — agent design, pipeline diagram, data flow
5. Methodology — dataset, agent prompts, evaluation setup
6. Results — accuracy tables, MITRE mapping precision/recall, latency
7. Conclusion and Future Work

**Target Venues:** IEEE ICACCI, ICCCS, or Computers & Security journal

**Deliverables:**
- [ ] Full paper draft (6-8 pages, IEEE format)
- [ ] Architecture diagram (draw.io / Mermaid)
- [ ] Results tables and charts from Phase 2 and Phase 3 benchmarks
- [ ] Submission-ready PDF

### 10.4 Member 4 — Demo Video & Presentation

**Responsibilities:**
- Record a 5-minute demo video showing:
  1. Ingesting a synthetic attack scenario
  2. Triage Agent classifying the alert
  3. MITRE Mapping Agent tagging techniques
  4. Investigation Report being generated
  5. SOC Dashboard displaying everything
- Prepare a 15-slide presentation deck for college evaluation
- Coordinate team demo rehearsal

**Deliverables:**
- [ ] 5-minute demo video (MP4)
- [ ] 15-slide presentation (PowerPoint / Google Slides)
- [ ] Live demo script and Q&A preparation notes

---

## 11. Revised Key Milestones

| Milestone | Phase | What It Means |
|---|---|---|
| Datasets loaded + Base agent working | Phase 1 | Data pipeline ready |
| 3 core agents functional | Phase 2 | Core AI working |
| Full pipeline via API | Phase 3 | End-to-end operational |
| Dashboard live + Paper submitted | Phase 4 | Project complete |

---

## 12. Evaluation Metrics (For Paper)

| Agent | Metric | Target |
|---|---|---|
| Triage Agent | Accuracy (vs. labeled dataset) | > 85% |
| Correlation Agent | Incident grouping F1-score | > 80% |
| MITRE Mapping Agent | Top-3 Precision | > 75% |
| Enrichment Agent | API success rate | > 95% |
| Full Pipeline | Avg. latency per event | < 10 seconds |

---

## 13. Important Notes

**API Costs:** Gemini 1.5 Flash API has a free tier (15 requests/min, 1M tokens/day) — sufficient for prototyping. Only pay if you exceed free limits.

**Database:** Neon PostgreSQL free tier gives 0.5 GB storage plus 190 compute hours/month — more than enough for this prototype. Sign up free at neon.tech.

**Vercel Free Tier Limits:** 100GB bandwidth/month, unlimited deployments, 12 serverless function regions — all free. No credit card needed for hobby plan.

**Vercel + FastAPI Note:** Vercel Python runtime supports FastAPI via ASGI. Each API route runs as a serverless function — cold starts may add 1-2 seconds on first call, which is acceptable for a prototype.

**Dataset Size:** Use a 5,000-event subset of CICIDS2017 for development. Do not load all 2M+ rows into memory — sample strategically.

**Scope Boundary:** This is a research prototype. Clearly state in the paper that it is not production-ready and requires real SIEM integration for enterprise deployment. This is academically expected and acceptable.

---

*This is a living document. Update at the end of each phase to reflect progress, blockers, and scope adjustments.*
