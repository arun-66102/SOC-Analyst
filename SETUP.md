# SETUP.md — Local Dev & Vercel Deployment Guide

**Agentic AI-Powered Autonomous SOC Analyst**  
*MAS-SOC v0.3.0 — Phase 3 Complete*

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | `python --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |
| Git | Any | For cloning & Vercel deploy |

---

## 1. Clone & Configure Environment

```bash
git clone https://github.com/<your-org>/SOC-Analyst.git
cd SOC-Analyst
```

Copy the env template and fill in your API keys:

```bash
cp .env.example .env
```

Open `.env` and set:

```ini
# Required — Groq Cloud (free at console.groq.com)
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxx

# Optional — Threat Intelligence APIs (free tiers)
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Optional — Neon PostgreSQL (free at neon.tech)
# Leave blank to use in-memory fallback (recommended for local dev)
NEON_DB_URL=postgresql://user:pass@ep-xxx.neon.tech/neondb

# Optional — MITRE ATT&CK STIX data path
MITRE_STIX_PATH=data/mitre_stix/enterprise-attack.json
```

---

## 2. Python Backend Setup

```bash
# Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# Install all Python dependencies
pip install -r requirements.txt
```

---

## 3. Frontend Setup

```bash
cd frontend
npm install
cd ..
```

---

## 4. Run Locally (Both Backend + Frontend)

Use the included dev launcher:

```bash
# Windows
run_dev.bat

# macOS / Linux
bash run_dev.sh
```

This starts:
- **FastAPI backend** at `http://localhost:8000`  
  Swagger UI: `http://localhost:8000/docs`
- **React frontend (Vite)** at `http://localhost:5173`  
  (Proxies `/api` requests to the backend automatically)

Or start them separately:

```bash
# Terminal 1 — Backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 — Frontend
cd frontend && npm run dev
```

---

## 5. Run Tests

```bash
# Run all tests
pytest

# Run a specific test module
pytest tests/test_report.py -v
pytest tests/test_enrichment.py -v
pytest tests/test_triage.py -v

# Run with coverage
pytest --cov=agents --cov=api --cov-report=term-missing
```

---

## 6. Build MITRE ATT&CK Index (one-time)

```bash
python scripts/build_mitre_index.py
```

This builds the FAISS vector index from `data/mitre_stix/techniques.json`.

---

## 7. Vercel Deployment

### 7.1 Prerequisites
- A [Vercel](https://vercel.com) account (free hobby plan)
- Your GitHub repo pushed and connected to Vercel

### 7.2 Steps

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Phase 3 complete — all agents + dashboard"
   git push origin main
   ```

2. **Import project on Vercel:**
   - Go to [vercel.com/new](https://vercel.com/new)
   - Click **Import Git Repository** → select your repo
   - Framework preset: **Vite** (Vercel auto-detects from `vercel.json`)

3. **Set Environment Variables** in the Vercel dashboard:
   - Settings → Environment Variables → add all keys from `.env.example`
   - At minimum, set `GROQ_API_KEY`

4. **Deploy:**
   - Click **Deploy** — Vercel builds and deploys automatically
   - Frontend served from `frontend/dist/`
   - Backend FastAPI runs as Vercel serverless functions (`/api/*` routes)

5. **Get your live URL:**
   - e.g. `https://soc-analyst.vercel.app`

### 7.3 vercel.json Reference

The `vercel.json` in the project root handles routing:

```json
{
  "version": 2,
  "builds": [
    { "src": "api/main.py", "use": "@vercel/python" },
    { "src": "frontend/package.json", "use": "@vercel/static-build",
      "config": { "distDir": "dist" } }
  ],
  "routes": [
    { "src": "/api/(.*)", "dest": "api/main.py" },
    { "src": "/(.*)", "dest": "frontend/dist/$1" }
  ]
}
```

> **Note:** Vercel Python runtime cold starts may add 1-2 seconds on first request — acceptable for a research prototype.

---

## 8. Architecture Overview

```
Browser (React + Recharts)
        │  HTTP (Axios)
        ▼
  FastAPI  /api/*
        │
   Orchestrator
   ┌────┼────────────────────────────────────────┐
   │    │                                        │
TriageAgent  CorrelationAgent  MITREAgent  EnrichmentAgent  InvestigationAgent  ReportAgent
   │              │               │              │                 │                │
   └──────────────┴───────────────┴──────────────┴─────────────────┴────────────────┘
                               Groq LLM API (deepseek-r1 / llama4)
                               VirusTotal API + AbuseIPDB API
                               FAISS Vector Store (sentence-transformers)
                               Neon PostgreSQL (optional, in-memory fallback)
```

---

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| `GROQ_API_KEY not set` | Add `GROQ_API_KEY` to `.env` and re-run |
| Frontend can't reach `/api` | Make sure backend is running on port 8000 |
| MITRE mapping is empty | Run `python scripts/build_mitre_index.py` first |
| Jinja2 template not found | Run from the project root (`SOC-Analyst/`), not a subfolder |
| PostgreSQL connection error | Leave `NEON_DB_URL` blank — system uses in-memory store |
| `pytest` import errors | Activate the venv and run `pip install -r requirements.txt` |
| Vercel build fails | Check that `frontend/dist` exists; run `cd frontend && npm run build` locally first |

---

## 10. Project Structure (Quick Reference)

```
SOC-Analyst/
├── agents/           # AI agents (triage, correlation, mitre, enrichment, report, investigation)
├── api/              # FastAPI app — routes, models, main
├── benchmarks/       # Pipeline latency benchmark scripts
├── data/             # Datasets (CICIDS2017, UNSW-NB15, MITRE STIX, eval set)
├── database/         # PostgreSQL + in-memory store
├── frontend/         # React + Vite dashboard
│   └── src/
│       ├── components/   # Reusable UI components
│       └── pages/        # Dashboard pages
├── ingestion/        # Data loaders, normalizer, log generator
├── notebooks/        # EDA notebook
├── paper/            # Research paper draft
├── scripts/          # Utility scripts (MITRE index builder)
├── templates/        # Jinja2 HTML report template
├── tests/            # pytest unit + integration tests
├── .env.example      # All API keys documented
├── requirements.txt  # Python dependencies
├── vercel.json       # Vercel routing config
└── run_dev.bat       # Local dev launcher (Windows)
```
