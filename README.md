# 🛡️ Agentic AI-Powered Autonomous SOC Analyst

> An autonomous, multi-agent Security Operations Center (SOC) analyst that ingests security alerts, investigates threats, maps to MITRE ATT&CK, scores risk, and generates actionable incident reports — with Human-in-the-Loop approval before response.

---

## 📖 Table of Contents

- [Overview](#-overview)
- [System Architecture](#-system-architecture)
- [Agent Pipeline](#-agent-pipeline)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [Agent Descriptions](#-agent-descriptions)
- [SOC Dashboard](#-soc-dashboard)
- [Incident Response](#-incident-response)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

Traditional SOC operations rely heavily on manual triage, which is slow, expensive, and error-prone at scale. This project implements a **fully autonomous, agentic AI pipeline** that:

- **Collects & correlates** alerts from heterogeneous security devices
- **Enriches threats** using real-world Threat Intelligence APIs
- **Investigates** incidents by analyzing logs and reconstructing attack chains
- **Maps** adversary behavior to the **MITRE ATT&CK** framework
- **Scores** risk and prioritizes incidents for analyst attention
- **Recommends & generates** containment actions and executive-ready reports
- **Presents** findings on an interactive SOC Dashboard
- **Waits for human approval** before executing any response action

This system acts as a **Tier 1–2 SOC Analyst**, dramatically reducing Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR).

---

## 🏗️ System Architecture

```
                       SECURITY DEVICES
 ┌──────────────────────────────────────────────────────────────┐
 │  Endpoints │ Servers │ Firewall │ IDS │ Email │ Cloud │ Apps  │
 └──────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    LOG COLLECTION LAYER
             (Sysmon + Zeek + Wazuh + Filebeat)
                              │
                              ▼
                   ALERT CORRELATION AGENT
             • Merge alerts from different sources
             • Remove duplicate events
             • Create a unified incident
                              │
                              ▼
                THREAT INTELLIGENCE AGENT
           • Query VirusTotal
           • Query AbuseIPDB
           • Query AlienVault OTX
           • Query MISP
                              │
                              ▼
                 INVESTIGATION AGENT
           • Analyze related logs
           • Identify attack chain
           • Collect supporting evidence
                              │
                              ▼
                 MITRE MAPPING AGENT
           • Identify ATT&CK tactics
           • Identify ATT&CK techniques
                              │
                              ▼
                   RISK SCORING AGENT
           • Calculate severity
           • Calculate confidence score
           • Prioritize incident
                              │
                              ▼
                RECOMMENDATION AGENT
           • Block malicious IP
           • Isolate endpoint
           • Reset credentials
           • Suggest containment
                              │
                              ▼
                REPORT GENERATION AGENT
           • Executive summary
           • Timeline
           • Indicators of Compromise (IOCs)
           • MITRE ATT&CK mapping
           • Recommended actions
                              │
                              ▼
                      SOC DASHBOARD
           • Investigation Summary
           • Attack Timeline
           • Risk Score
           • MITRE View
           • Download Report
                              │
                              ▼
                  HUMAN SOC ANALYST
           • Review findings
           • Validate investigation
           • Approve response
                              │
                              ▼
                    INCIDENT RESPONSE
           • Block IP / Domain
           • Isolate Endpoint
           • Reset Credentials
           • Create Ticket
           • Document Incident
```

---

## 🤖 Agent Pipeline

The system is composed of **7 specialized AI agents** working in a sequential pipeline, orchestrated via a multi-agent framework (LangGraph / CrewAI):

| # | Agent | Role | Key Actions |
|---|-------|------|-------------|
| 1 | **Alert Correlation Agent** | Normalizes & deduplicates alerts from all sources | Merges SIEM/EDR/Firewall/IDS events into a single unified incident object |
| 2 | **Threat Intelligence Agent** | Enriches IOCs with external threat feeds | Queries VirusTotal, AbuseIPDB, AlienVault OTX, MISP |
| 3 | **Investigation Agent** | Reconstructs the attack chain | Analyzes logs, identifies lateral movement, collects evidence |
| 4 | **MITRE Mapping Agent** | Classifies adversary behavior | Maps observed TTPs to ATT&CK tactics & techniques |
| 5 | **Risk Scoring Agent** | Prioritizes the incident | Computes severity score and confidence rating |
| 6 | **Recommendation Agent** | Proposes containment | Suggests specific, prioritized response actions |
| 7 | **Report Generation Agent** | Produces the final report | Generates executive summary, full timeline, IOC list, and MITRE view |

---

## 🛠️ Tech Stack

### Core AI & Agent Framework
| Component | Technology |
|-----------|------------|
| LLM Backend | OpenAI GPT-4o / Anthropic Claude / Google Gemini |
| Agent Orchestration | LangGraph / CrewAI |
| Reasoning Pattern | ReAct (Reasoning + Acting) |
| Structured Outputs | Pydantic v2 |

### Log Collection & SIEM
| Component | Technology |
|-----------|------------|
| Host Telemetry | Sysmon (Windows Events) |
| Network Telemetry | Zeek (formerly Bro) |
| SIEM / EDR | Wazuh |
| Log Shipper | Filebeat (Elastic Stack) |

### Threat Intelligence APIs
| Provider | Data |
|----------|------|
| [VirusTotal](https://www.virustotal.com) | File hash, URL, IP reputation |
| [AbuseIPDB](https://www.abuseipdb.com) | IP abuse reports & confidence score |
| [AlienVault OTX](https://otx.alienvault.com) | Threat pulses, IOC lookup |
| [MISP](https://www.misp-project.org) | Shared threat intelligence platform |

### Knowledge & RAG
| Component | Technology |
|-----------|------------|
| Vector Store | ChromaDB / FAISS |
| Embedding Model | OpenAI `text-embedding-3-small` |
| Playbook Source | NIST SP 800-61, SANS Incident Response |

### Dashboard & Reporting
| Component | Technology |
|-----------|------------|
| SOC Dashboard | Streamlit / FastAPI + React |
| Report Format | PDF / Markdown / JSON |
| Ticket System | Jira API / ServiceNow (optional) |

---

## 📁 Project Structure

```
SOC-Analyst/
├── README.md                          # Project overview (this file)
│
├── agents/                            # Individual AI agent modules
│   ├── alert_correlation_agent.py     # Merges & deduplicates alerts
│   ├── threat_intel_agent.py          # Queries TI APIs (VT, AbuseIPDB, OTX)
│   ├── investigation_agent.py         # Log analysis & attack chain reconstruction
│   ├── mitre_mapping_agent.py         # ATT&CK tactic/technique classification
│   ├── risk_scoring_agent.py          # Severity & confidence computation
│   ├── recommendation_agent.py        # Containment & remediation suggestions
│   └── report_generation_agent.py     # Final report synthesis
│
├── orchestrator/                      # Multi-agent pipeline coordination
│   ├── pipeline.py                    # Main agent orchestration graph (LangGraph)
│   └── state.py                       # Shared investigation state schema
│
├── tools/                             # External tool integrations
│   ├── virustotal.py                  # VirusTotal API client
│   ├── abuseipdb.py                   # AbuseIPDB API client
│   ├── otx.py                         # AlienVault OTX API client
│   ├── misp.py                        # MISP API client
│   └── log_query.py                   # SIEM / Wazuh log query tool
│
├── models/                            # Pydantic data models
│   ├── alert.py                       # Normalized alert schema
│   ├── incident.py                    # Unified incident object
│   ├── threat_intel.py                # TI enrichment result schema
│   ├── mitre.py                       # MITRE ATT&CK mapping schema
│   └── report.py                      # Final report schema
│
├── rag/                               # Retrieval-Augmented Generation layer
│   ├── playbook_indexer.py            # Indexes NIST/SANS playbooks into vector store
│   ├── playbook_retriever.py          # Retrieves relevant playbook steps
│   └── playbooks/                     # Raw playbook documents (PDF/Markdown)
│
├── dashboard/                         # SOC Analyst Dashboard
│   ├── app.py                         # Streamlit / FastAPI app entry point
│   ├── components/                    # UI components (timeline, MITRE view, etc.)
│   └── templates/                     # Report HTML templates
│
├── data/                              # Sample data for testing
│   ├── sample_alerts/                 # Example alert JSONs (SIEM, EDR, Firewall)
│   └── sample_logs/                   # Example raw logs (Syslog, CEF, EVTX)
│
├── tests/                             # Unit and integration tests
│   ├── test_agents.py
│   ├── test_tools.py
│   └── test_pipeline.py
│
├── config/                            # Configuration files
│   ├── settings.yaml                  # Global app settings
│   └── mitre_techniques.json          # Local ATT&CK technique definitions
│
├── .env.example                       # Environment variable template
├── requirements.txt                   # Python dependencies
└── docker-compose.yml                 # Docker setup (Wazuh, Filebeat, ChromaDB)
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/arun-66102/SOC-Analyst.git
cd SOC-Analyst
```

### 2. Create & Activate a Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env and fill in your API keys (see Configuration section)
```

### 5. (Optional) Start Supporting Services via Docker

```bash
docker-compose up -d
```

### 6. Run the Pipeline

```bash
# Run the full agentic pipeline with a sample alert
python -m orchestrator.pipeline --input data/sample_alerts/brute_force.json

# Launch the SOC Dashboard
streamlit run dashboard/app.py
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and fill in the required values:

```env
# ── LLM Backend ──────────────────────────────────────────────
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AIza...

# ── Threat Intelligence APIs ─────────────────────────────────
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
OTX_API_KEY=...
MISP_URL=https://your-misp-instance.local
MISP_API_KEY=...

# ── SIEM / Wazuh ─────────────────────────────────────────────
WAZUH_API_URL=https://localhost:55000
WAZUH_USERNAME=wazuh
WAZUH_PASSWORD=...

# ── Ticket Integration (Optional) ────────────────────────────
JIRA_URL=https://your-org.atlassian.net
JIRA_USERNAME=...
JIRA_API_TOKEN=...

# ── Vector Store ─────────────────────────────────────────────
CHROMA_PERSIST_DIR=./rag/chroma_db
```

---

## 🤖 Agent Descriptions

### 1. 🔗 Alert Correlation Agent
Receives raw alerts from multiple security sources (SIEM, EDR, Firewall, IDS, Email, Cloud). It normalizes each alert into a common schema, deduplicates overlapping events by timestamp and source IP, and emits a single **Unified Incident Object** for downstream agents.

### 2. 🌐 Threat Intelligence Agent
Receives all IOCs (IPs, domains, file hashes, URLs) from the correlated incident and enriches them in parallel by:
- Querying **VirusTotal** for malware reputation
- Querying **AbuseIPDB** for IP abuse score & reports
- Querying **AlienVault OTX** for threat pulses
- Querying **MISP** for shared organizational threat data

### 3. 🔬 Investigation Agent
The core reasoning agent. Uses the **ReAct loop** (Reason → Act → Observe → Repeat) to:
- Query relevant logs from Wazuh/SIEM around the incident timeframe
- Identify the attack chain (initial access → lateral movement → exfiltration)
- Collect and document supporting log evidence

### 4. 🎯 MITRE Mapping Agent
Takes the identified attack behaviors and classifies them against the [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/), outputting:
- **Tactics** (e.g., `TA0001 - Initial Access`)
- **Techniques** (e.g., `T1566.001 - Spearphishing Attachment`)

### 5. 📊 Risk Scoring Agent
Computes a structured risk assessment:
- **Severity Score** (Critical / High / Medium / Low) based on asset value, vulnerability, and impact
- **Confidence Score** (0–100%) based on evidence quality and TI signal strength
- **Priority Rank** for analyst queue ordering

### 6. 🛡️ Recommendation Agent
Retrieves relevant incident response playbooks from the RAG layer (NIST SP 800-61, SANS) and generates prioritized, actionable containment steps:
- Block malicious IPs / domains at the firewall
- Isolate compromised endpoints
- Force password resets for affected accounts
- Preserve forensic artifacts before remediation

### 7. 📄 Report Generation Agent
Synthesizes all upstream agent outputs into a structured **Incident Report** containing:
- **Executive Summary** — non-technical overview for leadership
- **Attack Timeline** — chronological reconstruction of the incident
- **IOC List** — all identified Indicators of Compromise
- **MITRE ATT&CK Mapping** — tactic/technique table
- **Recommended Actions** — prioritized response steps

---

## 🖥️ SOC Dashboard

The interactive dashboard provides SOC analysts with a single-pane view of the investigation:

| Panel | Description |
|-------|-------------|
| **Investigation Summary** | Agent findings, enriched IOCs, and overall verdict |
| **Attack Timeline** | Visual chronological event chain |
| **Risk Score** | Severity gauge, confidence meter, and priority rank |
| **MITRE ATT&CK View** | Interactive ATT&CK matrix heatmap with highlighted TTPs |
| **Download Report** | Export the full incident report as PDF, Markdown, or JSON |

> The dashboard enforces **Human-in-the-Loop (HITL)** — no response action is executed until a SOC analyst reviews, validates, and explicitly approves it.

---

## 🚨 Incident Response

Once the analyst approves the recommended actions, the system can execute automated response via integrated APIs:

| Action | Method |
|--------|--------|
| **Block IP / Domain** | Firewall API / EDR policy push |
| **Isolate Endpoint** | Wazuh active response / EDR network isolation |
| **Reset Credentials** | Active Directory / IAM API |
| **Create Ticket** | Jira / ServiceNow API |
| **Document Incident** | Auto-appends report to incident management system |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m 'feat: add your feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

Please ensure all new agent modules include unit tests under `tests/`.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built as a Final Year Project** | Agentic AI × Cybersecurity

_Autonomous threat detection, investigation, and response — powered by LLMs._

</div>

> ⚠️ **Important:** Read the dataset setup section below before running any code.

## Dataset Setup (Required — Not Included in Repo)

The raw datasets are too large for Git and are excluded via `.gitignore`.
Each team member must download them manually and place them in the exact
folder structure below before running any ingestion code.

### 1. CICIDS2017
- Download: https://www.unb.ca/cic/datasets/ids-2017.html
- Get the `MachineLearningCVE` folder (8 CSV files)
- Place at: `data/cicids2017/MachineLearningCVE/`

### 2. UNSW-NB15
- Download: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Get `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`
  (the processed/Kaggle-style version)
- Place at: `data/unsw_nb15/`

### 3. MITRE ATT&CK STIX Bundle (optional)
- Download: https://github.com/mitre/cti → `enterprise-attack/enterprise-attack.json`
- Place at: `data/mitre_stix/enterprise-attack.json`
- **Note:** You only need this if you're re-running `ingestion/mitre_parser.py`
  yourself. The parsed output (`data/mitre_stix/techniques.json`) is already
  committed to the repo and ready to use.

### Folder structure after setup

```
data/
├── cicids2017/
│   └── MachineLearningCVE/
│       └── *.csv (8 files)
├── unsw_nb15/
│   ├── UNSW_NB15_training-set.csv
│   └── UNSW_NB15_testing-set.csv
└── mitre_stix/
    ├── enterprise-attack.json   (optional, for re-parsing)
    └── techniques.json          (already in repo)
```