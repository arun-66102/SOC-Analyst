# MAS-SOC Agent Deep Dive
> A plain-language breakdown of how every agent in the Multi-Agent SOC Analyst system is **built** and **how it works**, with real examples.

---

## Table of Contents
1. [System Overview — The Pipeline](#1-system-overview--the-pipeline)
2. [BaseAgent — The Blueprint Every Agent Follows](#2-baseagent--the-blueprint-every-agent-follows)
3. [Triage Agent — "Is this alert real, and how bad is it?"](#3-triage-agent--is-this-alert-real-and-how-bad-is-it)
4. [Correlation Agent — "Have we seen this before?"](#4-correlation-agent--have-we-seen-this-before)
5. [MITRE Agent — "What attack technique is this?"](#5-mitre-agent--what-attack-technique-is-this)
6. [Enrichment Agent — "Who is behind this IP?"](#6-enrichment-agent--who-is-behind-this-ip)
7. [Report Agent — "Generate a human-readable summary"](#7-report-agent--generate-a-human-readable-summary)
8. [Orchestrator — "Run everything in order"](#8-orchestrator--run-everything-in-order)

---

## 1. System Overview — The Pipeline

When a network security event arrives (e.g., a suspicious connection from IP `192.168.1.50`), it doesn't just go to one agent — it travels through a **sequential pipeline**:

```
Raw Alert
    ↓
[NormalizedEvent]   ← standardised data structure
    ↓
 Triage Agent       → Is it real? How severe?
    ↓
 Correlation Agent  → Is it part of a known incident?
    ↓
 MITRE Agent        → Which ATT&CK technique matches?
    ↓
 Enrichment Agent   → What do VirusTotal / AbuseIPDB say?
    ↓
 Report Agent       → Write a readable incident report
    ↓
[AnalyzeResponse]   ← final structured result returned to API/UI
```

Every piece of data passed between agents is a **`NormalizedEvent`** — a shared Python dataclass containing fields like `src_ip`, `dst_port`, `threat_category`, `protocol`, and `flow_bytes_per_sec`. This ensures every agent speaks the same language.

---

## 2. BaseAgent — The Blueprint Every Agent Follows

**File:** `agents/base_agent.py`

### What it is
`BaseAgent` is an **abstract class** — it defines the skeleton that every other agent must fill in. Think of it like a job contract: every agent *must* implement a `process()` method, and in return gets timing, logging, and error handling for free.

### How it's built

```python
class BaseAgent(ABC):
    def __init__(self, agent_name: str, version: str = "1.0.0"):
        self.agent_name = agent_name
        self._logger = logging.getLogger(agent_name)

    @abstractmethod
    def process(self, event: NormalizedEvent) -> AgentResult:
        # Every subclass MUST implement this
        ...

    def run(self, event: NormalizedEvent) -> AgentResult:
        # Wraps process() with timing and error handling
        start = time.perf_counter()
        result = self.process(event)
        result.latency_ms = (time.perf_counter() - start) * 1000
        return result
```

### Simple example
Imagine a basic agent:
```python
class MyAgent(BaseAgent):
    def process(self, event):
        return AgentResult(event_id=event.event_id, status="success")

agent = MyAgent("MyAgent")
agent.run(my_event)
# → Automatically timed, logged, and error-caught
```

### Key design decisions
| Feature | Why it's there |
|---|---|
| `run()` wraps `process()` | Keeps business logic pure; cross-cutting concerns (timing, errors) stay in one place |
| `health_check()` | The Orchestrator calls this before the pipeline starts to make sure all agents are ready |
| Abstract `process()` | Forces every agent to implement its own logic — you can't accidentally forget |

---

## 3. Triage Agent — "Is this alert real, and how bad is it?"

**File:** `agents/triage_agent.py`

### What it does
The Triage Agent is the **first responder**. It reads a security event and answers two questions:
1. Is this a **true positive** (real attack) or a **false positive** (harmless noise)?
2. How **severe** is it? (`Critical / High / Medium / Low`)

### How it's built — Step by Step

**Step 1 — Build a prompt with few-shot examples**
```python
prompt = build_triage_prompt(event)
# e.g.:
# "Event category: BruteForce. Source IP: 10.0.0.5.
#  Packets/sec: 3200. Protocol: TCP. Port: 22.
#  Based on the examples above, classify this event."
```
The prompt includes 2–3 labelled examples so the LLM knows exactly what format to return.

**Step 2 — Send to Groq LLM (GPT-OSS 120B)**
```python
response = await self._llm.chat(
    prompt=prompt,
    system=TRIAGE_SYSTEM_PROMPT,
    temperature=0.1   # low temp = consistent, deterministic answers
)
```

**Step 3 — Parse the JSON response**
The LLM returns something like:
```json
{
  "severity": "High",
  "is_true_positive": true,
  "confidence": 0.92,
  "reasoning": "High packet rate on SSH port strongly suggests brute-force.",
  "recommended_action": "Block source IP. Escalate to Tier 2 analyst."
}
```
The agent strips any markdown fences and extracts this JSON safely.

**Step 4 — Heuristic fallback (if LLM fails)**
If the LLM is down or returns garbage, the agent falls back to **keyword rules**:
```python
if "ddos" in threat_category:
    severity = CRITICAL, confidence = 0.80
elif "bruteforce" in threat_category:
    severity = HIGH,     confidence = 0.75
elif "benign" in threat_category:
    severity = LOW,      is_true_positive = False
```
This means the pipeline **never crashes** even when the AI is unavailable.

### Real-world example

**Input event:**
```
src_ip          = "45.33.32.156"
threat_category = "BruteForce"
dst_port        = 22
protocol        = "TCP"
packets/sec     = 3,200
```

**Triage Agent output:**
```
severity           = HIGH
is_true_positive   = True
confidence         = 0.92
reasoning          = "3,200 packets/sec on SSH port 22 from a single
                      external IP is consistent with an SSH brute-force attack."
recommended_action = "Block 45.33.32.156 at firewall. Escalate to Tier 2."
```

---

## 4. Correlation Agent — "Have we seen this before?"

**File:** `agents/correlation_agent.py`

### What it does
The Correlation Agent is the **memory** of the system. It groups related alerts together into **incidents**, so that 50 alerts from the same attacker become one incident rather than 50 separate tickets.

### How it's built — Step by Step

**Step 1 — Time-window + Source IP matching (fast path)**
```
"Has any event from IP 45.33.32.156 arrived in the last 5 minutes?"
```
If yes → attach this alert to the **existing** incident.
If no → proceed to Step 2.

**Step 2 — Semantic similarity via embeddings (smart path)**
Each event is converted to a 384-dimensional vector using the **`all-MiniLM-L6-v2`** sentence-transformer model:
```python
text = "category:BruteForce label:SSH-Patator protocol:TCP dst_port:22 src_ip:45.33.32.156"
embedding = model.encode(text)  # → [0.12, -0.34, 0.87, ... ] 384 numbers
```
Then it computes **cosine similarity** against all past events. If similarity ≥ 0.75, it joins that existing incident.

**Step 3 — Create a new incident (if no match found)**
```python
incident_id = "INC-" + sha1("45.33.32.156:BruteForce")[:8].upper()
# → "INC-3A7F2B9C"
```
The ID is deterministic — the same attacker + category always produces the same incident ID.

**Step 4 — LLM writes an incident summary**
```
"Incident INC-3A7F2B9C: A sustained brute-force attack is being conducted
 from 45.33.32.156 against SSH (port 22). 12 related events detected over
 the past 4 minutes. The attacker appears to be systematically testing
 credentials. Immediate firewall block recommended."
```

### Real-world example

| Event | Time | Src IP | Result |
|---|---|---|---|
| Alert #1 | 14:00:00 | 45.33.32.156 | → New incident `INC-3A7F2B9C` |
| Alert #2 | 14:01:30 | 45.33.32.156 | → Merged into `INC-3A7F2B9C` |
| Alert #3 | 14:02:45 | 45.33.32.156 | → Merged into `INC-3A7F2B9C` |
| Alert #4 | 14:10:00 | 192.168.1.9  | → New incident `INC-FF12AA34` (different IP) |

Instead of 4 separate alerts, analysts see **2 incidents**.

---

## 5. MITRE Agent — "What attack technique is this?"

**File:** `agents/mitre_agent.py`

### What it does
The MITRE Agent maps each event to the relevant **MITRE ATT&CK technique** — a globally recognised taxonomy of attack methods used by real threat actors. This tells analysts exactly *what* the attacker is doing in a standardised language.

### How it's built — Step by Step

**Step 1 — Load the knowledge base at startup**
A JSON file (`data/mitre_stix/techniques.json`) containing ~600 real ATT&CK techniques is loaded once:
```json
{
  "T1110": {
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "Credential Access",
    "description": "Adversaries may use brute force techniques..."
  }
}
```

**Step 2 — Build a FAISS vector index**
Every technique description is embedded into a 384-dim vector and stored in a **FAISS** (Facebook AI Similarity Search) index. This allows lightning-fast nearest-neighbour lookup across all 600 techniques.

**Step 3 — Embed the incoming event**
```python
event_text = "attack type: SSH-Patator. threat category: BruteForce. protocol: TCP. destination port: 22"
event_vector = model.encode(event_text)
```

**Step 4 — Search FAISS for top-3 matches**
```python
scores, indices = faiss_index.search(event_vector, k=3)
# Returns the 3 most semantically similar ATT&CK techniques
```

**Step 5 — LLM confirms the best match**
```
"The top candidate is T1110 (Brute Force). Given the SSH traffic pattern
 and high packet rate, T1110.004 (Credential Stuffing) is actually a
 better sub-technique match here."
```

**Step 6 — Rule-based fallback (if FAISS not built yet)**
Simple keyword rules handle common cases without the AI:
```python
if "portscan" in category:     → T1046 (Network Service Discovery)
if "ddos" in category:         → T1498 (Network Denial of Service)
if "exfiltration" in category: → T1048 (Exfiltration Over Alt. Protocol)
```

### Real-world example

**Input:** BruteForce event targeting SSH port 22

**MITRE Agent top-3 output:**

| Rank | Technique ID | Name | Tactic | Confidence |
|---|---|---|---|---|
| 1 | T1110 | Brute Force | Credential Access | 0.92 |
| 2 | T1110.004 | Credential Stuffing | Credential Access | 0.88 |
| 3 | T1078 | Valid Accounts | Defense Evasion | 0.71 |

This directly maps to the MITRE ATT&CK framework and gives analysts standardised context to look up threat actor groups and mitigations.

---

## 6. Enrichment Agent — "Who is behind this IP?"

**File:** `agents/enrichment_agent.py`

### What it does (Phase 3 — Planned)
The Enrichment Agent queries external **Threat Intelligence** databases to answer: *"Is this IP/domain/hash known to be malicious?"*

### Planned data sources
| API | What it checks | Rate limit |
|---|---|---|
| **VirusTotal** | IP reputation, file hash lookups | 4 req/min (free) |
| **AbuseIPDB** | IP abuse history, country, ISP | 1,000 req/day (free) |

### How it will work (architecture)

```
EnrichmentAgent.process(event)
    ↓
1. Extract src_ip from event
    ↓
2. Query VirusTotal API
   → "Is 45.33.32.156 in any malware database?"
    ↓
3. Query AbuseIPDB API
   → "Has 45.33.32.156 been reported for abuse? Confidence score?"
    ↓
4. Run Gemini Chain-of-Thought reasoning
   → "Based on 47 abuse reports and 12 malware hits, this IP
      is very likely a known scanning host."
    ↓
5. Return enrichment data (abuse score, country, ISP, tags)
```

### Current status
```python
def process(self, event: NormalizedEvent) -> AgentResult:
    raise NotImplementedError("EnrichmentAgent will be implemented in Phase 3.")
```
The skeleton is in place; the API integration is planned for Phase 3.

---

## 7. Report Agent — "Generate a human-readable summary"

**File:** `agents/report_agent.py`

### What it does (Phase 3 — Planned)
The Report Agent is the **final stage** of the pipeline. It takes all the outputs from the previous agents and produces a complete, human-readable incident report that can be sent to a Tier 2 analyst or management.

### Planned output format
```markdown
## Incident Report — INC-3A7F2B9C
**Severity:** HIGH | **True Positive:** Yes | **Generated:** 2026-09-30 14:05:00

### Summary
A sustained SSH brute-force attack was detected originating from 45.33.32.156
(Abuse confidence: 95%, Country: Netherlands, ISP: DigitalOcean).

### MITRE ATT&CK Mapping
- Primary: T1110 — Brute Force (Credential Access)
- Sub-technique: T1110.004 — Credential Stuffing

### Recommended Actions
1. Block 45.33.32.156 at perimeter firewall immediately
2. Review SSH access logs for successful authentications
3. Enable MFA on all SSH-accessible systems
4. Escalate to Tier 2 analyst for forensic review
```

---

## 8. Orchestrator — "Run everything in order"

**File:** `agents/orchestrator.py`

### What it does
The Orchestrator is the **conductor** of the pipeline. It's the only component that knows about all agents. It runs them in sequence, passes results between stages, and returns a single `AnalyzeResponse` object.

### How it's built

```python
class Orchestrator:
    def __init__(self):
        self._agents = {
            "triage":      None,   # filled by register_agent()
            "correlation": None,
            "mitre":       None,
            "enrichment":  None,
            "report":      None,
        }

    def register_agent(self, stage, agent):
        self._agents[stage] = agent

    def run_pipeline(self, event) -> AnalyzeResponse:
        # Stage 1: Triage
        triage_result = self._run_stage("triage", event)
        event.severity = triage_result.output["severity"]  # enrich event

        # Stage 2: Correlation
        corr_result = self._run_stage("correlation", event)
        event.incident_id = corr_result.output["incident_id"]  # enrich event

        # Stage 3: MITRE
        mitre_result = self._run_stage("mitre", event)
        event.mitre_techniques = [t["technique_id"] for t in mitre_result.output["techniques"]]

        # Stages 4+5: Enrichment & Report
        ...

        return AnalyzeResponse(triage=triage_result, correlation=corr_result, ...)
```

### Key design feature — partial pipelines
If an agent hasn't been built yet (e.g., Enrichment is still Phase 3), the orchestrator **skips it gracefully** instead of crashing:
```python
def _run_stage(self, stage, event):
    agent = self._agents.get(stage)
    if agent is None:
        return None   # skip, don't crash
    return agent.run(event)
```
This was a deliberate choice to allow incremental delivery across project phases.

### Full pipeline walkthrough — one real event

```
Event arrives: {src_ip: "45.33.32.156", category: "BruteForce", port: 22}
    ↓
[Triage]      → severity=HIGH, is_tp=True, confidence=0.92
    ↓
[Correlation] → incident_id="INC-3A7F2B9C" (merged with 11 prior events)
    ↓
[MITRE]       → T1110 Brute Force (0.92), T1110.004 Credential Stuffing (0.88)
    ↓
[Enrichment]  → (Phase 3) AbuseIPDB: 95% abuse confidence, Country: NL
    ↓
[Report]      → (Phase 3) Full markdown incident report generated
    ↓
AnalyzeResponse returned to REST API → displayed in React dashboard
```

---

## Summary Table

| Agent | Role | Core Tech | Status |
|---|---|---|---|
| **BaseAgent** | Abstract blueprint for all agents | Python ABC, logging, timing | ✅ Complete |
| **Triage Agent** | Classify severity + true/false positive | Groq LLM + heuristic fallback | ✅ Complete |
| **Correlation Agent** | Group related alerts into incidents | Sentence-transformers + time-window matching | ✅ Complete |
| **MITRE Agent** | Map event to ATT&CK technique | FAISS vector search + LLM confirmation | ✅ Complete |
| **Enrichment Agent** | Threat intel lookup (VirusTotal, AbuseIPDB) | REST APIs + Gemini CoT | 🔄 Phase 3 |
| **Report Agent** | Generate human-readable incident report | LLM templating | 🔄 Phase 3 |
| **Orchestrator** | Run pipeline in sequence | Sequential stage runner | ✅ Complete |
