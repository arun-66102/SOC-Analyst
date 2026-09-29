"""
agents/mitre_agent.py
----------------------
MITRE ATT&CK Mapping Agent — maps security events to ATT&CK techniques
using sentence-transformer embeddings stored in a FAISS index,
with optional Groq LLM confirmation.

How it works:
  1. Load techniques.json (built by mitre_parser.py in Phase 1)
  2. Embed all technique descriptions using sentence-transformers
  3. Store embeddings in a FAISS FlatIP (inner-product / cosine) index
  4. For each event: embed the event description, query FAISS → top-3 matches
  5. Optionally ask Groq to confirm/refine the mapping with reasoning

The FAISS index is built once (on first run or by scripts/build_mitre_index.py)
and cached to data/processed/faiss_mitre.index for reuse.

Author  : Member 3 — Phase 2
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Optional

import numpy as np

from agents.base_agent import BaseAgent
from agents.llm_client import GroqTask, get_llm_client
from api.models import AgentResult, MITREOutput, MITRETechnique, NormalizedEvent

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES_JSON = ROOT / "data" / "mitre_stix" / "techniques.json"
FAISS_MITRE_INDEX = ROOT / "data" / "processed" / "faiss_mitre.index"
FAISS_MITRE_META  = ROOT / "data" / "processed" / "faiss_mitre.json"

# Embedding model (matches faiss_store.py)
EMBEDDING_DIM = 384
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Number of top techniques to return
TOP_K = 3


class MITREAgent(BaseAgent):
    """
    MITRE ATT&CK Mapping Agent — Phase 2.

    Maps each security event to the top-3 most relevant ATT&CK techniques
    using semantic embeddings, with LLM confirmation of the best match.
    """

    def __init__(self, use_llm_confirmation: bool = True) -> None:
        super().__init__(agent_name="MITREAgent", version="2.0.0")
        self.use_llm_confirmation = use_llm_confirmation

        # Lazy-loaded resources
        self._embedder = None          # SentenceTransformer
        self._faiss_index = None       # faiss.IndexFlatIP
        self._technique_list: list[dict] = []  # ordered metadata parallel to index
        self._techniques_by_id: dict[str, dict] = {}  # id -> metadata
        self._llm = None

        # Load techniques + index immediately
        self._load_resources()

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def process(self, event: NormalizedEvent) -> AgentResult:
        """Synchronous entry-point — runs async logic via asyncio.run()."""
        return asyncio.run(self.process_async(event))

    # ------------------------------------------------------------------
    # Core async logic
    # ------------------------------------------------------------------

    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        """
        Full MITRE mapping pipeline:
          1. Embed the event description
          2. Search FAISS for top-K technique matches
          3. (Optional) LLM confirmation of the top match
          4. Return MITREOutput with up to 3 techniques
        """
        self.log_info(f"MITRE mapping for event {event.event_id}")

        # Step 1: Embed the event
        event_text = self._event_to_text(event)
        embedding = self._embed_text(event_text)

        # Step 2: Search FAISS / fallback to rule-based
        if embedding is not None and self._faiss_index is not None:
            candidates = self._search_faiss(embedding, k=TOP_K)
        else:
            self.log_warning("FAISS index not available — using rule-based fallback")
            candidates = self._rule_based_mapping(event)

        # Step 3: LLM confirmation (top match only, to save tokens)
        llm_reasoning: Optional[str] = None
        if self.use_llm_confirmation and candidates:
            llm_reasoning = await self._llm_confirm(event, candidates)

        # Step 4: Build output
        techniques = [
            MITRETechnique(
                technique_id=c["technique_id"],
                technique_name=c["technique_name"],
                tactic=c["tactic"],
                confidence=round(c["score"], 4),
                description=(c.get("description") or "")[:300],
            )
            for c in candidates
        ]

        output = MITREOutput(
            techniques=techniques,
            llm_reasoning=llm_reasoning,
        )

        confidence = techniques[0].confidence if techniques else 0.0

        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=confidence,
            reasoning=(
                llm_reasoning or
                (f"Top match: {techniques[0].technique_id} ({techniques[0].technique_name})"
                 if techniques else "No techniques matched.")
            ),
            output=output.model_dump(),
        )

    # ------------------------------------------------------------------
    # FAISS search
    # ------------------------------------------------------------------

    def _search_faiss(self, embedding: np.ndarray, k: int = TOP_K) -> list[dict]:
        """Search the FAISS index for the top-k MITRE technique matches."""
        vec = embedding.reshape(1, -1).astype("float32")
        scores, indices = self._faiss_index.search(vec, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._technique_list):
                continue
            tech = self._technique_list[idx]
            tactic = (tech.get("tactics") or ["Unknown"])[0]
            results.append({
                "technique_id":   tech["technique_id"],
                "technique_name": tech["technique_name"],
                "tactic":         tactic,
                "description":    tech.get("description", ""),
                "score":          max(0.0, float(score)),  # inner-product scores
            })
        return results

    # ------------------------------------------------------------------
    # Rule-based fallback mapping
    # ------------------------------------------------------------------

    def _rule_based_mapping(self, event: NormalizedEvent) -> list[dict]:
        """
        Keyword-based MITRE technique mapping.
        Used when FAISS index is not available.
        """
        cat = str(event.threat_category).lower()
        label = str(event.label or "").lower()
        port = event.dst_port or 0

        # Mapping: threat category keyword → technique metadata
        # NOTE: keywords must match the LOWERCASED ThreatCategory enum values
        # (e.g. "BruteForce" → "bruteforce", "PortScan" → "portscan")
        # Parent techniques are listed BEFORE sub-techniques so the parent wins
        # on a category-level match before a label-level sub-technique match.
        RULES = [
            # Brute Force — "BruteForce" enum → "bruteforce" in text
            # "brute" matches "bruteforce"; parent T1110 listed first
            ("brute",       {"technique_id": "T1110",     "technique_name": "Brute Force",
              "tactic": "Credential Access", "score": 0.90}),
            ("ssh-patator",  {"technique_id": "T1110.004", "technique_name": "Credential Stuffing",
              "tactic": "Credential Access", "score": 0.88}),
            ("ftp-patator",  {"technique_id": "T1110.001", "technique_name": "Password Guessing",
              "tactic": "Credential Access", "score": 0.88}),
            # Port Scan — "PortScan" enum → "portscan" in text
            ("portscan",    {"technique_id": "T1046", "technique_name": "Network Service Discovery",
              "tactic": "Discovery", "score": 0.92}),
            # Reconnaissance — matches "reconnaissance" directly
            ("reconnaissance", {"technique_id": "T1595", "technique_name": "Active Scanning",
              "tactic": "Reconnaissance", "score": 0.88}),
            # DoS / DDoS — match "ddos" before "dos" to avoid partial match
            ("ddos",        {"technique_id": "T1498", "technique_name": "Network Denial of Service",
              "tactic": "Impact", "score": 0.93}),
            ("dos",         {"technique_id": "T1499", "technique_name": "Endpoint Denial of Service",
              "tactic": "Impact", "score": 0.88}),
            # Web Attack — "WebAttack" enum → "webattack" in text;
            # label "Web Attack XSS" → "web attack xss" also caught by "web attack"
            ("webattack",   {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
              "tactic": "Initial Access", "score": 0.85}),
            ("web attack",  {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
              "tactic": "Initial Access", "score": 0.85}),
            # Botnet / Malware
            ("botnet",      {"technique_id": "T1071", "technique_name": "Application Layer Protocol",
              "tactic": "Command And Control", "score": 0.85}),
            ("malware",     {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
              "tactic": "Execution", "score": 0.80}),
            # Infiltration / Exfiltration
            ("infiltration", {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel",
              "tactic": "Exfiltration", "score": 0.87}),
            ("exfiltration", {"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol",
              "tactic": "Exfiltration", "score": 0.87}),
            # Backdoor
            ("backdoor",    {"technique_id": "T1547", "technique_name": "Boot or Logon Autostart Execution",
              "tactic": "Persistence", "score": 0.82}),
        ]

        matches = []
        seen_ids: set[str] = set()
        text = f"{cat} {label}"
        for keyword, tech in RULES:
            if keyword in text:
                tid = tech["technique_id"]
                if tid not in seen_ids:
                    matches.append(dict(tech, description=""))
                    seen_ids.add(tid)
                if len(matches) >= TOP_K:
                    break

        # Default if nothing matched
        if not matches:
            matches.append({
                "technique_id":   "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic":         "Execution",
                "description":    "",
                "score":          0.40,
            })

        return matches[:TOP_K]

    # ------------------------------------------------------------------
    # LLM confirmation
    # ------------------------------------------------------------------

    async def _llm_confirm(self, event: NormalizedEvent, candidates: list[dict]) -> Optional[str]:
        """
        Ask Groq to confirm or refine the top MITRE technique match.
        Returns the LLM's reasoning text, or None on failure.
        """
        try:
            if self._llm is None:
                self._llm = get_llm_client(task=GroqTask.MITRE)

            top = candidates[0]
            candidates_text = "\n".join(
                f"  {i+1}. {c['technique_id']} — {c['technique_name']} "
                f"(tactic: {c['tactic']}, score: {c['score']:.2f})"
                for i, c in enumerate(candidates)
            )

            prompt = (
                f"You are a MITRE ATT&CK expert. Analyze this security event and confirm "
                f"the best ATT&CK technique mapping.\n\n"
                f"Event:\n"
                f"  Category   : {event.threat_category}\n"
                f"  Label      : {event.label or 'Unknown'}\n"
                f"  Protocol   : {event.protocol or 'Unknown'}\n"
                f"  Dst Port   : {event.dst_port or 'Unknown'}\n"
                f"  Bytes/sec  : {event.flow_bytes_per_sec or 'N/A'}\n"
                f"  Pkts/sec   : {event.flow_packets_per_sec or 'N/A'}\n\n"
                f"Top candidate techniques (ranked by semantic similarity):\n{candidates_text}\n\n"
                f"Confirm if '{top['technique_id']} — {top['technique_name']}' is correct, "
                f"or suggest a better match from the list. "
                f"Respond in 2-3 sentences. Plain text only, no JSON."
            )

            response = await self._llm.chat(prompt=prompt, temperature=0.1, max_tokens=200)
            return response.text.strip()

        except Exception as exc:
            self.log_warning(f"LLM confirmation failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Resource loading
    # ------------------------------------------------------------------

    def _load_resources(self) -> None:
        """
        Load techniques.json and the FAISS index.
        Called at __init__ so the agent is ready for the first event.
        """
        # Load techniques.json
        if TECHNIQUES_JSON.exists():
            try:
                with open(TECHNIQUES_JSON, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                self._techniques_by_id = raw
                self._technique_list = list(raw.values())
                self.log_info(f"Loaded {len(self._technique_list)} MITRE techniques")
            except Exception as exc:
                self.log_warning(f"Failed to load techniques.json: {exc}")
        else:
            self.log_warning(f"techniques.json not found at {TECHNIQUES_JSON}")

        # Load FAISS index if it exists
        if FAISS_MITRE_INDEX.exists() and FAISS_MITRE_META.exists():
            try:
                import faiss  # type: ignore
                self._faiss_index = faiss.read_index(str(FAISS_MITRE_INDEX))
                with open(FAISS_MITRE_META, "r", encoding="utf-8") as f:
                    self._technique_list = json.load(f)
                self.log_info(
                    f"Loaded MITRE FAISS index: {self._faiss_index.ntotal} vectors"
                )
            except ImportError:
                self.log_warning("faiss-cpu not installed — rule-based fallback will be used")
            except Exception as exc:
                self.log_warning(f"Failed to load FAISS index: {exc}")
        else:
            self.log_info(
                "MITRE FAISS index not found — run scripts/build_mitre_index.py to build it. "
                "Using rule-based fallback until then."
            )

    # ------------------------------------------------------------------
    # Embedding helper
    # ------------------------------------------------------------------

    def _embed_text(self, text: str) -> Optional[np.ndarray]:
        """Embed a text string using all-MiniLM-L6-v2."""
        try:
            if self._embedder is None:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer(EMBEDDING_MODEL)
            vec = self._embedder.encode(text, normalize_embeddings=True)
            return np.array(vec, dtype="float32")
        except ImportError:
            return None
        except Exception as exc:
            self.log_warning(f"Embedding failed: {exc}")
            return None

    @staticmethod
    def _event_to_text(event: NormalizedEvent) -> str:
        """
        Convert NormalizedEvent fields to a text description for embedding.
        Mirrors the text format used when building the MITRE index.
        """
        parts = []
        if event.label and event.label.lower() not in ("unknown", "none", "nan"):
            parts.append(f"attack type: {event.label}")
        parts.append(f"threat category: {event.threat_category}")
        if event.protocol:
            parts.append(f"protocol: {event.protocol}")
        if event.dst_port:
            parts.append(f"destination port: {event.dst_port}")
        if event.flow_bytes_per_sec and event.flow_bytes_per_sec > 100000:
            parts.append("high volume network traffic")
        if event.total_fwd_packets and event.total_bwd_packets:
            ratio = (event.total_fwd_packets / max(event.total_bwd_packets, 1))
            if ratio > 10:
                parts.append("asymmetric packet ratio — possible scan or flood")
        return ". ".join(parts) if parts else str(event.threat_category)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def _check_dependencies(self) -> dict:
        return {
            "healthy":              len(self._technique_list) > 0,
            "techniques_loaded":    len(self._technique_list),
            "faiss_index_loaded":   self._faiss_index is not None,
            "faiss_vectors":        self._faiss_index.ntotal if self._faiss_index else 0,
            "llm_confirmation":     self.use_llm_confirmation,
        }
