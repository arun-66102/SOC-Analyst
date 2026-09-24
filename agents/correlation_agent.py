"""
agents/correlation_agent.py
----------------------------
Log Correlation Engine — groups related security events into incidents
using a sliding time-window algorithm and FAISS semantic similarity.

How it works:
  1. Receives a NormalizedEvent
  2. Embeds the event using sentence-transformers (all-MiniLM-L6-v2)
  3. Searches FAISS alert index for semantically similar past events
  4. Checks if any past similar event is within the time window (default 5 min)
  5. If match found  → assigns existing incident_id
     If no match     → creates new incident_id, adds to index
  6. Asks Groq LLM to write a one-paragraph incident summary

Author  : Member 2 — Phase 2
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

import numpy as np

from agents.base_agent import BaseAgent
from agents.llm_client import GroqTask, get_llm_client
from api.models import AgentResult, CorrelationOutput, NormalizedEvent

# ---------------------------------------------------------------------------
# Correlation window (seconds) — configurable via env
# ---------------------------------------------------------------------------
CORRELATION_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))

# ---------------------------------------------------------------------------
# In-memory incident store:
#   {incident_id: {"event_ids": [...], "timestamps": [...], "src_ips": [...], ...}}
# Reset on process restart — persisted in Phase 3 via PostgreSQL
# ---------------------------------------------------------------------------
_incidents: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# In-memory vector store (event_id -> embedding)
# Used for similarity search when FAISS is not available
# ---------------------------------------------------------------------------
_event_embeddings: dict[str, np.ndarray] = {}
_event_metadata: dict[str, dict] = {}  # event_id -> {incident_id, timestamp, src_ip}


class CorrelationAgent(BaseAgent):
    """
    Log Correlation Agent — Phase 2.

    Groups related events into incidents by:
    1. Source IP + time window matching (primary)
    2. Semantic similarity via FAISS (secondary / fallback)
    3. LLM-generated incident summary
    """

    def __init__(
        self,
        window_seconds: int = CORRELATION_WINDOW_SECONDS,
        similarity_threshold: float = 0.75,
    ) -> None:
        super().__init__(agent_name="CorrelationAgent", version="2.0.0")
        self.window_seconds = window_seconds
        self.similarity_threshold = similarity_threshold
        self._model = None       # sentence-transformer model (lazy init)
        self._llm = None         # Groq client (lazy init)
        self._faiss_available = False

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
        Full correlation pipeline:
          1. Embed the event
          2. Search for matching incident (time-window + semantic)
          3. Assign or create incident_id
          4. Generate LLM incident summary
          5. Return CorrelationOutput
        """
        self.log_info(f"Correlating event {event.event_id}")

        # Lazy init embedder
        embedding = self._embed_event(event)

        # Step 1: Try time-window + source IP matching (fastest)
        incident_id, related_ids, similarity = self._find_incident_by_window(event)

        # Step 2: If no match, try semantic similarity via FAISS / in-memory
        if incident_id is None and embedding is not None:
            incident_id, related_ids, similarity = self._find_incident_by_similarity(
                event, embedding
            )

        # Step 3: Create a new incident if still no match
        is_new_incident = incident_id is None
        if is_new_incident:
            incident_id = self._make_incident_id(event)
            related_ids = []
            similarity = None
            self.log_info(f"New incident created: {incident_id}")
        else:
            self.log_info(f"Event correlated to existing incident: {incident_id}")

        # Step 4: Register event in incident store
        self._register_event(event, incident_id, embedding)

        # Step 5: Generate LLM summary for the incident
        incident_summary = await self._generate_summary(event, incident_id, related_ids)

        output = CorrelationOutput(
            incident_id=incident_id,
            related_event_ids=related_ids,
            time_window_seconds=float(self.window_seconds),
            similarity_score=similarity,
            incident_summary=incident_summary,
        )

        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=0.90 if not is_new_incident else 0.70,
            reasoning=(
                f"Event correlated to incident {incident_id}. "
                f"{len(related_ids)} related event(s) found within "
                f"{self.window_seconds}s window."
            ),
            output=output.model_dump(),
        )

    # ------------------------------------------------------------------
    # Time-window + source IP matching
    # ------------------------------------------------------------------

    def _find_incident_by_window(
        self, event: NormalizedEvent
    ) -> tuple[Optional[str], list[str], Optional[float]]:
        """
        Search existing incidents for events from the same source IP
        within the correlation time window.
        """
        if not event.src_ip:
            return None, [], None

        now = event.timestamp
        if isinstance(now, str):
            now = datetime.fromisoformat(now)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        window_start = now - timedelta(seconds=self.window_seconds)

        for inc_id, inc_data in _incidents.items():
            if event.src_ip not in inc_data.get("src_ips", set()):
                continue
            # Check if any event in the incident is within the window
            for ts_str in inc_data.get("timestamps", []):
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if window_start <= ts <= now:
                    related = [
                        eid for eid in inc_data["event_ids"]
                        if eid != event.event_id
                    ]
                    return inc_id, related, None

        return None, [], None

    # ------------------------------------------------------------------
    # Semantic similarity search (in-memory vectors)
    # ------------------------------------------------------------------

    def _find_incident_by_similarity(
        self, event: NormalizedEvent, embedding: np.ndarray
    ) -> tuple[Optional[str], list[str], Optional[float]]:
        """
        Find the most semantically similar past event using cosine similarity.
        Falls back gracefully if no embeddings are in memory yet.
        """
        if not _event_embeddings:
            return None, [], None

        query = embedding / (np.linalg.norm(embedding) + 1e-10)
        best_score = -1.0
        best_event_id = None

        for eid, vec in _event_embeddings.items():
            if eid == event.event_id:
                continue
            norm_vec = vec / (np.linalg.norm(vec) + 1e-10)
            score = float(np.dot(query, norm_vec))
            if score > best_score:
                best_score = score
                best_event_id = eid

        if best_score >= self.similarity_threshold and best_event_id:
            meta = _event_metadata.get(best_event_id, {})
            inc_id = meta.get("incident_id")
            if inc_id and inc_id in _incidents:
                related = [
                    eid for eid in _incidents[inc_id]["event_ids"]
                    if eid != event.event_id
                ]
                return inc_id, related, round(best_score, 4)

        return None, [], None

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    def _embed_event(self, event: NormalizedEvent) -> Optional[np.ndarray]:
        """
        Embed a NormalizedEvent as a 384-dim vector using sentence-transformers.
        Returns None if the library is not installed.
        """
        try:
            if self._model is None:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer("all-MiniLM-L6-v2")
            text = self._event_to_text(event)
            vec = self._model.encode(text, normalize_embeddings=True)
            return np.array(vec, dtype="float32")
        except ImportError:
            self.log_warning("sentence-transformers not installed — embedding disabled")
            return None
        except Exception as exc:
            self.log_warning(f"Embedding failed: {exc}")
            return None

    @staticmethod
    def _event_to_text(event: NormalizedEvent) -> str:
        """Convert a NormalizedEvent to a text string for embedding."""
        parts = [
            f"category:{event.threat_category}",
            f"label:{event.label or 'unknown'}",
            f"protocol:{event.protocol or 'unknown'}",
            f"dst_port:{event.dst_port or 0}",
            f"src_ip:{event.src_ip or 'unknown'}",
        ]
        if event.flow_bytes_per_sec:
            parts.append(f"bytes_per_sec:{int(event.flow_bytes_per_sec)}")
        if event.flow_packets_per_sec:
            parts.append(f"pkts_per_sec:{int(event.flow_packets_per_sec)}")
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Incident store helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_incident_id(event: NormalizedEvent) -> str:
        """
        Generate a deterministic incident ID from the event's source IP
        and threat category. Falls back to event_id hash if src_ip is None.
        """
        seed = f"{event.src_ip or event.event_id}:{event.threat_category}"
        return "INC-" + hashlib.sha1(seed.encode()).hexdigest()[:8].upper()

    def _register_event(
        self,
        event: NormalizedEvent,
        incident_id: str,
        embedding: Optional[np.ndarray],
    ) -> None:
        """Add this event to the in-memory incident store and embedding index."""
        if incident_id not in _incidents:
            _incidents[incident_id] = {
                "event_ids":  [],
                "timestamps": [],
                "src_ips":    set(),
            }

        inc = _incidents[incident_id]
        if event.event_id not in inc["event_ids"]:
            inc["event_ids"].append(event.event_id)
        ts = event.timestamp
        inc["timestamps"].append(ts.isoformat() if hasattr(ts, "isoformat") else str(ts))
        if event.src_ip:
            inc["src_ips"].add(event.src_ip)

        # Store embedding
        if embedding is not None:
            _event_embeddings[event.event_id] = embedding
            _event_metadata[event.event_id] = {
                "incident_id": incident_id,
                "timestamp":   str(event.timestamp),
                "src_ip":      event.src_ip,
            }

    # ------------------------------------------------------------------
    # LLM incident summary
    # ------------------------------------------------------------------

    async def _generate_summary(
        self,
        event: NormalizedEvent,
        incident_id: str,
        related_ids: list[str],
    ) -> str:
        """
        Ask the Groq LLM to write a one-paragraph incident summary.
        Returns a fallback string if the LLM call fails.
        """
        try:
            if self._llm is None:
                self._llm = get_llm_client(task=GroqTask.CORRELATION)

            total_events = len(_incidents.get(incident_id, {}).get("event_ids", [])) + 1
            prompt = (
                f"You are a SOC analyst writing a brief incident summary.\n"
                f"Incident ID: {incident_id}\n"
                f"Latest event: category={event.threat_category}, "
                f"label={event.label}, protocol={event.protocol}, "
                f"dst_port={event.dst_port}, src_ip={event.src_ip}\n"
                f"Total correlated events: {total_events}\n"
                f"Related event IDs: {related_ids[:5]}\n\n"
                f"Write a concise 2-3 sentence incident summary describing what is happening, "
                f"the likely attack scenario, and the potential impact. "
                f"Do not include any JSON — plain text only."
            )

            response = await self._llm.chat(prompt=prompt, temperature=0.2, max_tokens=200)
            return response.text.strip()

        except Exception as exc:
            self.log_warning(f"LLM summary generation failed: {exc}")
            return (
                f"Incident {incident_id}: {event.threat_category} activity detected from "
                f"{event.src_ip or 'unknown source'} targeting port {event.dst_port or 'N/A'}. "
                f"Correlated with {len(related_ids)} related event(s). "
                f"Manual analyst review recommended."
            )

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def _check_dependencies(self) -> dict:
        import os
        return {
            "healthy":       bool(os.getenv("GROQ_API_KEY")),
            "window_seconds": self.window_seconds,
            "incidents_tracked": len(_incidents),
            "embeddings_indexed": len(_event_embeddings),
        }
