"""Phase 3 Member 1: structured investigation reasoning using Groq."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from agents.base_agent import BaseAgent
from agents.llm_client import GroqTask, get_llm_client
from api.models import AgentResult, NormalizedEvent, SeverityLevel

SYSTEM = """You are a senior SOC analyst. Analyze the supplied security incident using only the evidence provided. Do not invent facts. Return ONLY valid JSON with keys: summary, evidence, risk_level, recommended_actions, confidence. evidence and recommended_actions must be arrays of short strings. risk_level must be one of Critical, High, Medium, Low, Unknown. confidence must be a number from 0 to 1. Provide concise analyst-facing justification, not hidden chain-of-thought."""


class InvestigationAgent(BaseAgent):
    """Combines triage, correlation, MITRE and threat-intel evidence."""

    def __init__(self) -> None:
        super().__init__(agent_name="InvestigationAgent", version="1.0.0")
        self._llm = None

    def _check_dependencies(self) -> dict[str, Any]:
        try:
            from agents.llm_client import GROQ_API_KEY
            return {"healthy": bool(GROQ_API_KEY), "groq_configured": bool(GROQ_API_KEY)}
        except Exception:
            return {"healthy": False, "groq_configured": False}

    def process(self, event: NormalizedEvent) -> AgentResult:
        return asyncio.run(self.process_async(event))

    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        if self._llm is None:
            self._llm = get_llm_client(task=GroqTask.REPORT)
        prompt = self._build_prompt(event)
        try:
            response = await self._llm.chat(prompt, system=SYSTEM, temperature=0.1, max_tokens=1200)
            data = self._parse(response.text)
        except Exception as exc:
            self.log_warning(f"Investigation LLM failed: {exc}")
            data = self._fallback(event, str(exc))

        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=float(data.get("confidence", 0.0)),
            reasoning=str(data.get("summary", "Investigation completed.")),
            output=data,
        )

    def _build_prompt(self, event: NormalizedEvent) -> str:
        evidence = {
            "event": event.model_dump(mode="json"),
            "triage": {
                "severity": event.severity,
                "true_positive": event.is_true_positive,
            },
            "correlation": {
                "incident_id": event.incident_id,
                "summary": getattr(event, "correlation_summary", None),
            },
            "mitre_techniques": event.mitre_techniques,
            "threat_intelligence": event.enrichment_data,
        }
        return "Investigate this correlated SOC event:\n" + json.dumps(evidence, indent=2, default=str)

    @staticmethod
    def _parse(text: str) -> dict[str, Any]:
        clean = re.sub(r"```(?:json)?", "", text or "").strip()
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if not match:
            raise ValueError("No JSON object in investigation response")
        data = json.loads(match.group())
        severity = str(data.get("risk_level", "Unknown")).capitalize()
        if severity not in {s.value for s in SeverityLevel}:
            severity = "Unknown"
        return {
            "summary": str(data.get("summary", "No summary provided.")),
            "evidence": [str(x) for x in (data.get("evidence") or [])][:10],
            "risk_level": severity,
            "recommended_actions": [str(x) for x in (data.get("recommended_actions") or [])][:10],
            "confidence": max(0.0, min(1.0, float(data.get("confidence", 0.5)))),
        }

    @staticmethod
    def _fallback(event: NormalizedEvent, error: str) -> dict[str, Any]:
        return {
            "summary": f"Investigation fallback for incident {event.incident_id or 'unassigned'}; LLM unavailable.",
            "evidence": [
                f"Severity: {event.severity}",
                f"True positive: {event.is_true_positive}",
                f"MITRE techniques: {', '.join(event.mitre_techniques) or 'none'}",
                f"Threat intelligence available: {bool(event.enrichment_data)}",
            ],
            "risk_level": str(event.severity),
            "recommended_actions": ["Review the correlated events and validate the threat-intelligence findings."],
            "confidence": 0.35,
            "llm_error": error,
        }
