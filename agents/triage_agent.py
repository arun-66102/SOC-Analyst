"""
agents/triage_agent.py
-----------------------
Alert Triage Agent — classifies each security event as
Critical / High / Medium / Low severity and determines True/False Positive.

How it works:
  1. Takes a NormalizedEvent as input
  2. Builds a structured prompt using few-shot examples (triage_prompts.py)
  3. Sends to Groq LLM (openai/gpt-oss-120b by default)
  4. Parses the JSON response into a TriageOutput
  5. Returns an AgentResult with severity, confidence, and reasoning

Author  : Member 1 — Phase 2
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Optional

from agents.base_agent import BaseAgent
from agents.llm_client import GroqTask, get_llm_client
from agents.prompts.triage_prompts import TRIAGE_SYSTEM_PROMPT, build_triage_prompt
from api.models import AgentResult, NormalizedEvent, SeverityLevel, TriageOutput


class TriageAgent(BaseAgent):
    """
    Alert Triage Agent — Phase 2.

    Classifies incoming security events by severity (Critical/High/Medium/Low)
    and determines whether each event is a true or false positive.

    Usage
    -----
    agent = TriageAgent()
    result = agent.run(event)          # sync wrapper from BaseAgent
    # or directly:
    result = await agent.process_async(event)
    """

    def __init__(self) -> None:
        super().__init__(agent_name="TriageAgent", version="2.0.0")
        self._llm = None  # lazy init — avoids import-time API key check

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def process(self, event: NormalizedEvent) -> AgentResult:
        """
        Synchronous entry point required by BaseAgent.
        Runs the async process_async() via asyncio.run().
        """
        return asyncio.run(self.process_async(event))

    # ------------------------------------------------------------------
    # Core async logic
    # ------------------------------------------------------------------

    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        """
        Full triage pipeline:
          1. Build prompt with few-shot examples
          2. Call Groq LLM
          3. Parse JSON response
          4. Return structured AgentResult
        """
        self.log_info(f"Triaging event {event.event_id} (category={event.threat_category})")

        # Lazy-init LLM client
        if self._llm is None:
            self._llm = get_llm_client(task=GroqTask.TRIAGE)

        # Build prompt
        prompt = build_triage_prompt(event)

        # Call LLM
        try:
            response = await self._llm.chat(
                prompt=prompt,
                system=TRIAGE_SYSTEM_PROMPT,
                temperature=0.1,
            )
            self.log_info(
                f"LLM responded ({response.input_tokens} in / {response.output_tokens} out tokens)"
            )
            llm_text = response.text
        except Exception as llm_exc:
            self.log_warning(f"LLM call failed: {llm_exc} — using heuristic fallback")
            llm_text = ""  # will trigger heuristic fallback inside _parse_response

        # Parse response
        triage_output = self._parse_response(llm_text, event)

        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=triage_output.confidence,
            reasoning=triage_output.reasoning,
            output={
                "severity":           triage_output.severity,
                "is_true_positive":   triage_output.is_true_positive,
                "confidence":         triage_output.confidence,
                "reasoning":          triage_output.reasoning,
                "recommended_action": triage_output.recommended_action,
            },
        )

    # ------------------------------------------------------------------
    # Response parser
    # ------------------------------------------------------------------

    def _parse_response(self, text: str, event: NormalizedEvent) -> TriageOutput:
        """
        Parse the LLM JSON response into a TriageOutput.

        Falls back to a heuristic rule-based triage if parsing fails,
        so the pipeline never crashes on a malformed LLM response.
        """
        try:
            # Strip markdown code fences if present
            clean = re.sub(r"```(?:json)?", "", text).strip()
            # Extract the first JSON object
            match = re.search(r"\{.*\}", clean, re.DOTALL)
            if not match:
                raise ValueError("No JSON object found in LLM response")

            data = json.loads(match.group())

            # Normalise severity — handle mixed case
            severity_raw = str(data.get("severity", "Medium")).capitalize()
            # Map to valid enum value
            severity_map = {
                "Critical": SeverityLevel.CRITICAL,
                "High":     SeverityLevel.HIGH,
                "Medium":   SeverityLevel.MEDIUM,
                "Low":      SeverityLevel.LOW,
            }
            severity = severity_map.get(severity_raw, SeverityLevel.MEDIUM)

            return TriageOutput(
                severity=severity,
                is_true_positive=bool(data.get("is_true_positive", True)),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=str(data.get("reasoning", "LLM provided no reasoning.")),
                recommended_action=data.get("recommended_action"),
            )

        except Exception as exc:
            self.log_warning(f"LLM response parse failed ({exc}) — using heuristic fallback")
            return self._heuristic_fallback(event)

    # ------------------------------------------------------------------
    # Heuristic fallback (no LLM needed) — used when parsing fails
    # ------------------------------------------------------------------

    def _heuristic_fallback(self, event: NormalizedEvent) -> TriageOutput:
        """
        Rule-based triage as a fallback when LLM response is unparseable.
        Based purely on threat_category and flow metrics.
        """
        cat = str(event.threat_category).lower()  # e.g. "PortScan" -> "portscan"

        if "ddos" in cat or "exfiltration" in cat or "infiltration" in cat:
            severity = SeverityLevel.CRITICAL
            is_tp = True
            confidence = 0.80
            reasoning = (
                f"Heuristic: {event.threat_category} category detected. "
                "High-severity category with no LLM confirmation available."
            )
            action = "Investigate immediately. Apply perimeter block on source IP."

        elif "brute" in cat or "port_scan" in cat or "portscan" in cat or "botnet" in cat or "malware" in cat or "backdoor" in cat:
            severity = SeverityLevel.HIGH
            is_tp = True
            confidence = 0.75
            reasoning = (
                f"Heuristic: {event.threat_category} category. "
                "Elevated threat activity detected from network flow metrics."
            )
            action = "Block source IP. Escalate to Tier 2 analyst."

        elif "dos" in cat or "web_attack" in cat or "webattack" in cat or "reconnaissance" in cat:
            severity = SeverityLevel.MEDIUM
            is_tp = True
            confidence = 0.65
            reasoning = (
                f"Heuristic: {event.threat_category} category. "
                "Moderate threat — further analysis required."
            )
            action = "Monitor and log. Alert on escalation."

        elif "benign" in cat:
            severity = SeverityLevel.LOW
            is_tp = False
            confidence = 0.90
            reasoning = "Heuristic: BENIGN category — traffic pattern consistent with normal activity."
            action = "No action required."

        else:
            severity = SeverityLevel.MEDIUM
            is_tp = True
            confidence = 0.50
            reasoning = "Heuristic: Unknown category — defaulting to Medium severity for analyst review."
            action = "Review event manually. Apply standard monitoring."

        return TriageOutput(
            severity=severity,
            is_true_positive=is_tp,
            confidence=confidence,
            reasoning=reasoning,
            recommended_action=action,
        )

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def _check_dependencies(self) -> dict:
        """Verify GROQ_API_KEY is set before pipeline starts."""
        import os
        api_key = os.getenv("GROQ_API_KEY", "")
        return {
            "healthy":     bool(api_key),
            "groq_key_set": bool(api_key),
            "model":       "openai/gpt-oss-120b (via GROQ_MODEL_TRIAGE env)",
        }
