"""
report_agent.py
---------------
Investigation Report Generation Agent — produces structured
investigation reports from fully processed incidents.

Phase 3 Member 3 Implementation:
  - Takes correlated incident (triage + MITRE + enrichment data)
  - Calculates risk score from severity + enrichment confidence
  - Generates executive summary, evidence, and recommended actions via Groq
  - Renders to HTML using Jinja2 template (templates/report.html)

Author  : Member 3 — Phase 3
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.base_agent import BaseAgent
from agents.llm_client import GroqTask, get_llm_client
from api.models import AgentResult, NormalizedEvent


# ---------------------------------------------------------------------------
# System prompt for the Groq report-generation task
# ---------------------------------------------------------------------------
_REPORT_SYSTEM = (
    "You are a senior SOC analyst writing formal investigation reports. "
    "Return ONLY valid JSON — no markdown fences, no preamble. "
    "Keys required: summary (str), evidence (list[str]), "
    "risk_level (one of Critical|High|Medium|Low|Unknown), "
    "recommended_actions (list[str]). "
    "Do NOT invent facts; use only the event data supplied."
)


class ReportAgent(BaseAgent):
    """
    Report Generation Agent — Phase 3 implementation.

    Generates a structured investigation report for a fully-processed
    NormalizedEvent and renders it to an HTML file via Jinja2.

    Exposes:
      - process(event)         → raises NotImplementedError (use process_async)
      - process_async(event)   → returns AgentResult with report payload
      - _calculate_risk_score  → 0-100 composite risk score
      - _build_context         → dict of template variables
    """

    def __init__(self) -> None:
        super().__init__(agent_name="ReportAgent", version="1.0.0")
        self.template_path = Path("templates/report.html")
        self.output_dir = Path("reports/generated")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Dependency check
    # ------------------------------------------------------------------
    def _check_dependencies(self) -> dict[str, Any]:
        groq_key = os.getenv("GROQ_API_KEY", "")
        jinja_ok = True
        try:
            import jinja2  # noqa: F401
        except ImportError:
            jinja_ok = False
        return {
            "healthy": bool(groq_key),
            "groq_key_set": bool(groq_key),
            "jinja2_available": jinja_ok,
            "template_exists": self.template_path.exists(),
        }

    # ------------------------------------------------------------------
    # Risk scoring: combines severity level and enrichment confidence
    # ------------------------------------------------------------------
    def _calculate_risk_score(self, event: NormalizedEvent) -> float:
        """
        Calculate a composite risk score in the range [0, 100].

        Formula:
            risk_score = (severity_base * 0.7) + (enrichment_confidence * 100 * 0.3)

        Returns
        -------
        float
            Risk score rounded to 2 decimal places.
        """
        severity_scores: dict[str, float] = {
            "Critical": 100.0,
            "High":     80.0,
            "Medium":   55.0,
            "Low":      25.0,
            "Unknown":  10.0,
        }

        # Handle both enum and plain string severity values
        severity = str(event.severity)
        if "." in severity:
            severity = severity.split(".")[-1]

        base_score = severity_scores.get(severity, 10.0)

        enrichment = event.enrichment_data or {}
        try:
            confidence = float(enrichment.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        # AbuseIPDB confidence bonus: if > 80 add 5 pts
        abuseipdb = enrichment.get("abuseipdb_score", 0) or 0
        try:
            abuseipdb = int(abuseipdb)
        except (TypeError, ValueError):
            abuseipdb = 0
        abuseipdb_bonus = 5.0 if abuseipdb > 80 else 0.0

        score = (base_score * 0.7) + (confidence * 100 * 0.3) + abuseipdb_bonus
        return round(min(score, 100.0), 2)

    # ------------------------------------------------------------------
    # Build Jinja2 / LLM prompt context dict from a NormalizedEvent
    # ------------------------------------------------------------------
    def _build_context(self, event: NormalizedEvent) -> dict[str, Any]:
        """
        Build the template-rendering context from a processed event.

        Returns
        -------
        dict
            All variables injected into the Jinja2 template and the LLM prompt.
        """
        enrichment = event.enrichment_data or {}

        severity = str(event.severity)
        if "." in severity:
            severity = severity.split(".")[-1]

        threat_category = str(event.threat_category)
        if "." in threat_category:
            threat_category = threat_category.split(".")[-1]

        status = str(event.status)
        if "." in status:
            status = status.split(".")[-1]

        return {
            "event_id":           event.event_id,
            "incident_id":        event.incident_id or event.event_id,
            "timestamp":          event.timestamp.isoformat()
                                  if hasattr(event.timestamp, "isoformat")
                                  else str(event.timestamp),
            "generated_at":       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "src_ip":             event.src_ip or "N/A",
            "dst_ip":             event.dst_ip or "N/A",
            "src_port":           event.src_port,
            "dst_port":           event.dst_port,
            "protocol":           event.protocol or "N/A",
            "severity":           severity,
            "threat_category":    threat_category,
            "status":             status,
            "is_true_positive":   event.is_true_positive,
            "correlation_summary": event.correlation_summary or "",
            "mitre_techniques":   event.mitre_techniques or [],
            "enrichment_data":    enrichment,
            "risk_score":         self._calculate_risk_score(event),
            # Enrichment convenience fields
            "is_malicious":       enrichment.get("is_malicious", False),
            "virustotal_score":   enrichment.get("virustotal_score", "N/A"),
            "abuseipdb_score":    enrichment.get("abuseipdb_score", 0),
            "threat_labels":      enrichment.get("threat_labels", []),
        }

    # ------------------------------------------------------------------
    # LLM call: generate summary, evidence, risk_level, actions
    # ------------------------------------------------------------------
    async def _generate_report_content(
        self, context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Call Groq to generate executive summary, evidence items,
        risk_level, and recommended_actions.

        Falls back to a heuristic response if the LLM is unavailable
        or returns malformed JSON.

        Returns
        -------
        dict
            Keys: summary, evidence, risk_level, recommended_actions
        """
        # Build a compact event description for the prompt
        prompt = f"""Analyze this security event and produce an investigation report.

Event data:
{json.dumps(context, default=str, indent=2)}

Return ONLY a JSON object with these exact keys:
{{
  "summary": "2-3 sentence executive summary of the incident",
  "evidence": ["evidence item 1", "evidence item 2", "evidence item 3"],
  "risk_level": "Critical|High|Medium|Low|Unknown",
  "recommended_actions": ["action 1", "action 2", "action 3"]
}}

Base your analysis strictly on the event data above. Do not invent IPs, domains, or file names not present in the data.
"""
        try:
            client = get_llm_client(task=GroqTask.REPORT)
            response = await client.chat(prompt=prompt, system=_REPORT_SYSTEM)
            text = response.text.strip()

            # Strip markdown code fences if the model adds them
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
            text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
            text = text.strip()

            return json.loads(text)

        except Exception as exc:
            self.log_warning(f"LLM report generation failed, using heuristic: {exc}")
            return self._heuristic_report(context)

    # ------------------------------------------------------------------
    # Heuristic fallback (no LLM / API key not set)
    # ------------------------------------------------------------------
    def _heuristic_report(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Generate a templated report without calling the LLM."""
        severity = ctx.get("severity", "Unknown")
        category = ctx.get("threat_category", "Unknown")
        src_ip   = ctx.get("src_ip", "unknown source")
        dst_ip   = ctx.get("dst_ip", "unknown destination")
        dst_port = ctx.get("dst_port", "unknown port")
        risk     = ctx.get("risk_score", 0)

        summary = (
            f"A {severity.lower()}-severity {category} event was detected from {src_ip} "
            f"targeting {dst_ip}:{dst_port}. "
            f"The computed risk score is {risk}/100. "
            f"Immediate investigation and containment measures are recommended."
        )

        evidence = [
            f"Source IP: {src_ip}",
            f"Destination: {dst_ip}:{dst_port}",
            f"Protocol: {ctx.get('protocol', 'Unknown')}",
            f"Threat category: {category}",
            f"Severity level: {severity}",
        ]
        if ctx.get("mitre_techniques"):
            evidence.append(f"MITRE ATT&CK techniques: {', '.join(ctx['mitre_techniques'])}")
        if ctx.get("is_malicious"):
            evidence.append("Threat intelligence confirms malicious activity.")

        actions = [
            f"Block source IP {src_ip} at perimeter firewall.",
            f"Inspect and close port {dst_port} on {dst_ip} if not required.",
            "Rotate credentials on any potentially compromised systems.",
            "Preserve system and network logs for forensic analysis.",
            "Review adjacent alerts for signs of lateral movement.",
        ]

        return {
            "summary":              summary,
            "evidence":             evidence,
            "risk_level":           severity,
            "recommended_actions":  actions,
        }

    # ------------------------------------------------------------------
    # Render Jinja2 HTML report to disk
    # ------------------------------------------------------------------
    def _render_html(
        self,
        context: dict[str, Any],
        report: dict[str, Any],
    ) -> str:
        """
        Render the Jinja2 template to an HTML file.

        Parameters
        ----------
        context : dict
            Variables from _build_context().
        report : dict
            LLM / heuristic output (summary, evidence, …).

        Returns
        -------
        str
            Absolute path to the generated HTML file, or "" on failure.
        """
        if not self.template_path.exists():
            self.log_warning(f"Template not found: {self.template_path}. Skipping HTML render.")
            return ""

        try:
            from jinja2 import Environment, FileSystemLoader

            env = Environment(
                loader=FileSystemLoader(str(self.template_path.parent)),
                autoescape=True,
            )
            template = env.get_template(self.template_path.name)

            html = template.render(
                **context,
                summary=report.get("summary", ""),
                evidence=report.get("evidence", []),
                risk_level=report.get("risk_level", context["severity"]),
                recommended_actions=report.get("recommended_actions", []),
            )

            out_file = self.output_dir / f"{context['incident_id']}.html"
            out_file.write_text(html, encoding="utf-8")
            self.log_info(f"HTML report written to {out_file}")
            return str(out_file)

        except Exception as exc:
            self.log_warning(f"HTML render failed: {exc}")
            return ""

    # ------------------------------------------------------------------
    # BaseAgent interface — synchronous process() is not supported
    # ------------------------------------------------------------------
    def process(self, event: NormalizedEvent) -> AgentResult:
        """
        Synchronous process() entry point.

        The orchestrator calls process_async() for this agent.
        Calling process() directly will raise NotImplementedError.
        """
        raise NotImplementedError(
            "ReportAgent is async-only. Use process_async() or "
            "call via the orchestrator's run_pipeline_async()."
        )

    # ------------------------------------------------------------------
    # Async process — main entry point
    # ------------------------------------------------------------------
    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        """
        Generate a full investigation report for the given event.

        Pipeline:
          1. Build context dict from the event
          2. Call Groq to generate narrative / evidence / actions
          3. Render HTML report to disk via Jinja2
          4. Return AgentResult with full report payload

        Parameters
        ----------
        event : NormalizedEvent
            A fully processed event (should have gone through Triage,
            Correlation, MITRE, and Enrichment stages first).

        Returns
        -------
        AgentResult
            Output dict contains: incident_id, risk_score, risk_level,
            summary, evidence, recommended_actions, html_report (path).
        """
        context = self._build_context(event)
        report  = await self._generate_report_content(context)
        html_path = self._render_html(context, report)

        return AgentResult(
            event_id=event.event_id,
            agent_name=self.agent_name,
            status="success",
            confidence=round(context["risk_score"] / 100.0, 4),
            reasoning=report.get("summary", "Investigation report generated."),
            output={
                "incident_id":         context["incident_id"],
                "risk_score":          context["risk_score"],
                "risk_level":          report.get("risk_level", context["severity"]),
                "summary":             report.get("summary", ""),
                "evidence":            report.get("evidence", []),
                "recommended_actions": report.get("recommended_actions", []),
                "html_report":         html_path,
                "generated_at":        context["generated_at"],
            },
        )