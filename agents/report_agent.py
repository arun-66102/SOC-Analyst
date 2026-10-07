"""
report_agent.py
---------------
Investigation Report Generation Agent — produces structured HTML/PDF
investigation reports from fully processed incidents.

TODO (Member 3 — Phase 3):
  - Take correlated incident (triage + MITRE + enrichment data)
  - Generate report sections via Gemini
  - Render to HTML using Jinja2 template (templates/report.html)
  - Export to PDF using ReportLab or WeasyPrint
  - Calculate risk score from severity + enrichment confidence


from agents.base_agent import BaseAgent
from api.models import AgentResult, NormalizedEvent


class ReportAgent(BaseAgent):
Report Generation Agent — Phase 3 implementation.

    def __init__(self) -> None:
        super().__init__(agent_name="ReportAgent", version="0.1.0")

    def process(self, event: NormalizedEvent) -> AgentResult:
        # TODO: implement in Phase 3
        raise NotImplementedError("ReportAgent.process() will be implemented in Phase 3.")nd"""


from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.base_agent import BaseAgent
from agents.llm_client import GroqTask, get_llm_client
from api.models import AgentResult, NormalizedEvent


class ReportAgent(BaseAgent):
    """
    Report Generation Agent.

    Generates:
    - Investigation summary
    - Evidence
    - Risk assessment
    - Recommended actions
    - HTML investigation report
    - PDF-ready report data

    Uses Groq for investigation report generation.
    """

    def __init__(self) -> None:
        super().__init__(
            agent_name="ReportAgent",
            version="1.0.0"
        )

        self.template_path = Path("templates/report.html")
        self.output_dir = Path("reports/generated")

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    def _calculate_risk_score(
        self,
        event: NormalizedEvent
    ) -> float:
        """
        Calculate a simple risk score using severity and
        enrichment confidence.

        Returns a score from 0 to 100.
        """

        severity_scores = {
            "Critical": 100,
            "High": 80,
            "Medium": 60,
            "Low": 30,
            "Unknown": 10
        }

        severity = str(event.severity)

        if "." in severity:
            severity = severity.split(".")[-1]

        base_score = severity_scores.get(
            severity,
            10
        )

        enrichment = event.enrichment_data or {}

        confidence = enrichment.get(
            "confidence",
            0
        )

        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0

        confidence = max(
            0.0,
            min(1.0, confidence)
        )

        # Combine severity and enrichment confidence.
        score = (
            (base_score * 0.7)
            + (confidence * 100 * 0.3)
        )

        return round(
            min(score, 100),
            2
        )

    def _build_context(
        self,
        event: NormalizedEvent
    ) -> dict[str, Any]:

        enrichment = event.enrichment_data or {}

        return {
            "event_id": event.event_id,
            "incident_id": event.incident_id or event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "severity": str(event.severity),
            "threat_category": str(event.threat_category),
            "status": str(event.status),
            "correlation_summary": event.correlation_summary,
            "mitre_techniques": event.mitre_techniques,
            "enrichment_data": enrichment,
            "risk_score": self._calculate_risk_score(event),
        }

    async def _generate_report_content(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:

        client = get_llm_client(
            task=GroqTask.REPORT
        )

        prompt = f"""
You are a cybersecurity SOC analyst.

Generate a concise investigation report from the following
security event.

Return ONLY valid JSON with these fields:

{{
    "summary": "short incident summary",
    "evidence": ["evidence 1", "evidence 2"],
    "risk_level": "Critical|High|Medium|Low|Unknown",
    "recommended_actions": [
        "action 1",
        "action 2"
    ]
}}

Do not invent evidence.
Use only the information provided.

Security event:

{json.dumps(context, default=str, indent=2)}
"""

        response = await client.chat(
            prompt=prompt,
            system=(
                "You are an experienced SOC analyst. "
                "Produce factual, concise investigation reports."
            )
        )

        text = response.text.strip()

        # Remove markdown JSON fences if the model adds them.
        if text.startswith("```"):
            text = text.replace("```json", "")
            text = text.replace("```", "")
            text = text.strip()

        try:
            return json.loads(text)

        except json.JSONDecodeError:
            # Safe fallback if the model does not return valid JSON.
            return {
                "summary": text,
                "evidence": [],
                "risk_level": str(context["severity"]),
                "recommended_actions": [
                    "Review the alert manually.",
                    "Investigate the source and destination systems.",
                    "Validate the associated threat intelligence."
                ]
            }

    def _render_html(
        self,
        context: dict[str, Any],
        report: dict[str, Any]
    ) -> str:

        if not self.template_path.exists():
            raise FileNotFoundError(
                f"Report template not found: {self.template_path}"
            )

        from jinja2 import Template

        template_text = self.template_path.read_text(
            encoding="utf-8"
        )

        template = Template(template_text)

        html = template.render(
            **context,
            summary=report.get("summary", ""),
            evidence=report.get("evidence", []),
            risk_level=report.get(
                "risk_level",
                context["severity"]
            ),
            recommended_actions=report.get(
                "recommended_actions",
                []
            )
        )

        output_file = (
            self.output_dir
            / f"{context['incident_id']}.html"
        )

        output_file.write_text(
            html,
            encoding="utf-8"
        )

        return str(output_file)

    def process(
        self,
        event: NormalizedEvent
    ) -> AgentResult:

        context = self._build_context(event)

        # Report generation requires the async Groq client,
        # while BaseAgent.process() is synchronous.
        #
        # The orchestrator should use process_async() for this agent.
        raise NotImplementedError(
            "Use ReportAgent.process_async() for report generation."
        )

    async def process_async(
        self,
        event: NormalizedEvent
    ) -> AgentResult:

        context = self._build_context(event)

        report = await self._generate_report_content(
            context
        )

        html_path = self._render_html(
            context,
            report
        )

        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=float(
                context["risk_score"]
            ) / 100.0,
            reasoning=report.get(
                "summary",
                "Investigation report generated."
            ),
            output={
                "incident_id": context["incident_id"],
                "risk_score": context["risk_score"],
                "risk_level": report.get(
                    "risk_level",
                    context["severity"]
                ),
                "summary": report.get(
                    "summary",
                    ""
                ),
                "evidence": report.get(
                    "evidence",
                    []
                ),
                "recommended_actions": report.get(
                    "recommended_actions",
                    []
                ),
                "html_report": html_path
            }
        )