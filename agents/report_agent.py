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
"""

from agents.base_agent import BaseAgent
from api.models import AgentResult, NormalizedEvent


class ReportAgent(BaseAgent):
    """Report Generation Agent — Phase 3 implementation."""

    def __init__(self) -> None:
        super().__init__(agent_name="ReportAgent", version="0.1.0")

    def process(self, event: NormalizedEvent) -> AgentResult:
        # TODO: implement in Phase 3
        raise NotImplementedError("ReportAgent.process() will be implemented in Phase 3.")
