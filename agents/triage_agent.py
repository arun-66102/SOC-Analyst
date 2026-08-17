"""
triage_agent.py
---------------
Alert Triage Agent — classifies each security event as
Critical / High / Medium / Low and determines True/False Positive.

TODO (Member 1 — Phase 2):
  - Implement process() with Gemini API prompt
  - Add few-shot examples in agents/prompts/triage_prompts.py
  - Save result to Neon PostgreSQL
  - Write tests in tests/test_triage.py
"""

from agents.base_agent import BaseAgent
from api.models import AgentResult, NormalizedEvent


class TriageAgent(BaseAgent):
    """Triage Agent — Phase 2 implementation."""

    def __init__(self) -> None:
        super().__init__(agent_name="TriageAgent", version="0.1.0")

    def process(self, event: NormalizedEvent) -> AgentResult:
        # TODO: implement in Phase 2
        raise NotImplementedError("TriageAgent.process() will be implemented in Phase 2.")
