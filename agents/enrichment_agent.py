"""
enrichment_agent.py
-------------------
Threat Intelligence Enrichment Agent — queries VirusTotal and AbuseIPDB
to determine if IPs/domains/hashes are malicious.

TODO (Member 1 — Phase 3):
  - Query VirusTotal Free API (rate limit: 4 req/min)
  - Query AbuseIPDB Free API (rate limit: 1000 req/day)
  - Implement exponential back-off retry logic
  - Run Chain-of-Thought investigation reasoning via Gemini
"""

from agents.base_agent import BaseAgent
from api.models import AgentResult, NormalizedEvent


class EnrichmentAgent(BaseAgent):
    """Enrichment Agent — Phase 3 implementation."""

    def __init__(self) -> None:
        super().__init__(agent_name="EnrichmentAgent", version="0.1.0")

    def process(self, event: NormalizedEvent) -> AgentResult:
        # TODO: implement in Phase 3
        raise NotImplementedError("EnrichmentAgent.process() will be implemented in Phase 3.")
