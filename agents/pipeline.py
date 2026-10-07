"""Build the shared Phase 3 orchestrator."""
from __future__ import annotations

from agents.orchestrator import Orchestrator
from agents.triage_agent import TriageAgent
from agents.correlation_agent import CorrelationAgent
from agents.mitre_agent import MITREAgent
from agents.enrichment_agent import EnrichmentAgent
from agents.investigation_agent import InvestigationAgent

_orchestrator: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
        _orchestrator.register_agent("triage", TriageAgent())
        _orchestrator.register_agent("correlation", CorrelationAgent())
        _orchestrator.register_agent("mitre", MITREAgent())
        _orchestrator.register_agent("enrichment", EnrichmentAgent())
        _orchestrator.register_agent("investigation", InvestigationAgent())
        # ReportAgent intentionally not registered: it is Phase 3 Member 3.
    return _orchestrator
