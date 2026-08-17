"""
orchestrator.py
---------------
Central pipeline controller that routes NormalizedEvents through
the agent chain:

  NormalizedEvent
      → TriageAgent
      → CorrelationAgent
      → MITREAgent
      → EnrichmentAgent
      → ReportAgent
      → AnalyzeResponse

The orchestrator is the ONLY component that knows about all agents.
Individual agents are fully decoupled from each other.

Author  : Member 1 — Project Lead
Phase   : 1 (skeleton) → Phase 3 (full wiring)
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from api.models import AgentResult, AnalyzeResponse, NormalizedEvent

logger = logging.getLogger("orchestrator")


class Orchestrator:
    """
    Runs the full SOC Analyst agent pipeline on a NormalizedEvent.

    Agent slots are filled lazily — the orchestrator starts with None
    placeholders and agents are registered via `register_agent()`.
    This allows phases to be delivered incrementally without breaking
    the API skeleton.

    Usage
    -----
    orchestrator = Orchestrator()
    orchestrator.register_agent("triage", triage_agent_instance)
    result = orchestrator.run_pipeline(event)
    """

    def __init__(self) -> None:
        # Ordered pipeline stages — filled as agents are built across phases
        self._agents: dict[str, Optional[object]] = {
            "triage": None,       # Phase 2 — Member 1
            "correlation": None,  # Phase 2 — Member 2
            "mitre": None,        # Phase 2 — Member 3
            "enrichment": None,   # Phase 3 — Member 1
            "report": None,       # Phase 3 — Member 3
        }
        logger.info("Orchestrator initialised (pipeline stages: %s)", list(self._agents))

    # ------------------------------------------------------------------
    # Agent registration
    # ------------------------------------------------------------------
    def register_agent(self, stage: str, agent: object) -> None:
        """
        Register an agent instance for a pipeline stage.

        Parameters
        ----------
        stage : str
            One of: 'triage', 'correlation', 'mitre', 'enrichment', 'report'
        agent : BaseAgent subclass instance
        """
        if stage not in self._agents:
            raise ValueError(
                f"Unknown pipeline stage '{stage}'. Valid stages: {list(self._agents)}"
            )
        self._agents[stage] = agent
        logger.info("Registered agent for stage '%s': %s", stage, agent)

    # ------------------------------------------------------------------
    # Health check — polls all registered agents
    # ------------------------------------------------------------------
    def health_check(self) -> list[dict]:
        """Return health status of all registered agents."""
        results = []
        for stage, agent in self._agents.items():
            if agent is None:
                results.append({"stage": stage, "agent": None, "healthy": False, "reason": "Not yet registered"})
            else:
                status = agent.health_check()  # type: ignore[attr-defined]
                status["stage"] = stage
                results.append(status)
        return results

    # ------------------------------------------------------------------
    # Main pipeline entry-point
    # ------------------------------------------------------------------
    def run_pipeline(self, event: NormalizedEvent) -> AnalyzeResponse:
        """
        Execute the full agent pipeline on a single NormalizedEvent.

        Stages run sequentially. If an agent is not yet registered (None)
        its slot is skipped — this allows partial pipelines during development.

        Parameters
        ----------
        event : NormalizedEvent
            The security event to analyse.

        Returns
        -------
        AnalyzeResponse
            Aggregated results from all pipeline stages.
        """
        pipeline_run_id = str(uuid.uuid4())
        start = time.perf_counter()
        logger.info("Pipeline run %s started for event %s", pipeline_run_id, event.event_id)

        results: dict[str, Optional[AgentResult]] = {
            "triage": None,
            "correlation": None,
            "mitre": None,
            "enrichment": None,
            "report": None,
        }

        # ---- Stage 1: Triage -------------------------------------------
        results["triage"] = self._run_stage("triage", event)
        if results["triage"] and results["triage"].status == "success":
            triage_out = results["triage"].output or {}
            if "severity" in triage_out:
                event.severity = triage_out["severity"]
            if "is_true_positive" in triage_out:
                event.is_true_positive = triage_out["is_true_positive"]

        # ---- Stage 2: Correlation ---------------------------------------
        results["correlation"] = self._run_stage("correlation", event)
        if results["correlation"] and results["correlation"].status == "success":
            corr_out = results["correlation"].output or {}
            if "incident_id" in corr_out:
                event.incident_id = corr_out["incident_id"]

        # ---- Stage 3: MITRE Mapping -------------------------------------
        results["mitre"] = self._run_stage("mitre", event)
        if results["mitre"] and results["mitre"].status == "success":
            mitre_out = results["mitre"].output or {}
            if "techniques" in mitre_out:
                event.mitre_techniques = [
                    t.get("technique_id", "") for t in mitre_out["techniques"]
                ]

        # ---- Stage 4: Enrichment ----------------------------------------
        results["enrichment"] = self._run_stage("enrichment", event)
        if results["enrichment"] and results["enrichment"].status == "success":
            event.enrichment_data = results["enrichment"].output

        # ---- Stage 5: Report Generation ---------------------------------
        results["report"] = self._run_stage("report", event)

        # ---- Aggregate --------------------------------------------------
        total_latency_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(
            "Pipeline run %s completed in %s ms", pipeline_run_id, total_latency_ms
        )

        return AnalyzeResponse(
            event_id=event.event_id,
            pipeline_run_id=pipeline_run_id,
            triage=results["triage"],
            correlation=results["correlation"],
            mitre=results["mitre"],
            enrichment=results["enrichment"],
            report=results["report"],
            total_latency_ms=total_latency_ms,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _run_stage(self, stage: str, event: NormalizedEvent) -> Optional[AgentResult]:
        """Run a single pipeline stage; returns None if agent not registered."""
        agent = self._agents.get(stage)
        if agent is None:
            logger.debug("Stage '%s' skipped — agent not registered", stage)
            return None
        return agent.run(event)  # type: ignore[attr-defined]
