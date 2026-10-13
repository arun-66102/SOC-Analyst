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
      → InvestigationAgent
      → ReportAgent
      → AnalyzeResponse

Features:
  - Supports both synchronous and asynchronous pipeline execution
  - Auto-registers available Phase 2 & Phase 3 agents by default
  - Enables progressive enrichment where each stage enhances the event
  - Automatically persists analyzed alerts and agent results to storage

Author  : Member 1 & Member 2 — Phase 3
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Optional

from api.models import AgentResult, AnalyzeResponse, NormalizedEvent
from database.store import get_store

logger = logging.getLogger("orchestrator")


class Orchestrator:
    """
    Runs the full SOC Analyst agent pipeline on a NormalizedEvent.

    Agent slots are filled lazily or automatically loaded upon initialization.
    """

    def __init__(self, auto_register_defaults: bool = True) -> None:
        self._agents: dict[str, Optional[object]] = {
            "triage": None,
            "correlation": None,
            "mitre": None,
            "enrichment": None,
            "investigation": None,
            "report": None,
        }

        if auto_register_defaults:
            self._register_default_agents()

        logger.info("Orchestrator initialised (active agents: %s)", [k for k, v in self._agents.items() if v])

    def _register_default_agents(self) -> None:
        """Auto-register core agents if their modules are available."""
        # 1. Triage Agent
        try:
            from agents.triage_agent import TriageAgent
            self.register_agent("triage", TriageAgent())
        except Exception as exc:
            logger.debug("Triage agent auto-register skipped: %s", exc)

        # 2. Correlation Agent
        try:
            from agents.correlation_agent import CorrelationAgent
            self.register_agent("correlation", CorrelationAgent())
        except Exception as exc:
            logger.debug("Correlation agent auto-register skipped: %s", exc)

        # 3. MITRE Agent
        try:
            from agents.mitre_agent import MITREAgent
            self.register_agent("mitre", MITREAgent())
        except Exception as exc:
            logger.debug("MITRE agent auto-register skipped: %s", exc)

        # 4. Enrichment Agent (Phase 3 Member 1)
        try:
            from agents.enrichment_agent import EnrichmentAgent
            self.register_agent("enrichment", EnrichmentAgent())
        except Exception as exc:
            logger.debug("Enrichment agent auto-register skipped: %s", exc)

        # 5. Investigation Agent (Phase 3 Member 1)
        try:
            from agents.investigation_agent import InvestigationAgent
            self.register_agent("investigation", InvestigationAgent())
        except Exception as exc:
            logger.debug("Investigation agent auto-register skipped: %s", exc)

        # 6. Report Agent (Phase 3 Member 3)
        try:
            from agents.report_agent import ReportAgent
            self.register_agent("report", ReportAgent())
        except Exception as exc:
            logger.debug("Report agent auto-register skipped: %s", exc)

    def register_agent(self, stage: str, agent: object) -> None:
        if stage not in self._agents:
            raise ValueError(f"Unknown pipeline stage '{stage}'. Valid stages: {list(self._agents)}")
        self._agents[stage] = agent

    def health_check(self) -> list[dict]:
        results = []
        for stage, agent in self._agents.items():
            if agent is None:
                results.append({"stage": stage, "agent": None, "healthy": False, "reason": "Not registered"})
            else:
                try:
                    status = agent.health_check()  # type: ignore[attr-defined]
                    status["stage"] = stage
                    results.append(status)
                except Exception as exc:
                    results.append({"stage": stage, "agent": stage, "healthy": False, "error": str(exc)})
        return results

    async def run_pipeline_async(self, event: NormalizedEvent) -> AnalyzeResponse:
        """
        Execute the agent pipeline asynchronously without blocking the event loop.
        """
        pipeline_run_id = str(uuid.uuid4())
        start = time.perf_counter()
        logger.info("Async pipeline run %s started for event %s", pipeline_run_id, event.event_id)

        results: dict[str, Optional[AgentResult]] = {
            "triage": None,
            "correlation": None,
            "mitre": None,
            "enrichment": None,
            "investigation": None,
            "report": None,
        }

        # Stage 1: Triage
        results["triage"] = await self._run_stage_async("triage", event)
        if results["triage"] and results["triage"].status == "success":
            triage_out = results["triage"].output or {}
            if "severity" in triage_out:
                event.severity = triage_out["severity"]
            if "is_true_positive" in triage_out:
                event.is_true_positive = triage_out["is_true_positive"]
            event.status = "triaged"

        # Stage 2: Correlation
        results["correlation"] = await self._run_stage_async("correlation", event)
        if results["correlation"] and results["correlation"].status == "success":
            corr_out = results["correlation"].output or {}
            if "incident_id" in corr_out:
                event.incident_id = corr_out["incident_id"]
            if "incident_summary" in corr_out:
                event.correlation_summary = corr_out["incident_summary"]
            event.status = "correlated"

        # Stage 3: MITRE
        results["mitre"] = await self._run_stage_async("mitre", event)
        if results["mitre"] and results["mitre"].status == "success":
            mitre_out = results["mitre"].output or {}
            if "techniques" in mitre_out:
                event.mitre_techniques = [
                    t.get("technique_id", "") for t in mitre_out["techniques"]
                ]

        # Stage 4: Enrichment
        results["enrichment"] = await self._run_stage_async("enrichment", event)
        if results["enrichment"] and results["enrichment"].status == "success":
            event.enrichment_data = results["enrichment"].output
            event.status = "enriched"

        # Stage 5: Investigation
        results["investigation"] = await self._run_stage_async("investigation", event)

        # Stage 6: Report
        results["report"] = await self._run_stage_async("report", event)
        if results["report"] and results["report"].status == "success":
            event.status = "reported"

        total_latency_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("Async pipeline run %s completed in %s ms", pipeline_run_id, total_latency_ms)

        # Persist alert and results
        try:
            get_store().save_alert(event, results)
        except Exception as exc:
            logger.debug("Failed to persist alert in store: %s", exc)

        return AnalyzeResponse(
            event_id=event.event_id,
            pipeline_run_id=pipeline_run_id,
            triage=results["triage"],
            correlation=results["correlation"],
            mitre=results["mitre"],
            enrichment=results["enrichment"],
            investigation=results["investigation"],
            report=results["report"],
            total_latency_ms=total_latency_ms,
        )

    def run_pipeline(self, event: NormalizedEvent) -> AnalyzeResponse:
        """Sync entry point for scripts/tests outside an active event loop."""
        return asyncio.run(self.run_pipeline_async(event))

    async def _run_stage_async(self, stage: str, event: NormalizedEvent) -> Optional[AgentResult]:
        """Run a single stage asynchronously."""
        agent = self._agents.get(stage)
        if agent is None:
            return None

        try:
            process_async = getattr(agent, "process_async", None)
            if process_async is not None:
                start = time.perf_counter()
                res: AgentResult = await process_async(event)
                res.latency_ms = round((time.perf_counter() - start) * 1000, 2)
                res.agent_name = getattr(agent, "agent_name", stage)
                return res
            # Existing Phase 2 agents expose only sync process(). Run in a thread.
            return await asyncio.to_thread(agent.run, event)  # type: ignore[attr-defined]
        except Exception as exc:
            logger.warning("Stage '%s' async failed: %s", stage, exc)
            return AgentResult(
                event_id=event.event_id,
                status="error",
                error_message=str(exc),
                agent_name=stage,
            )


# ---------------------------------------------------------------------------
# Global Singleton Accessor
# ---------------------------------------------------------------------------
_global_orchestrator: Optional[Orchestrator] = None


def get_orchestrator() -> Orchestrator:
    """Return the global Orchestrator singleton."""
    global _global_orchestrator  # noqa: PLW0603
    if _global_orchestrator is None:
        _global_orchestrator = Orchestrator(auto_register_defaults=True)
    return _global_orchestrator
