"""Central Phase 3 pipeline controller."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Optional

from api.models import AgentResult, AnalyzeResponse, NormalizedEvent

logger = logging.getLogger("orchestrator")


class Orchestrator:
    def __init__(self) -> None:
        self._agents: dict[str, Optional[object]] = {
            "triage": None,
            "correlation": None,
            "mitre": None,
            "enrichment": None,
            "investigation": None,
            "report": None,  # Member 3; remains optional until implemented.
        }

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
                status = agent.health_check()  # type: ignore[attr-defined]
                status["stage"] = stage
                results.append(status)
        return results

    async def run_pipeline_async(self, event: NormalizedEvent) -> AnalyzeResponse:
        pipeline_run_id = str(uuid.uuid4())
        start = time.perf_counter()
        results: dict[str, Optional[AgentResult]] = {
            "triage": None, "correlation": None, "mitre": None,
            "enrichment": None, "investigation": None, "report": None,
        }

        results["triage"] = await self._run_stage_async("triage", event)
        if results["triage"] and results["triage"].status == "success":
            event.status = "triaged"
            out = results["triage"].output or {}
            if "severity" in out:
                event.severity = out["severity"]
            if "is_true_positive" in out:
                event.is_true_positive = out["is_true_positive"]

        results["correlation"] = await self._run_stage_async("correlation", event)
        if results["correlation"] and results["correlation"].status == "success":
            event.status = "correlated"
            out = results["correlation"].output or {}
            if "incident_id" in out:
                event.incident_id = out["incident_id"]
            if "incident_summary" in out:
                event.correlation_summary = out["incident_summary"]

        results["mitre"] = await self._run_stage_async("mitre", event)
        if results["mitre"] and results["mitre"].status == "success":
            out = results["mitre"].output or {}
            event.mitre_techniques = [t.get("technique_id", "") for t in out.get("techniques", [])]

        results["enrichment"] = await self._run_stage_async("enrichment", event)
        if results["enrichment"] and results["enrichment"].status == "success":
            event.status = "enriched"
            event.enrichment_data = results["enrichment"].output

        results["investigation"] = await self._run_stage_async("investigation", event)

        # ReportAgent belongs to Phase 3 Member 3, so it is intentionally optional.
        results["report"] = await self._run_stage_async("report", event)

        total_latency_ms = round((time.perf_counter() - start) * 1000, 2)
        await self._persist(event, pipeline_run_id, results)

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
        agent = self._agents.get(stage)
        if agent is None:
            return None
        process_async = getattr(agent, "process_async", None)
        if process_async is not None:
            return await process_async(event)
        # Existing Phase 2 agents expose only sync process(). Run them in a
        # worker thread so their asyncio.run() does not collide with FastAPI's loop.
        return await asyncio.to_thread(agent.run, event)  # type: ignore[attr-defined]

    async def _persist(self, event: NormalizedEvent, pipeline_run_id: str, results: dict[str, Optional[AgentResult]]) -> None:
        try:
            from database.db import persist_pipeline
            await asyncio.to_thread(persist_pipeline, event, pipeline_run_id, results)
        except Exception as exc:
            logger.warning("Pipeline DB persistence skipped: %s", exc)
