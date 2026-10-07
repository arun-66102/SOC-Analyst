"""Phase 3 Member 2 pipeline, incident and dashboard endpoints."""
"""
api/routes/agents.py
---------------------
Agent-pipeline REST endpoints.

Endpoints:
  POST /api/analyze   — trigger the full agent pipeline on a new event
  GET  /api/incidents — list correlated incidents
  GET  /api/stats     — dashboard summary stats

Author  : Member 2 — Phase 3
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter

from api.models import AnalyzeRequest, AnalyzeResponse, DashboardStats, IncidentSummary
from agents.orchestrator import get_orchestrator
from api.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    DashboardStats,
    IncidentSummary,
)
from database.store import get_store

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze a security event")
async def analyze_event(body: AnalyzeRequest) -> AnalyzeResponse:
    from agents.pipeline import get_orchestrator
    return await get_orchestrator().run_pipeline_async(body.event)


@router.get("/incidents", response_model=list[IncidentSummary], summary="List correlated incidents")
async def list_incidents() -> list[IncidentSummary]:
    from database.db import fetch_incidents
    rows = await asyncio.to_thread(fetch_incidents)
    return [IncidentSummary(**row) for row in rows]


@router.get("/stats", response_model=DashboardStats, summary="Dashboard summary statistics")
async def get_stats() -> DashboardStats:
    from database.db import fetch_stats
    return DashboardStats(**await asyncio.to_thread(fetch_stats))
# ---------------------------------------------------------------------------
# POST /api/analyze
# ---------------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a security event",
    description=(
        "Triggers the multi-agent pipeline: "
        "Triage → Correlation → MITRE Mapping → Threat Intel Enrichment → Report."
    ),
)
async def analyze_event(body: AnalyzeRequest) -> AnalyzeResponse:
    """Run the complete multi-agent pipeline on the supplied NormalizedEvent."""
    event = body.event
    logger.info("POST /api/analyze — event_id=%s category=%s", event.event_id, event.threat_category)

    orchestrator = get_orchestrator()
    response = await orchestrator.run_pipeline_async(event)
    return response


# ---------------------------------------------------------------------------
# GET /api/incidents
# ---------------------------------------------------------------------------


@router.get(
    "/incidents",
    response_model=list[IncidentSummary],
    summary="List correlated incidents",
    description="Returns all correlated incident groups identified across the alert stream.",
)
async def list_incidents() -> list[IncidentSummary]:
    """Retrieve correlated incidents from the repository."""
    store = get_store()
    return store.list_incidents()


# ---------------------------------------------------------------------------
# GET /api/stats
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    response_model=DashboardStats,
    summary="Dashboard summary statistics",
    description="Aggregated metrics powering the SOC Dashboard overview widgets and charts.",
)
async def get_stats() -> DashboardStats:
    """Return live dashboard statistics."""
    store = get_store()
    return store.get_stats()
