"""Phase 3 Member 2 pipeline, incident and dashboard endpoints."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter

from api.models import AnalyzeRequest, AnalyzeResponse, DashboardStats, IncidentSummary

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
