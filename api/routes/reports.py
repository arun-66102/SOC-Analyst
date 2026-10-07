"""Report retrieval endpoint. Report generation itself belongs to Member 3."""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/reports/{incident_id}", summary="Get investigation report")
async def get_report(incident_id: str) -> dict:
    from database.db import fetch_report
    report = await asyncio.to_thread(fetch_report, incident_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"No report found for incident '{incident_id}'. ReportAgent is implemented by Phase 3 Member 3.")
    return report
