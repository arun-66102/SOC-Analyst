"""Phase 3 Member 2 alert endpoints."""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from api.models import AlertListResponse, AlertStatus, AnalystActionRequest, NormalizedEvent, SeverityLevel

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/alerts", response_model=AlertListResponse, summary="List all alerts")
async def list_alerts(
    severity: Optional[SeverityLevel] = Query(None),
    status: Optional[AlertStatus] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> AlertListResponse:
    from database.db import fetch_alerts
    total, rows = await asyncio.to_thread(
        fetch_alerts,
        severity.value if severity else None,
        status.value if status else None,
        limit,
        offset,
    )
    return AlertListResponse(total=total, alerts=[NormalizedEvent.model_validate(r) for r in rows])


@router.get("/alerts/{alert_id}", response_model=NormalizedEvent, summary="Get a single alert")
async def get_alert(alert_id: str) -> NormalizedEvent:
    from database.db import fetch_alert
    row = await asyncio.to_thread(fetch_alert, alert_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return NormalizedEvent.model_validate(row)


@router.post("/alerts/{alert_id}/action", summary="Analyst action on alert")
async def analyst_action(alert_id: str, body: AnalystActionRequest) -> dict:
    from database.db import fetch_alert, record_analyst_action
    if not await asyncio.to_thread(fetch_alert, alert_id):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    await asyncio.to_thread(record_analyst_action, alert_id, body.action.value, body.comment, body.analyst_id)
    return {"alert_id": alert_id, "action": body.action.value, "status": "recorded"}
