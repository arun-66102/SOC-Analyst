"""Phase 3 Member 2 alert endpoints."""
"""
api/routes/alerts.py
---------------------
Alert-related REST endpoints.

Endpoints:
  GET  /api/alerts             — paginated list of normalized security events
  GET  /api/alerts/{alert_id}  — single alert with full agent outputs
  POST /api/alerts/{alert_id}/action — analyst approve / escalate / dismiss / close

Author  : Member 2 — Phase 3
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from api.models import AlertListResponse, AlertStatus, AnalystActionRequest, NormalizedEvent, SeverityLevel
from api.models import (
    AlertListResponse,
    AlertStatus,
    AnalystAction,
    AnalystActionRequest,
    NormalizedEvent,
    SeverityLevel,
    ThreatCategory,
)
from database.store import get_store

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
# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List all alerts",
    description=(
        "Returns a paginated list of normalized security events. "
        "Supports filtering by severity, lifecycle status, and threat category."
    ),
)
async def list_alerts(
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity level"),
    status: Optional[AlertStatus] = Query(None, description="Filter by alert status"),
    threat_category: Optional[ThreatCategory] = Query(None, description="Filter by threat category"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> AlertListResponse:
    """Retrieve alerts from the repository with optional filters."""
    logger.info(
        "GET /api/alerts — severity=%s status=%s category=%s limit=%d offset=%d",
        severity, status, threat_category, limit, offset,
    )
    store = get_store()
    records, total = store.list_alerts(
        severity=severity,
        status=status,
        threat_category=threat_category,
        limit=limit,
        offset=offset,
    )
    return AlertListResponse(total=total, alerts=records)


# ---------------------------------------------------------------------------
# GET /api/alerts/{alert_id}
# ---------------------------------------------------------------------------


@router.get(
    "/alerts/{alert_id}",
    response_model=NormalizedEvent,
    summary="Get a single alert",
    description="Retrieve a single alert by its event_id with complete agent analysis details.",
)
async def get_alert(alert_id: str) -> NormalizedEvent:
    """Retrieve a single alert by its event_id."""
    store = get_store()
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


# ---------------------------------------------------------------------------
# POST /api/alerts/{alert_id}/action
# ---------------------------------------------------------------------------


@router.post(
    "/alerts/{alert_id}/action",
    summary="Record analyst action on alert",
    description="Record an analyst action (approve / escalate / dismiss / close) and update lifecycle status.",
)
async def analyst_action(
    alert_id: str,
    body: AnalystActionRequest,
) -> dict:
    """Accept an analyst decision and persist status update and audit trail."""
    logger.info(
        "Analyst action on %s: %s by %s — '%s'",
        alert_id, body.action, body.analyst_id, body.comment,
    )
    store = get_store()
    updated = store.update_alert_action(
        alert_id=alert_id,
        action=body.action,
        comment=body.comment,
        analyst_id=body.analyst_id,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    return {
        "alert_id": alert_id,
        "action": body.action.value if hasattr(body.action, "value") else str(body.action),
        "status": "recorded",
        "new_alert_status": updated.status.value if hasattr(updated.status, "value") else str(updated.status),
        "message": f"Action '{body.action}' recorded for alert {alert_id}.",
    }
