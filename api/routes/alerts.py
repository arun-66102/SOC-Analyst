"""
api/routes/alerts.py
---------------------
Alert-related REST endpoints.

Endpoints:
  GET  /api/alerts            — paginated list of all normalized events
  GET  /api/alerts/{id}       — single alert with full agent outputs
  POST /api/alerts/{id}/action — analyst approve / escalate / dismiss

Author  : Member 3 — Vercel Setup & API Skeleton
Phase   : 1 (stubs) → Phase 3 (full implementation)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from api.models import (
    AlertListResponse,
    AlertStatus,
    AnalystAction,
    AnalystActionRequest,
    NormalizedEvent,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List all alerts",
    description=(
        "Returns a paginated list of normalized security events. "
        "Supports filtering by severity and status."
    ),
)
async def list_alerts(
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity level"),
    status: Optional[AlertStatus] = Query(None, description="Filter by alert status"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> AlertListResponse:
    """
    Retrieve alerts from the database with optional filters.

    Phase 1: Returns an empty list (DB not yet wired to agents).
    Phase 3: Queries Neon PostgreSQL and returns real records.
    """
    # TODO (Phase 3): Query Neon PostgreSQL via database.db
    logger.info(
        "GET /api/alerts — severity=%s status=%s limit=%d offset=%d",
        severity, status, limit, offset,
    )
    return AlertListResponse(total=0, alerts=[])


# ---------------------------------------------------------------------------
# GET /api/alerts/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/alerts/{alert_id}",
    response_model=NormalizedEvent,
    summary="Get a single alert",
)
async def get_alert(alert_id: str) -> NormalizedEvent:
    """
    Retrieve a single alert by its event_id.

    Phase 1: Always raises 404 (no data yet).
    Phase 3: Fetches from PostgreSQL with joined agent outputs.
    """
    # TODO (Phase 3): SELECT * FROM alerts WHERE event_id = alert_id
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")


# ---------------------------------------------------------------------------
# POST /api/alerts/{id}/action
# ---------------------------------------------------------------------------


@router.post(
    "/alerts/{alert_id}/action",
    summary="Analyst action on alert",
    description="Record an analyst action (approve / escalate / dismiss) on an alert.",
)
async def analyst_action(
    alert_id: str,
    body: AnalystActionRequest,
) -> dict:
    """
    Accept an analyst decision and persist it.

    Phase 1: Echoes the action back (no DB write yet).
    Phase 3: Updates the alert status in PostgreSQL.
    """
    logger.info(
        "Analyst action on %s: %s by %s — '%s'",
        alert_id, body.action, body.analyst_id, body.comment,
    )
    # TODO (Phase 3): UPDATE alerts SET status=... WHERE event_id=alert_id
    return {
        "alert_id": alert_id,
        "action": body.action,
        "status": "recorded",
        "message": f"Action '{body.action}' noted for alert {alert_id}.",
    }
