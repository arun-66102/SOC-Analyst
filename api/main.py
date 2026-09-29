"""
api/main.py
-----------
FastAPI application entry point for the Agentic SOC Analyst system.

Responsibilities:
  - Creates the FastAPI app instance with CORS middleware
  - Registers all route modules (alerts, agents, reports)
  - Exposes a /health liveness endpoint
  - Initialises the FAISS vector store on startup
  - Connects / disconnects the Neon PostgreSQL pool on lifespan events

Author  : Member 3 — Vercel Setup & API Skeleton
Phase   : 1
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.models import HealthResponse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App metadata
# ---------------------------------------------------------------------------

APP_VERSION = "0.1.0"
APP_TITLE = "Agentic SOC Analyst API"
APP_DESCRIPTION = (
    "Multi-agent LLM system for autonomous alert triage, log correlation, "
    "MITRE ATT&CK mapping, and investigation report generation."
)

# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown hooks
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks before yielding, then cleanup on shutdown."""

    # ---- Startup ----------------------------------------------------------
    logger.info("SOC Analyst API starting up — version %s", APP_VERSION)

    # 1. Database connection pool
    try:
        from database.db import init_db
        await init_db()
        logger.info("PostgreSQL connection pool initialised.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Database init skipped (running without DB): %s", exc)

    # 2. FAISS vector store
    try:
        from ingestion.faiss_store import init_faiss
        init_faiss()
        logger.info("FAISS index initialised.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("FAISS init skipped: %s", exc)

    yield  # ← application is running

    # ---- Shutdown ---------------------------------------------------------
    logger.info("SOC Analyst API shutting down…")
    try:
        from database.db import close_db
        await close_db()
        logger.info("Database pool closed.")
    except Exception as exc:  # noqa: BLE001
        logger.debug("DB close skipped: %s", exc)


# ---------------------------------------------------------------------------
# FastAPI app instance
# ---------------------------------------------------------------------------

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — allow the React frontend (localhost:5173 in dev, Vercel URL in prod)
# ---------------------------------------------------------------------------

_allowed_origins: list[str] = [
    "http://localhost:5173",   # Vite dev server
    "http://localhost:3000",   # CRA dev server (fallback)
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# Add the production Vercel URL from env if set
_vercel_url = os.getenv("VERCEL_URL")
if _vercel_url:
    _allowed_origins.append(f"https://{_vercel_url}")

# Allow an explicit FRONTEND_URL override (useful for custom domains)
_frontend_url = os.getenv("FRONTEND_URL")
if _frontend_url:
    _allowed_origins.append(_frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

try:
    from api.routes import alerts, agents, reports

    app.include_router(alerts.router, prefix="/api", tags=["Alerts"])
    app.include_router(agents.router, prefix="/api", tags=["Agents"])
    app.include_router(reports.router, prefix="/api", tags=["Reports"])
    logger.info("All API routes registered.")
except ModuleNotFoundError as exc:
    # Routes not yet implemented in Phase 1 — log and continue
    logger.warning("Route modules not yet available: %s", exc)

# ---------------------------------------------------------------------------
# Health-check endpoint
# ---------------------------------------------------------------------------

_start_time = time.time()


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    tags=["System"],
)
async def health_check() -> HealthResponse:
    """
    Lightweight liveness probe.

    Returns the API version, uptime, and a status object for each
    registered agent (useful for k8s / Vercel health monitoring).
    """
    from datetime import datetime, timezone

    agent_statuses: list[dict] = []

    agent_names = [
        "triage_agent",
        "correlation_agent",
        "mitre_agent",
        "enrichment_agent",
        "report_agent",
    ]

    for name in agent_names:
        try:
            module = __import__(f"agents.{name}", fromlist=[name])
            agent_class = getattr(module, _to_class_name(name))
            instance = agent_class()
            status = instance.health_check()
        except Exception as exc:  # noqa: BLE001
            status = {"status": "unavailable", "error": str(exc)}

        agent_statuses.append({"agent": name, **status})

    return HealthResponse(
        status="ok",
        version=APP_VERSION,
        agents=agent_statuses,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _to_class_name(snake: str) -> str:
    """Convert 'triage_agent' → 'TriageAgent'."""
    return "".join(part.capitalize() for part in snake.split("_"))


# ---------------------------------------------------------------------------
# Root redirect → docs
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse(
        {"message": "SOC Analyst API", "docs": "/docs", "health": "/health"}
    )


# ---------------------------------------------------------------------------
# Vercel serverless entry point
# ---------------------------------------------------------------------------
# Vercel Python runtime expects the module-level `app` object — no extra
# configuration needed.  For local dev, run via:
#   uvicorn api.main:app --reload --port 8000
# ---------------------------------------------------------------------------
