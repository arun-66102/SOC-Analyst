from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from api.models import HealthResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
logger = logging.getLogger(__name__)
APP_VERSION = "0.2.0"
APP_TITLE = "Agentic SOC Analyst API"
APP_DESCRIPTION = "Multi-agent LLM system for autonomous alert triage, correlation, MITRE mapping, threat enrichment, investigation and report generation."


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SOC Analyst API starting — version %s", APP_VERSION)
    try:
        from database.db import init_db
        await init_db()
        logger.info("PostgreSQL pool initialised.")
    except Exception as exc:
        logger.warning("Database init skipped: %s", exc)
    try:
        from ingestion.faiss_store import init_faiss
        init_faiss()
    except Exception as exc:
        logger.warning("FAISS init skipped: %s", exc)
    yield
    try:
        from database.db import close_db
        await close_db()
    except Exception as exc:
        logger.debug("DB close skipped: %s", exc)


app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION, docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json", lifespan=lifespan)

_allowed_origins = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:3000"]
if os.getenv("VERCEL_URL"):
    _allowed_origins.append(f"https://{os.getenv('VERCEL_URL')}")
if os.getenv("FRONTEND_URL"):
    _allowed_origins.append(os.getenv("FRONTEND_URL"))
app.add_middleware(CORSMiddleware, allow_origins=_allowed_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

try:
    from api.routes import alerts, agents, reports
    app.include_router(alerts.router, prefix="/api", tags=["Alerts"])
    app.include_router(agents.router, prefix="/api", tags=["Agents"])
    app.include_router(reports.router, prefix="/api", tags=["Reports"])
except ModuleNotFoundError as exc:
    logger.warning("Route modules unavailable: %s", exc)

_start_time = time.time()


def _to_class_name(snake: str) -> str:
    if snake == "mitre_agent":
        return "MITREAgent"
    return "".join(part.capitalize() for part in snake.split("_"))

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    from datetime import datetime, timezone
    agent_statuses = []
    for name in ["triage_agent", "correlation_agent", "mitre_agent", "enrichment_agent", "investigation_agent", "report_agent"]:
        try:
            module = __import__(f"agents.{name}", fromlist=[name])
            instance = getattr(module, _to_class_name(name))()
            status = instance.health_check()
        except Exception as exc:
            status = {"status": "unavailable", "healthy": False, "error": str(exc)}
        agent_statuses.append({"agent": name, **status})
    return HealthResponse(status="ok", version=APP_VERSION, agents=agent_statuses, timestamp=datetime.now(timezone.utc).isoformat())


@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse({"message": "SOC Analyst API", "docs": "/docs", "health": "/health"})
