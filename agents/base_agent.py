"""
base_agent.py
-------------
Abstract base class for all SOC Analyst agents.
Every specialized agent (Triage, Correlation, MITRE, Enrichment, Report)
must inherit from BaseAgent and implement the `process()` method.

Author  : Member 1 — Project Lead
Phase   : 1
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from api.models import AgentResult, NormalizedEvent

# ---------------------------------------------------------------------------
# Module-level logger (each agent instance gets a child logger)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


class BaseAgent(ABC):
    """
    Abstract base class that all SOC Analyst agents must extend.

    Responsibilities
    ----------------
    - Provide a common `run()` entry-point that wraps `process()` with
      timing, error handling, and structured result packaging.
    - Expose `health_check()` so the orchestrator can confirm every agent
      is ready before the pipeline starts.
    - Expose `log()` helpers (info / warning / error) that automatically
      prefix messages with the agent name.

    Usage
    -----
    class MyAgent(BaseAgent):
        def process(self, event: NormalizedEvent) -> AgentResult:
            ...
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def __init__(self, agent_name: str, version: str = "1.0.0") -> None:
        self.agent_name: str = agent_name
        self.version: str = version
        self._logger: logging.Logger = logging.getLogger(agent_name)
        self._is_healthy: bool = True

    # ------------------------------------------------------------------
    # Public entry-point — wraps process() with cross-cutting concerns
    # ------------------------------------------------------------------
    def run(self, event: NormalizedEvent) -> AgentResult:
        """
        Execute the agent on a NormalizedEvent.

        Wraps `process()` with:
        - Execution timing (latency_ms)
        - Unique run_id for traceability
        - Structured error handling — never raises; returns error AgentResult

        Parameters
        ----------
        event : NormalizedEvent
            The standardized security event to analyse.

        Returns
        -------
        AgentResult
            Contains the agent output, confidence, latency, and status.
        """
        run_id = str(uuid.uuid4())
        start = time.perf_counter()
        self.log_info(f"Starting run {run_id} for event {event.event_id}")

        try:
            result: AgentResult = self.process(event)
            result.run_id = run_id
            result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            result.agent_name = self.agent_name
            result.status = "success"
            self.log_info(
                f"Completed run {run_id} in {result.latency_ms} ms"
            )
            return result

        except Exception as exc:  # pylint: disable=broad-except
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            self.log_error(f"Run {run_id} failed: {exc}")
            return AgentResult(
                run_id=run_id,
                agent_name=self.agent_name,
                event_id=event.event_id,
                status="error",
                error_message=str(exc),
                latency_ms=latency_ms,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    # ------------------------------------------------------------------
    # Abstract — subclasses MUST implement this
    # ------------------------------------------------------------------
    @abstractmethod
    def process(self, event: NormalizedEvent) -> "AgentResult":
        """
        Core agent logic. Must be implemented by every subclass.

        Parameters
        ----------
        event : NormalizedEvent
            Standardized security event.

        Returns
        -------
        AgentResult
            The analysis result produced by this agent.
        """

    # ------------------------------------------------------------------
    # Health check — orchestrator calls this before starting a pipeline
    # ------------------------------------------------------------------
    def health_check(self) -> dict[str, Any]:
        """
        Return a health status dictionary.

        Returns
        -------
        dict
            {
                "agent"   : str,   # agent name
                "version" : str,   # agent version
                "healthy" : bool,  # True if agent is ready
                "checked_at": str, # ISO-8601 UTC timestamp
            }
        """
        status = self._check_dependencies()
        self._is_healthy = status.get("healthy", True)
        return {
            "agent": self.agent_name,
            "version": self.version,
            "healthy": self._is_healthy,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            **status,
        }

    def _check_dependencies(self) -> dict[str, Any]:
        """
        Override in subclasses to check agent-specific dependencies
        (e.g. API keys, model availability, FAISS index loaded).

        Returns
        -------
        dict
            Must contain at minimum ``{"healthy": bool}``.
        """
        return {"healthy": True}

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def log_info(self, message: str) -> None:
        """Log an INFO-level message prefixed with the agent name."""
        self._logger.info(message)

    def log_warning(self, message: str) -> None:
        """Log a WARNING-level message prefixed with the agent name."""
        self._logger.warning(message)

    def log_error(self, message: str) -> None:
        """Log an ERROR-level message prefixed with the agent name."""
        self._logger.error(message)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.agent_name!r} v{self.version}>"
