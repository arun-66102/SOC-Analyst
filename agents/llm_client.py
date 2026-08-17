"""
llm_client.py
-------------
Groq Cloud LLM client with task-specific model selection.

Each SOC agent uses the Groq model best suited for its task:

  Task                  Model                              Reason
  ────────────────────  ─────────────────────────────────  ───────────────────────────────────
  Triage                openai/gpt-oss-120b                Best accuracy for classification
  Correlation           llama-3.1-8b-instant               Fastest — processes many events
  MITRE Mapping         openai/gpt-oss-120b                Precision matters for ATT&CK tags
  Enrichment            llama-3.1-8b-instant               Simple lookups, speed > accuracy
  Investigation/Report  deepseek-r1-distill-llama-70b      Best chain-of-thought reasoning

NOTE: Groq does NOT host GPT models — those are OpenAI proprietary.
      Groq runs open-source models (LLaMA, Mixtral, DeepSeek) on LPU hardware.

Configuration (.env):
  GROQ_API_KEY                      — required
  GROQ_MODEL_TRIAGE                 — override triage model
  GROQ_MODEL_CORRELATION            — override correlation model
  GROQ_MODEL_MITRE                  — override MITRE mapping model
  GROQ_MODEL_ENRICHMENT             — override enrichment model
  GROQ_MODEL_REPORT                 — override report/investigation model
  GROQ_TEMPERATURE                  — default temperature (0.1)
  GROQ_MAX_TOKENS                   — default max tokens (2048)

Usage
-----
from agents.llm_client import get_llm_client, GroqTask

# Using a named task (recommended — picks the right model automatically)
client = get_llm_client(task=GroqTask.TRIAGE)
response = await client.chat(prompt, system="You are a SOC analyst.")
print(response.text)

# Using a specific model directly
client = get_llm_client(model="mixtral-8x7b-32768")
response = await client.chat(prompt)

Author  : Member 1 — Project Lead
Phase   : 1 (setup) — used by all agents from Phase 2 onwards
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger("llm_client")

# ---------------------------------------------------------------------------
# API credentials
# ---------------------------------------------------------------------------
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

# ---------------------------------------------------------------------------
# Generation defaults (apply to all tasks unless overridden per-call)
# ---------------------------------------------------------------------------
GROQ_TEMPERATURE: float = float(os.getenv("GROQ_TEMPERATURE", "0.1"))
GROQ_MAX_TOKENS: int    = int(os.getenv("GROQ_MAX_TOKENS", "2048"))


# ---------------------------------------------------------------------------
# Task enum — one value per agent / pipeline stage
# ---------------------------------------------------------------------------
class GroqTask(str, Enum):
    """
    Named pipeline tasks — each maps to the best Groq model for that job.
    Pass a GroqTask to get_llm_client() to auto-select the right model.
    """
    TRIAGE      = "triage"       # Alert classification (Critical/High/Medium/Low)
    CORRELATION = "correlation"  # Event grouping and incident summarisation
    MITRE       = "mitre"        # ATT&CK technique identification and confirmation
    ENRICHMENT  = "enrichment"   # Threat intel lookup reasoning
    REPORT      = "report"       # Full investigation narrative + executive summary


# ---------------------------------------------------------------------------
# Available Groq model IDs — verified active as of Aug 2026
# Query live list: curl https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"
# ---------------------------------------------------------------------------
GROQ_MODELS = [
    "openai/gpt-oss-120b",              # OpenAI open-weight MoE, 120B — best all-round
    "openai/gpt-oss-20b",               # Smaller GPT-OSS, fast + capable
    "meta-llama/llama-4-scout-17b-16e-instruct",  # Llama 4 Scout — multimodal, 10M ctx
    "meta-llama/llama-4-maverick-17b-128e-instruct",  # Llama 4 Maverick — high quality
    "llama-3.1-8b-instant",             # Fast 8B — high-volume / low-latency tasks
    "llama3-8b-8192",                   # Stable fast 8B, 8192 ctx
    "mixtral-8x7b-32768",               # 32K context window
    "deepseek-r1-distill-llama-70b",    # Best chain-of-thought reasoning
    "deepseek-r1-distill-qwen-32b",     # Strong reasoning, 32B
    "moonshotai/kimi-k2-instruct",      # Kimi K2 — strong agentic reasoning
]


# ---------------------------------------------------------------------------
# Task → model mapping
# Each env var lets you override a specific task's model without touching code
# ---------------------------------------------------------------------------
TASK_MODELS: dict[GroqTask, str] = {
    GroqTask.TRIAGE: os.getenv(
        "GROQ_MODEL_TRIAGE",
        "openai/gpt-oss-120b",               # Best accuracy for severity classification
    ),
    GroqTask.CORRELATION: os.getenv(
        "GROQ_MODEL_CORRELATION",
        "llama-3.1-8b-instant",              # Fastest — processes many events quickly
    ),
    GroqTask.MITRE: os.getenv(
        "GROQ_MODEL_MITRE",
        "openai/gpt-oss-120b",               # Precision matters for ATT&CK tagging
    ),
    GroqTask.ENRICHMENT: os.getenv(
        "GROQ_MODEL_ENRICHMENT",
        "llama-3.1-8b-instant",              # Simple lookups — speed over depth
    ),
    GroqTask.REPORT: os.getenv(
        "GROQ_MODEL_REPORT",
        "deepseek-r1-distill-llama-70b",     # Best chain-of-thought for investigation
    ),
}


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------
@dataclass
class LLMResponse:
    """Standardised response returned by the Groq client."""
    text: str                          # Generated text
    model: str                         # Model that produced this
    task: Optional[str] = None         # GroqTask name that triggered this call
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    raw: Optional[object] = None       # Raw Groq SDK response object


# ---------------------------------------------------------------------------
# Groq client
# ---------------------------------------------------------------------------
class GroqClient:
    """
    Async Groq Cloud client.

    Wraps the official `groq` Python SDK (OpenAI-compatible format) so agents
    never deal with SDK-specific message structures directly.

    Instantiate via `get_llm_client(task=GroqTask.TRIAGE)` — do not
    construct directly unless you need a non-standard model.
    """

    def __init__(self, model: str, task: Optional[GroqTask] = None) -> None:
        if not GROQ_API_KEY:
            raise EnvironmentError(
                "GROQ_API_KEY is not set. "
                "Get a free key at https://console.groq.com and add it to your .env file."
            )
        self.model = model
        self.task  = task
        from groq import AsyncGroq
        self._client = AsyncGroq(api_key=GROQ_API_KEY)
        logger.info(
            "GroqClient ready  task=%-12s  model=%s",
            task.value if task else "custom",
            self.model,
        )

    async def chat(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Send a prompt to Groq and return a unified LLMResponse.

        Parameters
        ----------
        prompt : str
            The user message / task for the agent.
        system : str, optional
            System-level instruction (e.g. "You are an expert SOC analyst.").
        temperature : float, optional
            Per-call override of GROQ_TEMPERATURE.
        max_tokens : int, optional
            Per-call override of GROQ_MAX_TOKENS.

        Returns
        -------
        LLMResponse
            `.text` contains the answer.  `.input_tokens` / `.output_tokens`
            show usage for rate-limit tracking.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature if temperature is not None else GROQ_TEMPERATURE,
            max_tokens=max_tokens     if max_tokens  is not None else GROQ_MAX_TOKENS,
        )

        choice = response.choices[0]
        return LLMResponse(
            text=choice.message.content or "",
            model=self.model,
            task=self.task.value if self.task else None,
            input_tokens=getattr(response.usage, "prompt_tokens",     None),
            output_tokens=getattr(response.usage, "completion_tokens", None),
            raw=response,
        )

    def health_check(self) -> dict:
        """Return health status — used by orchestrator before pipeline starts."""
        return {
            "healthy":      bool(GROQ_API_KEY),
            "model":        self.model,
            "task":         self.task.value if self.task else "custom",
            "api_key_set":  bool(GROQ_API_KEY),
        }


# ---------------------------------------------------------------------------
# Per-task singleton cache  {GroqTask: GroqClient}
# Clients are created once per task and reused across the process lifetime
# ---------------------------------------------------------------------------
_task_clients: dict[GroqTask, GroqClient] = {}


def get_llm_client(
    task: Optional[GroqTask] = None,
    model: Optional[str] = None,
) -> GroqClient:
    """
    Return a GroqClient for a specific pipeline task or model.

    Preferred usage — pass a task, get the best model automatically:
        client = get_llm_client(task=GroqTask.TRIAGE)

    Override for a custom model:
        client = get_llm_client(model="mixtral-8x7b-32768")

    Parameters
    ----------
    task : GroqTask, optional
        Pipeline task — auto-selects the best model from TASK_MODELS.
    model : str, optional
        Explicit model override. If provided, `task` is ignored for model
        selection but still stored on the client for logging.

    Returns
    -------
    GroqClient
        A cached client instance (one per task, reused across calls).

    Raises
    ------
    EnvironmentError
        If GROQ_API_KEY is not set.
    ValueError
        If neither `task` nor `model` is provided.
    """
    if task is None and model is None:
        raise ValueError(
            "Provide either a `task` (e.g. GroqTask.TRIAGE) or an explicit `model` string."
        )

    # Explicit model — always create a fresh client (no caching for custom models)
    if model:
        return GroqClient(model=model, task=task)

    # Task-based — return cached client, create if not yet initialised
    if task not in _task_clients:
        selected_model = TASK_MODELS[task]
        _task_clients[task] = GroqClient(model=selected_model, task=task)

    return _task_clients[task]


def get_all_task_models() -> dict[str, str]:
    """
    Return the active model assigned to each task.
    Useful for logging at startup and the /health endpoint.
    """
    return {task.value: model for task, model in TASK_MODELS.items()}
