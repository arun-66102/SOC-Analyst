"""
tests/conftest.py
-----------------
Shared pytest fixtures for the SOC Analyst test suite.

Fixtures available to all test modules:
  - sample_events     : list of 5 NormalizedEvent dicts (one per attack type)
  - sample_brute_force: single brute-force NormalizedEvent dict
  - sample_benign     : single benign NormalizedEvent dict
  - bulk_events       : 100 mixed events for batch / correlation tests
  - normalizer        : the ingestion.normalizer module (function-based API)
  - loader            : the ingestion.dataset_loader module (function-based API)

Author : Member 4 — Synthetic Log Generator & Testing Setup
Phase  : 1
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from ingestion.log_generator import generate_event, generate_events


# ---------------------------------------------------------------------------
# Shared event fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def sample_events() -> list[dict]:
    """
    5 deterministic synthetic events — one per attack type commonly used in tests.
    Session-scoped so they are created only once across all tests.
    """
    return [
        generate_event("brute_force",  base_timestamp=datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)),
        generate_event("port_scan",    base_timestamp=datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc)),
        generate_event("exfiltration", base_timestamp=datetime(2024, 1, 1, 0, 10, tzinfo=timezone.utc)),
        generate_event("malware_c2",   base_timestamp=datetime(2024, 1, 1, 0, 15, tzinfo=timezone.utc)),
        generate_event("benign",       base_timestamp=datetime(2024, 1, 1, 0, 20, tzinfo=timezone.utc)),
    ]


@pytest.fixture
def sample_brute_force() -> dict:
    """Single brute-force event with a fixed seed for reproducibility."""
    import random
    random.seed(42)
    return generate_event("brute_force")


@pytest.fixture
def sample_benign() -> dict:
    """Single benign/normal-traffic event."""
    import random
    random.seed(99)
    return generate_event("benign")


@pytest.fixture(scope="module")
def bulk_events() -> list[dict]:
    """100 mixed events used for batch / correlation tests."""
    return generate_events(count=100, seed=2024)


# ---------------------------------------------------------------------------
# Infrastructure fixtures — module-level (functions, not classes)
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer():
    """
    Return the ingestion.normalizer module.

    The normalizer uses standalone functions, not a class:
      normalizer.normalize_cicids2017_row(row) -> NormalizedEvent
      normalizer.normalize_unsw_nb15_row(row)  -> NormalizedEvent
    """
    from ingestion import normalizer as n
    return n


@pytest.fixture
def loader():
    """
    Return the ingestion.dataset_loader module.

    The loader uses standalone functions, not a class:
      loader.load_cicids2017_sample(max_rows) -> list[NormalizedEvent]
      loader.load_unsw_nb15_sample(max_rows)  -> list[NormalizedEvent]
    """
    from ingestion import dataset_loader as d
    return d


@pytest.fixture
def normalizer_module():
    """Alias fixture — same as 'normalizer' but with an explicit name for
    tests that need both loader and normalizer in the same test function."""
    from ingestion import normalizer as n
    return n

