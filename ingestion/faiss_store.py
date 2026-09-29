"""
ingestion/faiss_store.py
------------------------
FAISS vector store initialisation and management.

Used by:
  - Correlation Agent  : semantic alert similarity search
  - MITRE Agent        : cosine similarity over 700+ ATT&CK technique embeddings
  - api/main.py        : called at startup via init_faiss()

Author  : Member 3 — Vercel Setup & API Skeleton
Phase   : 1 (init scaffold) → Phase 2 (embeddings loaded)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
FAISS_INDEX_PATH = ROOT / "data" / "processed" / "faiss_alerts.index"
MITRE_INDEX_PATH = ROOT / "data" / "processed" / "faiss_mitre.index"
MITRE_TECHNIQUES_PATH = ROOT / "data" / "mitre_stix" / "techniques.json"

# Embedding dimension (all-MiniLM-L6-v2 → 384 dims)
EMBEDDING_DIM = 384

# ---------------------------------------------------------------------------
# Module-level index handles (set by init_faiss)
# ---------------------------------------------------------------------------

_alert_index = None   # FAISS FlatL2 — alert similarity
_mitre_index = None   # FAISS FlatIP — MITRE technique cosine similarity
_mitre_metadata: list[dict] = []   # parallel list to mitre index rows


def init_faiss() -> None:
    """
    Initialise (or load) both FAISS indices.

    Called once at FastAPI startup from api/main.py.
    On first run (index files don't exist yet), creates empty indices.
    In Phase 2, pre-computed MITRE embeddings will be loaded here.
    """
    global _alert_index, _mitre_index, _mitre_metadata

    try:
        import faiss  # type: ignore
    except ImportError:
        logger.warning(
            "faiss-cpu not installed — FAISS features disabled. "
            "Run: pip install faiss-cpu"
        )
        return

    # --- Alert similarity index -------------------------------------------
    (ROOT / "data" / "processed").mkdir(parents=True, exist_ok=True)

    if FAISS_INDEX_PATH.exists():
        _alert_index = faiss.read_index(str(FAISS_INDEX_PATH))
        logger.info(
            "Loaded alert FAISS index from %s (%d vectors)",
            FAISS_INDEX_PATH, _alert_index.ntotal,
        )
    else:
        _alert_index = faiss.IndexFlatL2(EMBEDDING_DIM)
        logger.info("Created new empty alert FAISS index (dim=%d)", EMBEDDING_DIM)

    # --- MITRE technique index --------------------------------------------
    if MITRE_INDEX_PATH.exists():
        _mitre_index = faiss.read_index(str(MITRE_INDEX_PATH))
        logger.info(
            "Loaded MITRE FAISS index from %s (%d techniques)",
            MITRE_INDEX_PATH, _mitre_index.ntotal,
        )
        # Load technique metadata alongside index
        meta_path = MITRE_INDEX_PATH.with_suffix(".json")
        if meta_path.exists():
            with open(meta_path, encoding="utf-8") as fh:
                _mitre_metadata = json.load(fh)
    else:
        # Inner-product index (cosine similarity after L2-normalising vectors)
        _mitre_index = faiss.IndexFlatIP(EMBEDDING_DIM)
        logger.info(
            "Created new empty MITRE FAISS index (dim=%d). "
            "Run scripts/build_mitre_index.py to populate it.",
            EMBEDDING_DIM,
        )


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_alert_index():
    """Return the alert similarity FAISS index handle."""
    return _alert_index


def get_mitre_index():
    """Return the MITRE technique FAISS index handle (inner-product)."""
    return _mitre_index


def get_mitre_metadata() -> list[dict]:
    """Return the list of technique dicts parallel to the MITRE index rows."""
    return _mitre_metadata


def add_alert_vector(embedding: np.ndarray) -> int:
    """
    Add a single alert embedding to the alert index.

    Parameters
    ----------
    embedding : np.ndarray  shape (EMBEDDING_DIM,)

    Returns
    -------
    int — total vectors now in the index
    """
    if _alert_index is None:
        raise RuntimeError("FAISS not initialised. Call init_faiss() first.")
    vec = embedding.reshape(1, -1).astype("float32")
    _alert_index.add(vec)
    return _alert_index.ntotal


def search_similar_alerts(
    query_embedding: np.ndarray,
    k: int = 5,
) -> tuple[list[float], list[int]]:
    """
    Search the alert index for the k most similar past alerts.

    Returns
    -------
    (distances, indices) — parallel lists of length min(k, ntotal)
    """
    if _alert_index is None or _alert_index.ntotal == 0:
        return [], []
    vec = query_embedding.reshape(1, -1).astype("float32")
    distances, indices = _alert_index.search(vec, k)
    return distances[0].tolist(), indices[0].tolist()


def search_mitre_techniques(
    query_embedding: np.ndarray,
    k: int = 3,
) -> list[dict]:
    """
    Return the top-k MITRE ATT&CK technique matches for an event embedding.

    Parameters
    ----------
    query_embedding : np.ndarray  shape (EMBEDDING_DIM,) — L2-normalised
    k               : int          number of top matches to return

    Returns
    -------
    list of dicts: [{technique_id, technique_name, tactic, score}, …]
    """
    if _mitre_index is None or _mitre_index.ntotal == 0:
        return []

    vec = query_embedding.reshape(1, -1).astype("float32")
    scores, indices = _mitre_index.search(vec, k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx < 0:
            continue
        meta = _mitre_metadata[idx] if idx < len(_mitre_metadata) else {}
        results.append({**meta, "score": float(score)})

    return results


def save_alert_index() -> None:
    """Persist the alert index to disk."""
    if _alert_index is None:
        return
    try:
        import faiss  # type: ignore
        faiss.write_index(_alert_index, str(FAISS_INDEX_PATH))
        logger.info("Alert FAISS index saved to %s", FAISS_INDEX_PATH)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to save alert index: %s", exc)
