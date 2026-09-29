"""
scripts/build_mitre_index.py
-----------------------------
One-time script: builds the FAISS index for MITRE ATT&CK technique embeddings.

Run once before starting the system:
    python scripts/build_mitre_index.py

What it does:
  1. Loads data/mitre_stix/techniques.json
  2. Encodes each technique description using sentence-transformers (all-MiniLM-L6-v2)
  3. Saves embeddings to a FAISS FlatIP index at data/processed/faiss_mitre.index
  4. Saves technique metadata (parallel to index rows) at data/processed/faiss_mitre.json

The MITREAgent loads this pre-built index at startup for fast similarity search.

Author  : Member 3 — Phase 2
"""

import json
import sys
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Resolve project root so we can import from it
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TECHNIQUES_JSON = ROOT / "data" / "mitre_stix" / "techniques.json"
OUTPUT_INDEX    = ROOT / "data" / "processed" / "faiss_mitre.index"
OUTPUT_META     = ROOT / "data" / "processed" / "faiss_mitre.json"

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM   = 384
BATCH_SIZE      = 64   # encode this many techniques per batch


def build_index() -> None:
    # ---- Pre-flight checks ------------------------------------------------
    if not TECHNIQUES_JSON.exists():
        print(f"[ERROR] techniques.json not found at:\n  {TECHNIQUES_JSON}")
        print("Run: python ingestion/mitre_parser.py  first.")
        sys.exit(1)

    try:
        import faiss
    except ImportError:
        print("[ERROR] faiss-cpu is not installed.")
        print("Run: pip install faiss-cpu")
        sys.exit(1)

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("[ERROR] sentence-transformers is not installed.")
        print("Run: pip install sentence-transformers")
        sys.exit(1)

    # ---- Load techniques --------------------------------------------------
    print(f"Loading techniques from:\n  {TECHNIQUES_JSON}\n")
    with open(TECHNIQUES_JSON, "r", encoding="utf-8") as f:
        raw = json.load(f)

    techniques = list(raw.values())
    print(f"Total techniques to embed: {len(techniques)}")

    # ---- Build text strings for embedding ---------------------------------
    texts = []
    for tech in techniques:
        name = tech.get("technique_name", "")
        desc = (tech.get("description") or "")[:512]   # truncate long descriptions
        tactics = ", ".join(tech.get("tactics") or [])
        text = f"{name}. Tactics: {tactics}. {desc}"
        texts.append(text)

    # ---- Embed using sentence-transformers --------------------------------
    print(f"\nLoading embedding model: {EMBEDDING_MODEL} ...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    print(f"Encoding {len(texts)} techniques in batches of {BATCH_SIZE} ...")
    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        normalize_embeddings=True,   # L2-normalise → inner product = cosine similarity
        show_progress_bar=True,
    )
    embeddings = np.array(embeddings, dtype="float32")
    print(f"Embedding matrix shape: {embeddings.shape}")

    # ---- Build FAISS FlatIP index ----------------------------------------
    # FlatIP with L2-normalised vectors = cosine similarity
    print("\nBuilding FAISS FlatIP index ...")
    index = faiss.IndexFlatIP(EMBEDDING_DIM)
    index.add(embeddings)
    print(f"Index contains {index.ntotal} vectors")

    # ---- Save index + metadata -------------------------------------------
    OUTPUT_INDEX.parent.mkdir(parents=True, exist_ok=True)

    faiss.write_index(index, str(OUTPUT_INDEX))
    print(f"\nFAISS index saved to:\n  {OUTPUT_INDEX}")

    # Save metadata: keep only lightweight fields (no full descriptions)
    meta_list = [
        {
            "technique_id":   t.get("technique_id"),
            "technique_name": t.get("technique_name"),
            "tactics":        t.get("tactics", []),
            "description":    (t.get("description") or "")[:300],
        }
        for t in techniques
    ]
    with open(OUTPUT_META, "w", encoding="utf-8") as f:
        json.dump(meta_list, f, ensure_ascii=False, indent=2)
    print(f"Metadata saved to:\n  {OUTPUT_META}")

    # ---- Smoke test -------------------------------------------------------
    print("\nSmoke test — querying index with 'brute force password attack' ...")
    test_vec = model.encode(["brute force password attack"], normalize_embeddings=True)
    test_vec = np.array(test_vec, dtype="float32")
    scores, indices = index.search(test_vec, 3)
    print("Top 3 matches:")
    for score, idx in zip(scores[0], indices[0]):
        if idx < 0:
            continue
        m = meta_list[idx]
        print(f"  [{score:.4f}] {m['technique_id']} — {m['technique_name']} ({', '.join(m['tactics'])})")

    print("\nDone. MITRE FAISS index is ready.")


if __name__ == "__main__":
    build_index()
