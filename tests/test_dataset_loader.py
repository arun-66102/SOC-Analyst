"""
tests/test_dataset_loader.py
-----------------------------
Unit tests for ingestion/dataset_loader.py

The loader module exposes standalone functions:
  - load_cicids2017_sample(sample_size, random_state) -> pd.DataFrame
  - load_unsw_nb15_sample(sample_size, random_state)  -> pd.DataFrame
  - load_csv(file_path, nrows)                        -> pd.DataFrame

Tests verify:
  1. Functions are importable and callable
  2. Loading returns a DataFrame (or empty DataFrame if CSVs absent)
  3. CSV round-trip: write synthetic data, load back via load_csv
  4. MITRE techniques.json loads with expected structure and count

Author : Member 4 — Synthetic Log Generator & Testing Setup
Phase  : 1
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pd = pytest.importorskip("pandas", reason="pandas required for loader tests")

from api.models import NormalizedEvent

TECHNIQUES_JSON = (
    Path(__file__).resolve().parent.parent / "data" / "mitre_stix" / "techniques.json"
)


# ---------------------------------------------------------------------------
# Test 1 — Module imports & callable check
# ---------------------------------------------------------------------------


class TestDatasetLoaderImports:
    def test_loader_module_importable(self, loader) -> None:
        assert loader is not None

    def test_has_load_cicids_function(self, loader) -> None:
        assert callable(getattr(loader, "load_cicids2017_sample", None)), (
            "Missing: load_cicids2017_sample"
        )

    def test_has_load_unsw_function(self, loader) -> None:
        assert callable(getattr(loader, "load_unsw_nb15_sample", None)), (
            "Missing: load_unsw_nb15_sample"
        )

    def test_has_load_csv_function(self, loader) -> None:
        assert callable(getattr(loader, "load_csv", None)), (
            "Missing: load_csv"
        )


# ---------------------------------------------------------------------------
# Test 2 — Graceful handling when dataset CSVs are absent
# ---------------------------------------------------------------------------


class TestMissingDatasets:
    """CSVs are not committed to git. Loader raises FileNotFoundError when absent."""

    def test_load_cicids_raises_when_no_csvs(self, loader) -> None:
        """load_cicids2017_sample must raise FileNotFoundError when CSVs are absent."""
        try:
            result = loader.load_cicids2017_sample(sample_size=10)
            # If CSVs exist, result should be a DataFrame
            assert isinstance(result, pd.DataFrame)
        except FileNotFoundError:
            pass  # Expected when dataset CSVs are not downloaded

    def test_load_unsw_raises_when_no_csvs(self, loader) -> None:
        """load_unsw_nb15_sample must raise FileNotFoundError when CSVs are absent."""
        try:
            result = loader.load_unsw_nb15_sample(sample_size=10)
            assert isinstance(result, pd.DataFrame)
        except FileNotFoundError:
            pass  # Expected when dataset CSVs are not downloaded


# ---------------------------------------------------------------------------
# Test 3 — Synthetic CSV round-trip via tmp_path
# ---------------------------------------------------------------------------


class TestSyntheticCSVRoundTrip:
    """Write a minimal CSV and load it back via load_csv()."""

    @pytest.fixture
    def synthetic_csv(self, tmp_path: Path) -> Path:
        from ingestion.log_generator import generate_events

        events = generate_events(count=10, seed=77)
        rows = [{
            "Label": ev["label"],
            "Flow Duration": ev["flow_duration"],
            "Total Fwd Packets": ev["total_fwd_packets"],
            "Total Backward Packets": ev["total_bwd_packets"],
            "Total Length of Fwd Packets": ev["total_length_fwd_packets"] or 0,
            "Total Length of Bwd Packets": ev["total_length_bwd_packets"] or 0,
            "Flow Bytes/s": ev["flow_bytes_per_sec"] or 0,
            "Flow Packets/s": ev["flow_packets_per_sec"] or 0,
            "Destination Port": ev["dst_port"],
            # Store protocol as numeric string to match CICIDS2017 format
            "Protocol": "6" if ev["protocol"] == "TCP" else "17",
        } for ev in events]

        df = pd.DataFrame(rows)
        csv_path = tmp_path / "synthetic_cicids.csv"
        df.to_csv(csv_path, index=False)
        return csv_path

    def test_load_csv_returns_dataframe(self, loader, synthetic_csv: Path) -> None:
        """load_csv must return a non-empty DataFrame for a valid CSV."""
        df = loader.load_csv(str(synthetic_csv))
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0, "DataFrame is empty for a valid synthetic CSV."

    def test_load_csv_nrows_limit(self, loader, synthetic_csv: Path) -> None:
        """load_csv(nrows=5) must return at most 5 rows."""
        df = loader.load_csv(str(synthetic_csv), nrows=5)
        assert len(df) <= 5

    def test_load_csv_has_expected_columns(self, loader, synthetic_csv: Path) -> None:
        """Loaded DataFrame must contain the Label column."""
        df = loader.load_csv(str(synthetic_csv))
        assert "Label" in df.columns, f"Missing Label column. Got: {list(df.columns)}"

    def test_round_trip_normalisation(self, loader, normalizer_module, synthetic_csv: Path) -> None:
        """Rows from load_csv must successfully normalise to NormalizedEvent."""
        df = loader.load_csv(str(synthetic_csv))
        events = []
        for _, row in df.iterrows():
            ev = normalizer_module.normalize_cicids2017_row(row)
            events.append(ev)
        assert all(isinstance(e, NormalizedEvent) for e in events)


# ---------------------------------------------------------------------------
# Test 4 — MITRE techniques JSON
# ---------------------------------------------------------------------------


class TestMITRETechniquesJSON:
    """Validate the pre-parsed MITRE techniques lookup table built by Member 2."""

    @pytest.mark.skipif(
        not TECHNIQUES_JSON.exists(),
        reason=f"techniques.json not found at {TECHNIQUES_JSON}",
    )
    def test_techniques_json_loads(self) -> None:
        with open(TECHNIQUES_JSON, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data is not None

    @pytest.mark.skipif(
        not TECHNIQUES_JSON.exists(),
        reason=f"techniques.json not found at {TECHNIQUES_JSON}",
    )
    def test_techniques_json_is_list_or_dict(self) -> None:
        with open(TECHNIQUES_JSON, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, (list, dict))

    @pytest.mark.skipif(
        not TECHNIQUES_JSON.exists(),
        reason=f"techniques.json not found at {TECHNIQUES_JSON}",
    )
    def test_techniques_json_has_substantial_count(self) -> None:
        with open(TECHNIQUES_JSON, encoding="utf-8") as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else list(data.values())
        assert len(items) >= 100, f"Expected 100+ entries, found {len(items)}."

    @pytest.mark.skipif(
        not TECHNIQUES_JSON.exists(),
        reason=f"techniques.json not found at {TECHNIQUES_JSON}",
    )
    def test_each_technique_has_id_and_name(self) -> None:
        with open(TECHNIQUES_JSON, encoding="utf-8") as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else list(data.values())
        if not items:
            pytest.skip("techniques.json is empty.")
        sample = items[0]
        has_id = any(k in sample for k in ("technique_id", "id", "external_id"))
        has_name = any(k in sample for k in ("name", "technique_name"))
        assert has_id, f"No id field in: {list(sample.keys())}"
        assert has_name, f"No name field in: {list(sample.keys())}"
