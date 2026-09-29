"""
tests/test_normalizer.py
------------------------
Unit tests for ingestion/normalizer.py

The normalizer uses standalone functions that accept pandas Series rows:
  - normalize_cicids2017_row(row: pd.Series) -> NormalizedEvent
  - normalize_unsw_nb15_row(row: pd.Series)  -> NormalizedEvent
  - map_cicids_label(label: str)             -> ThreatCategory
  - map_unsw_label(attack_cat: str)          -> ThreatCategory
  - normalize_dataframe(df, source)          -> list[NormalizedEvent]

Note: CICIDS2017 columns are stored in the dataset with leading spaces.
The normalizer accesses them via stripped keys (e.g. "Label", not " Label").
We test with stripped-key Series matching how the loader passes rows.

Author : Member 4 — Synthetic Log Generator & Testing Setup
Phase  : 1
"""

from __future__ import annotations

import pytest

pd = pytest.importorskip("pandas", reason="pandas required for normalizer tests")

from api.models import NormalizedEvent, ThreatCategory, SeverityLevel

# ---------------------------------------------------------------------------
# Realistic pandas Series samples matching normalizer's expected column names
# (stripped — no leading spaces, as the loader strips them before passing rows)
# ---------------------------------------------------------------------------

CICIDS_SERIES_BENIGN = pd.Series({
    "Label": "BENIGN",
    "Flow Duration": 1234567.0,
    "Total Fwd Packets": 5,
    "Total Backward Packets": 3,
    "Total Length of Fwd Packets": 1500.0,
    "Total Length of Bwd Packets": 800.0,
    "Flow Bytes/s": 1854.27,
    "Flow Packets/s": 6.5,
    "Destination Port": 53,
    "Protocol": "17",  # CICIDS stores protocol as numeric string
})

CICIDS_SERIES_BRUTEFORCE = pd.Series({
    "Label": "FTP-Patator",
    "Flow Duration": 500000.0,
    "Total Fwd Packets": 150,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 9000.0,
    "Total Length of Bwd Packets": 0.0,
    "Flow Bytes/s": 18000.0,
    "Flow Packets/s": 300.0,
    "Destination Port": 22,
    "Protocol": "6",
})

UNSW_SERIES_BACKDOOR = pd.Series({
    "attack_cat": "Backdoors",
    "proto": "tcp",
    "dur": 300.5,
    "sbytes": 25000,
    "dbytes": 5000,
    "spkts": 120,
    "dpkts": 30,
    "rate": 50.0,
    "label": "1",
})

UNSW_SERIES_NORMAL = pd.Series({
    "attack_cat": "Normal",
    "proto": "udp",
    "dur": 0.5,
    "sbytes": 100,
    "dbytes": 200,
    "spkts": 2,
    "dpkts": 3,
    "rate": 10.0,
    "label": "0",
})


# ---------------------------------------------------------------------------
# Test 1 — CICIDS2017 normalisation
# ---------------------------------------------------------------------------


class TestCICIDSNormalisation:
    """Tests for normalize_cicids2017_row()."""

    def test_cicids_benign_normalises_successfully(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert result is not None

    def test_cicids_result_is_normalized_event(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert isinstance(result, NormalizedEvent)

    def test_cicids_benign_has_benign_category(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert result.threat_category == ThreatCategory.BENIGN

    def test_cicids_bruteforce_has_correct_category(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BRUTEFORCE)
        assert result.threat_category == ThreatCategory.BRUTE_FORCE

    def test_cicids_event_id_is_set(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert result.event_id and len(result.event_id) > 0

    def test_cicids_flow_duration_is_numeric(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert isinstance(result.flow_duration, (int, float))

    def test_cicids_source_dataset_tag(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert result.source_dataset == "cicids2017"

    def test_cicids_label_preserved(self, normalizer) -> None:
        result = normalizer.normalize_cicids2017_row(CICIDS_SERIES_BENIGN)
        assert result.label == "BENIGN"


# ---------------------------------------------------------------------------
# Test 2 — UNSW-NB15 normalisation
# ---------------------------------------------------------------------------


class TestUNSWNormalisation:
    """Tests for normalize_unsw_nb15_row()."""

    def test_unsw_backdoor_normalises_successfully(self, normalizer) -> None:
        result = normalizer.normalize_unsw_nb15_row(UNSW_SERIES_BACKDOOR)
        assert result is not None

    def test_unsw_result_is_normalized_event(self, normalizer) -> None:
        result = normalizer.normalize_unsw_nb15_row(UNSW_SERIES_BACKDOOR)
        assert isinstance(result, NormalizedEvent)

    def test_unsw_source_dataset_tag(self, normalizer) -> None:
        result = normalizer.normalize_unsw_nb15_row(UNSW_SERIES_BACKDOOR)
        assert result.source_dataset == "unsw_nb15"

    def test_unsw_backdoor_category(self, normalizer) -> None:
        result = normalizer.normalize_unsw_nb15_row(UNSW_SERIES_BACKDOOR)
        assert result.threat_category == ThreatCategory.BACKDOOR

    def test_unsw_normal_maps_to_benign(self, normalizer) -> None:
        result = normalizer.normalize_unsw_nb15_row(UNSW_SERIES_NORMAL)
        assert result.threat_category == ThreatCategory.BENIGN

    def test_unsw_event_id_is_set(self, normalizer) -> None:
        result = normalizer.normalize_unsw_nb15_row(UNSW_SERIES_BACKDOOR)
        assert result.event_id and len(result.event_id) > 0


# ---------------------------------------------------------------------------
# Test 3 — Label mapping functions
# ---------------------------------------------------------------------------


class TestLabelMapping:
    """Tests for map_cicids_label() and map_unsw_label()."""

    @pytest.mark.parametrize("raw_label,expected", [
        ("BENIGN",                ThreatCategory.BENIGN),
        ("FTP-Patator",           ThreatCategory.BRUTE_FORCE),
        ("SSH-Patator",           ThreatCategory.BRUTE_FORCE),
        ("DoS slowloris",         ThreatCategory.DOS),
        ("DDoS",                  ThreatCategory.DDOS),
        ("PortScan",              ThreatCategory.PORT_SCAN),
        ("Bot",                   ThreatCategory.BOTNET),
        ("Web Attack - Sql Injection", ThreatCategory.WEB_ATTACK),
        ("Web Attack - XSS",      ThreatCategory.WEB_ATTACK),
        ("Infiltration",          ThreatCategory.INFILTRATION),
        ("SomethingUnknown",      ThreatCategory.UNKNOWN),
    ])
    def test_cicids_label_mapping(self, normalizer, raw_label: str, expected) -> None:
        result = normalizer.map_cicids_label(raw_label)
        assert result == expected, f"'{raw_label}' → expected {expected}, got {result}"

    @pytest.mark.parametrize("attack_cat,expected", [
        ("Normal",         ThreatCategory.BENIGN),
        ("DoS",            ThreatCategory.DOS),
        ("Reconnaissance", ThreatCategory.RECONNAISSANCE),
        ("Backdoors",      ThreatCategory.BACKDOOR),
        ("Backdoor",       ThreatCategory.BACKDOOR),
        # UNSW categories without a matching enum fall back to UNKNOWN
        ("Exploits",       ThreatCategory.UNKNOWN),
        ("Generic",        ThreatCategory.UNKNOWN),
        ("",               ThreatCategory.UNKNOWN),
        (None,             ThreatCategory.UNKNOWN),
    ])
    def test_unsw_label_mapping(self, normalizer, attack_cat, expected) -> None:
        result = normalizer.map_unsw_label(attack_cat)
        assert result == expected, f"'{attack_cat}' → expected {expected}, got {result}"


# ---------------------------------------------------------------------------
# Test 4 — normalize_dataframe dispatch
# ---------------------------------------------------------------------------


class TestNormalizeDataframe:
    """Tests for normalize_dataframe() batch dispatcher."""

    def test_normalize_cicids_dataframe(self, normalizer) -> None:
        df = pd.DataFrame([CICIDS_SERIES_BENIGN, CICIDS_SERIES_BRUTEFORCE])
        results = normalizer.normalize_dataframe(df, source="cicids2017")
        assert len(results) == 2
        for r in results:
            assert isinstance(r, NormalizedEvent)

    def test_normalize_unsw_dataframe(self, normalizer) -> None:
        df = pd.DataFrame([UNSW_SERIES_BACKDOOR, UNSW_SERIES_NORMAL])
        results = normalizer.normalize_dataframe(df, source="unsw_nb15")
        assert len(results) == 2
        for r in results:
            assert isinstance(r, NormalizedEvent)

    def test_invalid_source_raises_value_error(self, normalizer) -> None:
        df = pd.DataFrame([CICIDS_SERIES_BENIGN])
        with pytest.raises(ValueError, match="Unknown source dataset"):
            normalizer.normalize_dataframe(df, source="unknown_dataset")


# ---------------------------------------------------------------------------
# Test 5 — NormalizedEvent Pydantic schema validation
# ---------------------------------------------------------------------------


class TestNormalizedEventSchema:
    """Direct Pydantic model validation tests."""

    def test_minimal_valid_event(self) -> None:
        ev = NormalizedEvent(event_id="test-001")
        assert ev.event_id == "test-001"

    def test_default_status_is_new(self) -> None:
        ev = NormalizedEvent(event_id="test-002")
        assert str(ev.status) in ("new", "AlertStatus.NEW")

    def test_default_severity_is_unknown(self) -> None:
        ev = NormalizedEvent(event_id="test-003")
        assert str(ev.severity) in ("Unknown", "SeverityLevel.UNKNOWN")

    def test_invalid_port_raises_validation_error(self) -> None:
        with pytest.raises(Exception):
            NormalizedEvent(event_id="test-004", dst_port=99999)

    def test_timestamp_auto_populated(self) -> None:
        ev = NormalizedEvent(event_id="test-005")
        assert ev.timestamp is not None

    def test_mitre_techniques_default_empty_list(self) -> None:
        ev = NormalizedEvent(event_id="test-006")
        assert ev.mitre_techniques == []

    def test_severity_accepts_valid_values(self) -> None:
        for level in ("Critical", "High", "Medium", "Low", "Unknown"):
            ev = NormalizedEvent(event_id=f"test-sev-{level}", severity=level)
            assert str(ev.severity) in (level, f"SeverityLevel.{level.upper()}")
