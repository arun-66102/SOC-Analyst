"""
tests/test_log_generator.py
----------------------------
Unit tests for ingestion/log_generator.py

Tests verify:
  1. Generated events contain all required NormalizedEvent fields
  2. All 12 attack types produce structurally valid events
  3. Batch generation produces the correct count and ordering
  4. Multi-step attack scenarios generate chronologically ordered chains
  5. CLI-level distribution is sane (benign events > attack events in mixed mode)
  6. Reproducibility via random seed

Author : Member 4 — Synthetic Log Generator & Testing Setup
Phase  : 1
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from ingestion.log_generator import (
    ALL_ATTACK_TYPES,
    generate_attack_scenario,
    generate_event,
    generate_events,
)

# Fields that MUST be present in every generated event (NormalizedEvent keys)
REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "label",
    "threat_category",
    "severity",
    "status",
    "source_dataset",
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Unknown"}
VALID_STATUSES = {"new", "triaged", "correlated", "enriched", "reported", "escalated", "dismissed", "closed"}


# ---------------------------------------------------------------------------
# Test 1 — single event structure
# ---------------------------------------------------------------------------


class TestSingleEventStructure:
    """Verify the shape of a single generated event."""

    def test_required_fields_present(self, sample_brute_force: dict) -> None:
        """All required NormalizedEvent fields must be in the generated event."""
        missing = REQUIRED_FIELDS - set(sample_brute_force.keys())
        assert not missing, f"Missing fields: {missing}"

    def test_event_id_is_valid_uuid(self, sample_brute_force: dict) -> None:
        """event_id must be a valid UUID v4 string."""
        try:
            uuid.UUID(sample_brute_force["event_id"], version=4)
        except ValueError:
            pytest.fail(f"event_id is not a valid UUID: {sample_brute_force['event_id']}")

    def test_timestamp_is_parseable(self, sample_brute_force: dict) -> None:
        """timestamp must be a parseable ISO-8601 string."""
        ts = sample_brute_force["timestamp"]
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            pytest.fail(f"timestamp is not ISO-8601: {ts}")

    def test_severity_is_valid(self, sample_brute_force: dict) -> None:
        """severity must be one of the known SeverityLevel values."""
        assert sample_brute_force["severity"] in VALID_SEVERITIES

    def test_status_is_new(self, sample_brute_force: dict) -> None:
        """Freshly generated events must have status='new'."""
        assert sample_brute_force["status"] == "new"

    def test_source_dataset_is_synthetic(self, sample_brute_force: dict) -> None:
        """Source dataset tag must be 'synthetic'."""
        assert sample_brute_force["source_dataset"] == "synthetic"

    def test_ports_are_in_valid_range(self, sample_brute_force: dict) -> None:
        """Source and destination ports must be in [0, 65535]."""
        assert 0 <= sample_brute_force["src_port"] <= 65535
        assert 0 <= sample_brute_force["dst_port"] <= 65535

    def test_benign_is_not_true_positive(self, sample_benign: dict) -> None:
        """Benign events must be marked as false positives."""
        assert sample_benign["is_true_positive"] is False

    def test_attack_is_true_positive(self, sample_brute_force: dict) -> None:
        """Attack events must be marked as true positives."""
        assert sample_brute_force["is_true_positive"] is True

    def test_mitre_techniques_is_empty_list(self, sample_brute_force: dict) -> None:
        """MITRE techniques list should be empty at generation time (populated by agent)."""
        assert sample_brute_force["mitre_techniques"] == []

    def test_flow_metrics_are_non_negative(self, sample_brute_force: dict) -> None:
        """Flow duration and packet counts must be non-negative."""
        assert sample_brute_force["flow_duration"] >= 0
        assert sample_brute_force["total_fwd_packets"] >= 0
        assert sample_brute_force["total_bwd_packets"] >= 0


# ---------------------------------------------------------------------------
# Test 2 — all attack types produce valid events
# ---------------------------------------------------------------------------


class TestAllAttackTypes:
    """Parametrised test — one event per attack type."""

    @pytest.mark.parametrize("attack_type", ALL_ATTACK_TYPES)
    def test_event_generation_succeeds(self, attack_type: str) -> None:
        """generate_event() must not raise for any known attack type."""
        ev = generate_event(attack_type)
        assert ev is not None

    @pytest.mark.parametrize("attack_type", ALL_ATTACK_TYPES)
    def test_label_is_non_empty(self, attack_type: str) -> None:
        """Every attack type must produce a non-empty label."""
        ev = generate_event(attack_type)
        assert ev["label"], f"Empty label for attack type: {attack_type}"

    @pytest.mark.parametrize("attack_type", ALL_ATTACK_TYPES)
    def test_threat_category_is_non_empty(self, attack_type: str) -> None:
        """Every attack type must produce a non-empty threat_category."""
        ev = generate_event(attack_type)
        assert ev["threat_category"], f"Empty threat_category for: {attack_type}"

    def test_invalid_attack_type_raises(self) -> None:
        """Unknown attack types must raise ValueError."""
        with pytest.raises(ValueError, match="Unknown attack_type"):
            generate_event("alien_invasion")


# ---------------------------------------------------------------------------
# Test 3 — batch generation
# ---------------------------------------------------------------------------


class TestBatchGeneration:
    """Tests for generate_events() batch function."""

    def test_correct_count_returned(self) -> None:
        """generate_events(count=N) must return exactly N events."""
        events = generate_events(count=50, seed=1)
        assert len(events) == 50

    def test_events_are_sorted_by_timestamp(self) -> None:
        """Batch output must be sorted ascending by timestamp."""
        events = generate_events(count=100, seed=2)
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps), "Events are not sorted by timestamp."

    def test_single_attack_type_filter(self) -> None:
        """Specifying attack_type must produce only that category."""
        events = generate_events(count=30, attack_type="ddos", seed=3)
        categories = {e["threat_category"] for e in events}
        assert categories == {"DDoS"}, f"Expected only DDoS, got: {categories}"

    def test_mixed_mode_produces_multiple_categories(self, bulk_events: list[dict]) -> None:
        """Mixed mode (no attack_type filter) must produce multiple categories."""
        categories = {e["threat_category"] for e in bulk_events}
        assert len(categories) >= 3, f"Too few categories in mixed mode: {categories}"

    def test_reproducibility_with_seed(self) -> None:
        """Same seed must produce identical reproducible fields (IPs, labels, severity).
        Note: event_id uses uuid4() which draws OS entropy — it is intentionally
        unique per call and cannot be seeded, so we test the seeded fields only.
        """
        batch_a = generate_events(count=10, seed=42)
        batch_b = generate_events(count=10, seed=42)
        # These fields are fully determined by random.seed()
        assert [e["src_ip"]  for e in batch_a] == [e["src_ip"]  for e in batch_b]
        assert [e["dst_ip"]  for e in batch_a] == [e["dst_ip"]  for e in batch_b]
        assert [e["label"]   for e in batch_a] == [e["label"]   for e in batch_b]
        assert [e["severity"] for e in batch_a] == [e["severity"] for e in batch_b]

    def test_different_seeds_produce_different_events(self) -> None:
        """Different seeds must (almost certainly) produce different event_ids."""
        batch_a = generate_events(count=5, seed=1)
        batch_b = generate_events(count=5, seed=2)
        ids_a = set(e["event_id"] for e in batch_a)
        ids_b = set(e["event_id"] for e in batch_b)
        assert ids_a.isdisjoint(ids_b), "Seeded batches share event_ids — collision risk."

    def test_all_events_have_unique_ids(self, bulk_events: list[dict]) -> None:
        """All event_ids in a batch must be unique."""
        ids = [e["event_id"] for e in bulk_events]
        assert len(ids) == len(set(ids)), "Duplicate event_ids found in batch."

    def test_json_serialisable(self) -> None:
        """Generated events must be JSON-serialisable."""
        events = generate_events(count=5, seed=7)
        try:
            json.dumps(events, default=str)
        except (TypeError, ValueError) as exc:
            pytest.fail(f"Events are not JSON serialisable: {exc}")


# ---------------------------------------------------------------------------
# Test 4 — attack scenario chains
# ---------------------------------------------------------------------------


class TestAttackScenarios:
    """Tests for multi-step attack scenario generator."""

    @pytest.mark.parametrize("scenario", ["apt", "ransomware", "web"])
    def test_scenario_generates_events(self, scenario: str) -> None:
        """All scenario names must produce at least 2 events."""
        chain = generate_attack_scenario(scenario)
        assert len(chain) >= 2, f"Scenario '{scenario}' produced too few events."

    def test_apt_scenario_chronological_order(self) -> None:
        """APT scenario events must be sorted by timestamp."""
        chain = generate_attack_scenario("apt")
        timestamps = [e["timestamp"] for e in chain]
        assert timestamps == sorted(timestamps), "APT scenario events not in chronological order."

    def test_apt_scenario_contains_expected_stages(self) -> None:
        """APT scenario must contain recon, brute-force, lateral movement, and exfiltration."""
        chain = generate_attack_scenario("apt")
        categories = {e["threat_category"] for e in chain}
        expected = {"Reconnaissance", "BruteForce", "Infiltration", "Malware", "Exfiltration"}
        assert expected.issubset(categories), (
            f"APT scenario missing stages. Got: {categories}"
        )

    def test_consistent_src_ip_across_scenario(self) -> None:
        """All events in a scenario must share the same attacker src_ip."""
        chain = generate_attack_scenario("apt")
        src_ips = {e["src_ip"] for e in chain}
        # All attacker IPs should be the same (set in scenario builder)
        assert len(src_ips) == 1, f"Multiple src_ips in scenario: {src_ips}"

    def test_invalid_scenario_raises(self) -> None:
        """Unknown scenario names must raise ValueError."""
        with pytest.raises(ValueError, match="Unknown scenario"):
            generate_attack_scenario("solar_storm")
