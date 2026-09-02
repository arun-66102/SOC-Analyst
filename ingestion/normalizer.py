import sys
import uuid
from pathlib import Path

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")

# ============================================================================
# Make the project root importable, so we can import api.models
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from api.models import NormalizedEvent, ThreatCategory

from ingestion.dataset_loader import (
    load_cicids2017_sample,
    load_unsw_nb15_sample,
)


# ============================================================================
# Safe value extraction helper
# ============================================================================

def get_val(row, column):
    """
    Safely fetch a value from a row.

    Returns None if the column doesn't exist or the value is NaN,
    instead of raising an error or storing a NaN into the schema.
    """

    if column not in row or pd.isna(row[column]):
        return None

    return row[column]


# ============================================================================
# CICIDS2017 label -> ThreatCategory mapping
# ============================================================================

def map_cicids_label(label):
    """
    Map a raw CICIDS2017 'Label' value to a ThreatCategory enum member.
    """

    if label is None:
        return ThreatCategory.UNKNOWN

    label = str(label).strip()

    if label == "BENIGN":
        return ThreatCategory.BENIGN

    if label in ("FTP-Patator", "SSH-Patator"):
        return ThreatCategory.BRUTE_FORCE

    if label.startswith("DoS") or label == "Heartbleed":
        return ThreatCategory.DOS

    if label == "DDoS":
        return ThreatCategory.DDOS

    if label == "PortScan":
        return ThreatCategory.PORT_SCAN

    if label == "Infiltration":
        return ThreatCategory.INFILTRATION

    if label == "Bot":
        return ThreatCategory.BOTNET

    # CICIDS2017's raw CSVs sometimes corrupt the dash in "Web Attack – X"
    # (encoding issue in the original dataset). Match on the prefix instead
    # of the exact string so this still works regardless of the dash used.
    if label.startswith("Web Attack"):
        return ThreatCategory.WEB_ATTACK

    return ThreatCategory.UNKNOWN


# ============================================================================
# UNSW-NB15 attack_cat -> ThreatCategory mapping
# ============================================================================

def map_unsw_label(attack_cat):
    """
    Map a raw UNSW-NB15 'attack_cat' value to a ThreatCategory enum member.

    NOTE: UNSW-NB15 has several categories (Generic, Exploits, Fuzzers,
    Analysis, Shellcode, Worms) with no matching ThreatCategory member.
    These currently fall back to UNKNOWN — flag this to Member 1 if the
    team wants these preserved as distinct categories.
    """

    if attack_cat is None:
        return ThreatCategory.UNKNOWN

    attack_cat = str(attack_cat).strip()

    if attack_cat == "Normal":
        return ThreatCategory.BENIGN

    if attack_cat == "DoS":
        return ThreatCategory.DOS

    if attack_cat == "Reconnaissance":
        return ThreatCategory.RECONNAISSANCE

    if attack_cat in ("Backdoor", "Backdoors"):
        return ThreatCategory.BACKDOOR

    # Generic, Exploits, Fuzzers, Analysis, Shellcode, Worms
    return ThreatCategory.UNKNOWN


# ============================================================================
# CICIDS2017 row -> NormalizedEvent
# ============================================================================

def normalize_cicids2017_row(row):
    """
    Convert a single CICIDS2017 row (pandas Series) into a NormalizedEvent.
    """

    label = get_val(row, "Label")
    protocol_raw = get_val(row, "Protocol")
    # Protocol in CICIDS2017 is stored as a numeric code (6=TCP, 17=UDP).
    # NormalizedEvent.protocol expects a string — coerce safely.
    protocol_str = str(int(protocol_raw)) if protocol_raw is not None else None

    event = NormalizedEvent(
        event_id=str(uuid.uuid4()),

        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=get_val(row, "Destination Port"),
        protocol=protocol_str,

        flow_duration=get_val(row, "Flow Duration"),
        total_fwd_packets=get_val(row, "Total Fwd Packets"),
        total_bwd_packets=get_val(row, "Total Backward Packets"),
        total_length_fwd_packets=get_val(row, "Total Length of Fwd Packets"),
        total_length_bwd_packets=get_val(row, "Total Length of Bwd Packets"),
        flow_bytes_per_sec=get_val(row, "Flow Bytes/s"),
        flow_packets_per_sec=get_val(row, "Flow Packets/s"),

        label=str(label) if label is not None else None,
        threat_category=map_cicids_label(label),

        raw_payload=row.to_dict(),
        source_dataset="cicids2017",
    )

    return event



# ============================================================================
# UNSW-NB15 row -> NormalizedEvent
# ============================================================================

def normalize_unsw_nb15_row(row):
    """
    Convert a single UNSW-NB15 row (pandas Series) into a NormalizedEvent.
    """

    attack_cat = get_val(row, "attack_cat")

    event = NormalizedEvent(
        event_id=str(uuid.uuid4()),

        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=get_val(row, "proto"),

        flow_duration=get_val(row, "dur"),
        total_fwd_packets=get_val(row, "spkts"),
        total_bwd_packets=get_val(row, "dpkts"),
        total_length_fwd_packets=get_val(row, "sbytes"),
        total_length_bwd_packets=get_val(row, "dbytes"),
        flow_bytes_per_sec=None,
        flow_packets_per_sec=get_val(row, "rate"),

        label=str(attack_cat) if attack_cat is not None else "Normal",
        threat_category=map_unsw_label(attack_cat),

        raw_payload=row.to_dict(),
        source_dataset="unsw_nb15",
    )

    return event


# ============================================================================
# Dataframe -> list[NormalizedEvent] dispatcher
# ============================================================================

def normalize_dataframe(df, source):
    """
    Normalize every row of a dataframe into a list of NormalizedEvent objects.

    Parameters:
        df: pandas.DataFrame containing raw dataset rows.
        source: Either "cicids2017" or "unsw_nb15".

    Returns:
        list[NormalizedEvent]
    """

    if source == "cicids2017":
        normalize_fn = normalize_cicids2017_row
    elif source == "unsw_nb15":
        normalize_fn = normalize_unsw_nb15_row
    else:
        raise ValueError(
            f"Unknown source dataset: {source}. "
            "Expected 'cicids2017' or 'unsw_nb15'."
        )

    events = []

    for _, row in df.iterrows():
        events.append(normalize_fn(row))

    return events


# ============================================================================
# Main test
# ============================================================================

if __name__ == "__main__":

    print("Loading CICIDS2017 sample...\n")

    cicids_df = load_cicids2017_sample(sample_size=100, random_state=42)

    print("Normalizing CICIDS2017 sample...\n")

    cicids_events = normalize_dataframe(cicids_df, source="cicids2017")

    print(f"Normalized {len(cicids_events)} CICIDS2017 events.")

    print("\nExample normalized event:")
    print(cicids_events[0].model_dump_json(indent=2))

    print(
        "\n\nLoading UNSW-NB15 sample...\n"
    )

    unsw_df = load_unsw_nb15_sample(sample_size=100, random_state=42)

    print("Normalizing UNSW-NB15 sample...\n")

    unsw_events = normalize_dataframe(unsw_df, source="unsw_nb15")

    print(f"Normalized {len(unsw_events)} UNSW-NB15 events.")

    print("\nExample normalized event:")
    print(unsw_events[0].model_dump_json(indent=2))