import sys
import uuid
from pathlib import Path

import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ============================================================================
# Make the project root importable, so we can import api.models
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from api.models import NormalizedEvent, ThreatCategory

from ingestion.dataset_loader import (
    load_cicids2017_sample,
    load_cicids2017_labelled_sample,
    load_unsw_nb15_sample,
    load_unsw_nb15_raw_sample,
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

    return ThreatCategory.UNKNOWN


# ============================================================================
# CICIDS2017 row -> NormalizedEvent
# (works for both the processed, IP-less version and the labelled,
#  IP-inclusive version — get_val() simply returns None for any column
#  that isn't present in a given row's source)
# ============================================================================

def normalize_cicids2017_row(row, source_dataset="cicids2017"):
    """
    Convert a single CICIDS2017 row (pandas Series) into a NormalizedEvent.

    Parameters:
        row: A pandas Series representing one raw CICIDS2017 event.
        source_dataset: Label identifying which CICIDS2017 variant this row
            came from — "cicids2017" (no IPs) or "cicids2017_labelled"
            (with Source IP / Destination IP).
    """

    label = get_val(row, "Label")

    event = NormalizedEvent(
        event_id=str(uuid.uuid4()),

        src_ip=get_val(row, "Source IP"),
        dst_ip=get_val(row, "Destination IP"),
        src_port=get_val(row, "Source Port"),
        dst_port=get_val(row, "Destination Port"),
        protocol=str(get_val(row, "Protocol")) if get_val(row, "Protocol") is not None else None,
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
        source_dataset=source_dataset,
    )

    return event


# ============================================================================
# UNSW-NB15 row -> NormalizedEvent
# (works for both the processed, IP-less version and the raw,
#  IP-inclusive version — get_val() handles either column set safely)
# ============================================================================

def normalize_unsw_nb15_row(row, source_dataset="unsw_nb15"):
    """
    Convert a single UNSW-NB15 row (pandas Series) into a NormalizedEvent.

    Parameters:
        row: A pandas Series representing one raw UNSW-NB15 event.
        source_dataset: Label identifying which UNSW-NB15 variant this row
            came from — "unsw_nb15" (no IPs) or "unsw_nb15_raw"
            (with srcip / dstip).
    """

    attack_cat = get_val(row, "attack_cat")

    # The processed version uses lowercase 'label'; the raw version uses
    # capitalized 'Label'. Try both so this function works for either.
    label_val = get_val(row, "label")
    if label_val is None:
        label_val = get_val(row, "Label")

    event = NormalizedEvent(
        event_id=str(uuid.uuid4()),

        src_ip=get_val(row, "srcip"),
        dst_ip=get_val(row, "dstip"),
        src_port=get_val(row, "sport"),
        dst_port=get_val(row, "dsport"),
        protocol=get_val(row, "proto"),

        flow_duration=get_val(row, "dur"),
        total_fwd_packets=get_val(row, "spkts") or get_val(row, "Spkts"),
        total_bwd_packets=get_val(row, "dpkts") or get_val(row, "Dpkts"),
        total_length_fwd_packets=get_val(row, "sbytes"),
        total_length_bwd_packets=get_val(row, "dbytes"),
        flow_bytes_per_sec=None,
        flow_packets_per_sec=get_val(row, "rate"),

        label=str(attack_cat) if attack_cat is not None else "Normal",
        threat_category=map_unsw_label(attack_cat),

        raw_payload=row.to_dict(),
        source_dataset=source_dataset,
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
        source: One of "cicids2017", "cicids2017_labelled", "unsw_nb15",
            or "unsw_nb15_raw".

    Returns:
        list[NormalizedEvent]
    """

    if source in ("cicids2017", "cicids2017_labelled"):
        normalize_fn = lambda row: normalize_cicids2017_row(row, source_dataset=source)
    elif source in ("unsw_nb15", "unsw_nb15_raw"):
        normalize_fn = lambda row: normalize_unsw_nb15_row(row, source_dataset=source)
    else:
        raise ValueError(
            f"Unknown source dataset: {source}. "
            "Expected 'cicids2017', 'cicids2017_labelled', "
            "'unsw_nb15', or 'unsw_nb15_raw'."
        )

    events = []

    for _, row in df.iterrows():
        events.append(normalize_fn(row))

    return events


# ============================================================================
# Main test
# ============================================================================

if __name__ == "__main__":

    print("Loading CICIDS2017 labelled (IP-inclusive) sample...\n")

    cicids_df = load_cicids2017_labelled_sample(sample_size=100, random_state=42)

    print("Normalizing CICIDS2017 labelled sample...\n")

    cicids_events = normalize_dataframe(cicids_df, source="cicids2017_labelled")

    print(f"Normalized {len(cicids_events)} CICIDS2017 (labelled) events.")

    print("\nExample normalized event (src_ip / dst_ip should be populated):")
    example = cicids_events[0]
    print(f"src_ip: {example.src_ip}")
    print(f"dst_ip: {example.dst_ip}")
    print(f"src_port: {example.src_port}")
    print(f"threat_category: {example.threat_category}")

    print(
        "\n\nLoading UNSW-NB15 raw (IP-inclusive) sample...\n"
    )

    unsw_df = load_unsw_nb15_raw_sample(sample_size=100, random_state=42)

    print("Normalizing UNSW-NB15 raw sample...\n")

    unsw_events = normalize_dataframe(unsw_df, source="unsw_nb15_raw")

    print(f"Normalized {len(unsw_events)} UNSW-NB15 (raw) events.")

    print("\nExample normalized event (src_ip / dst_ip should be populated):")
    example2 = unsw_events[0]
    print(f"src_ip: {example2.src_ip}")
    print(f"dst_ip: {example2.dst_ip}")
    print(f"src_port: {example2.src_port}")
    print(f"threat_category: {example2.threat_category}")