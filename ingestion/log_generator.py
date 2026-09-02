"""
ingestion/log_generator.py
--------------------------
Synthetic Security Event Generator

Generates realistic fake security events for testing and development.
Produces NormalizedEvent-compatible JSON records without needing real
network traffic data.

Attack Types Supported (10+):
  1.  Brute Force (SSH / RDP / HTTP login)
  2.  Port Scan (horizontal + vertical)
  3.  DDoS (UDP/ICMP flood)
  4.  DoS (SYN flood, Slowloris)
  5.  Data Exfiltration (large outbound transfers)
  6.  Malware C2 Beacon (periodic callback)
  7.  Web Application Attack (SQLi, XSS, LFI)
  8.  Botnet Activity (peer-to-peer coordination)
  9.  Lateral Movement (SMB / pass-the-hash)
  10. Reconnaissance (ICMP sweep, DNS enumeration)
  11. Backdoor / Reverse Shell
  12. Benign (normal traffic baseline)

Usage:
    python -m ingestion.log_generator --count 1000 --output data/synthetic/events.json
    python -m ingestion.log_generator --count 100  --attack brute_force

Author : Member 4 — Synthetic Log Generator & Testing Setup
Phase  : 1
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants / realistic value pools
# ---------------------------------------------------------------------------

_INTERNAL_SUBNETS = ["192.168.1", "10.0.0", "172.16.0"]
_EXTERNAL_IPS = [
    "45.33.32.156", "198.51.100.23", "203.0.113.99",
    "185.220.101.18", "91.108.4.2",  "104.21.45.12",
    "52.86.200.111",  "146.190.50.14", "167.99.210.44",
    "142.250.80.46",  "13.107.42.14",  "34.160.0.1",
]
_PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "python-requests/2.28.0",
    "Masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "nmap",
    "sqlmap/1.7",
    "curl/7.88.1",
]
_USERNAMES = ["admin", "root", "user", "administrator", "service", "deploy", "pi"]
_FILE_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592",
    "098f6bcd4621d373cade4e832627b4f6",
]

# ---------------------------------------------------------------------------
# Attack scenario definitions
# ---------------------------------------------------------------------------

AttackType = str

ATTACK_PROFILES: dict[AttackType, dict] = {
    "brute_force": {
        "label": "BruteForce",
        "threat_category": "BruteForce",
        "dst_ports": [22, 3389, 80, 443, 21, 23],
        "protocol": "TCP",
        "severity_weights": {"Critical": 0.2, "High": 0.5, "Medium": 0.3},
        "flow_duration_range": (100, 5000),
        "pkt_range": (2, 10),
        "bytes_range": (60, 500),
        "description": "Repeated login attempts from external IP",
    },
    "port_scan": {
        "label": "PortScan",
        "threat_category": "PortScan",
        "dst_ports": list(range(1, 1024)),
        "protocol": "TCP",
        "severity_weights": {"High": 0.3, "Medium": 0.5, "Low": 0.2},
        "flow_duration_range": (10, 200),
        "pkt_range": (1, 3),
        "bytes_range": (40, 100),
        "description": "Sequential port probing from single source",
    },
    "ddos": {
        "label": "DDoS",
        "threat_category": "DDoS",
        "dst_ports": [80, 443, 53],
        "protocol": "UDP",
        "severity_weights": {"Critical": 0.6, "High": 0.4},
        "flow_duration_range": (50000, 500000),
        "pkt_range": (50000, 1000000),
        "bytes_range": (1000000, 50000000),
        "description": "Volumetric UDP/ICMP flood from multiple sources",
    },
    "dos": {
        "label": "DoS",
        "threat_category": "DoS",
        "dst_ports": [80, 443],
        "protocol": "TCP",
        "severity_weights": {"Critical": 0.4, "High": 0.5, "Medium": 0.1},
        "flow_duration_range": (100000, 2000000),
        "pkt_range": (10000, 200000),
        "bytes_range": (500000, 20000000),
        "description": "SYN flood / Slowloris exhausting server resources",
    },
    "exfiltration": {
        "label": "Exfiltration",
        "threat_category": "Exfiltration",
        "dst_ports": [443, 80, 21, 22],
        "protocol": "TCP",
        "severity_weights": {"Critical": 0.7, "High": 0.3},
        "flow_duration_range": (30000, 300000),
        "pkt_range": (100, 5000),
        "bytes_range": (5000000, 100000000),
        "description": "Large outbound data transfer to external IP",
    },
    "malware_c2": {
        "label": "Malware",
        "threat_category": "Malware",
        "dst_ports": [4444, 8080, 443, 1337, 6667],
        "protocol": "TCP",
        "severity_weights": {"Critical": 0.6, "High": 0.4},
        "flow_duration_range": (1000, 10000),
        "pkt_range": (5, 50),
        "bytes_range": (200, 4000),
        "description": "Periodic C2 beacon to known malicious infrastructure",
    },
    "web_attack": {
        "label": "WebAttack",
        "threat_category": "WebAttack",
        "dst_ports": [80, 443, 8080, 8443],
        "protocol": "TCP",
        "severity_weights": {"High": 0.4, "Medium": 0.5, "Low": 0.1},
        "flow_duration_range": (500, 20000),
        "pkt_range": (3, 30),
        "bytes_range": (200, 8000),
        "description": "SQL injection / XSS / LFI web application attack",
    },
    "botnet": {
        "label": "Botnet",
        "threat_category": "Botnet",
        "dst_ports": [6667, 6697, 443, 8080],
        "protocol": "TCP",
        "severity_weights": {"High": 0.5, "Medium": 0.4, "Low": 0.1},
        "flow_duration_range": (5000, 60000),
        "pkt_range": (20, 200),
        "bytes_range": (1000, 50000),
        "description": "IRC / HTTP botnet coordination traffic",
    },
    "lateral_movement": {
        "label": "Infiltration",
        "threat_category": "Infiltration",
        "dst_ports": [445, 135, 139, 3389],
        "protocol": "TCP",
        "severity_weights": {"Critical": 0.5, "High": 0.5},
        "flow_duration_range": (1000, 50000),
        "pkt_range": (10, 100),
        "bytes_range": (500, 20000),
        "description": "SMB / RDP lateral movement to internal host",
    },
    "reconnaissance": {
        "label": "Reconnaissance",
        "threat_category": "Reconnaissance",
        "dst_ports": [53, 80, 443, 8080],
        "protocol": "ICMP",
        "severity_weights": {"Medium": 0.5, "Low": 0.5},
        "flow_duration_range": (10, 500),
        "pkt_range": (1, 5),
        "bytes_range": (20, 200),
        "description": "ICMP sweep / DNS enumeration reconnaissance",
    },
    "backdoor": {
        "label": "Backdoor",
        "threat_category": "Backdoor",
        "dst_ports": [4444, 1234, 31337, 9001],
        "protocol": "TCP",
        "severity_weights": {"Critical": 0.8, "High": 0.2},
        "flow_duration_range": (10000, 300000),
        "pkt_range": (50, 500),
        "bytes_range": (2000, 30000),
        "description": "Persistent reverse shell / backdoor connection",
    },
    "benign": {
        "label": "BENIGN",
        "threat_category": "Benign",
        "dst_ports": [80, 443, 53, 25, 587, 22],
        "protocol": "TCP",
        "severity_weights": {"Low": 1.0},
        "flow_duration_range": (100, 50000),
        "pkt_range": (1, 500),
        "bytes_range": (64, 500000),
        "description": "Normal business traffic",
    },
}

ALL_ATTACK_TYPES = list(ATTACK_PROFILES.keys())

# Default distribution for mixed generation (weighted toward benign)
_DEFAULT_WEIGHTS = [
    5,   # brute_force
    6,   # port_scan
    4,   # ddos
    4,   # dos
    3,   # exfiltration
    5,   # malware_c2
    5,   # web_attack
    3,   # botnet
    3,   # lateral_movement
    5,   # reconnaissance
    2,   # backdoor
    55,  # benign  ← realistic ratio
]


# ---------------------------------------------------------------------------
# Helper generators
# ---------------------------------------------------------------------------


def _random_internal_ip() -> str:
    subnet = random.choice(_INTERNAL_SUBNETS)
    return f"{subnet}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    return random.choice(_EXTERNAL_IPS)


def _weighted_choice(weights_dict: dict[str, float]) -> str:
    keys = list(weights_dict.keys())
    weights = [weights_dict[k] for k in keys]
    return random.choices(keys, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Core event generator
# ---------------------------------------------------------------------------


def generate_event(
    attack_type: Optional[str] = None,
    base_timestamp: Optional[datetime] = None,
    jitter_seconds: int = 300,
) -> dict:
    """
    Generate a single synthetic security event.

    Parameters
    ----------
    attack_type     : one of ATTACK_PROFILES keys; random if None
    base_timestamp  : anchor time for the event (defaults to now UTC)
    jitter_seconds  : ±random seconds added to base_timestamp

    Returns
    -------
    dict compatible with NormalizedEvent schema (serialised to JSON)
    """
    if attack_type is None:
        attack_type = random.choices(ALL_ATTACK_TYPES, weights=_DEFAULT_WEIGHTS, k=1)[0]

    if attack_type not in ATTACK_PROFILES:
        raise ValueError(f"Unknown attack_type '{attack_type}'. Choose from: {ALL_ATTACK_TYPES}")

    profile = ATTACK_PROFILES[attack_type]
    is_benign = attack_type == "benign"

    # Timestamps
    if base_timestamp is None:
        base_timestamp = datetime.now(timezone.utc)
    jitter = timedelta(seconds=random.randint(-jitter_seconds, jitter_seconds))
    timestamp = (base_timestamp + jitter).isoformat()

    # Network context
    if is_benign or attack_type == "lateral_movement":
        src_ip = _random_internal_ip()
    else:
        src_ip = _random_external_ip() if random.random() > 0.2 else _random_internal_ip()

    dst_ip = _random_internal_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(profile["dst_ports"])
    protocol = profile.get("protocol", random.choice(_PROTOCOLS))

    # Traffic features
    flow_min, flow_max = profile["flow_duration_range"]
    pkt_min, pkt_max = profile["pkt_range"]
    byte_min, byte_max = profile["bytes_range"]

    flow_duration = random.uniform(flow_min, flow_max)
    total_fwd = random.randint(pkt_min, pkt_max)
    total_bwd = random.randint(0, total_fwd)
    fwd_bytes = random.uniform(byte_min / 2, byte_max / 2)
    bwd_bytes = random.uniform(0, fwd_bytes)

    flow_bytes_ps = (fwd_bytes + bwd_bytes) / max(flow_duration / 1_000_000, 0.001)
    flow_pkts_ps = (total_fwd + total_bwd) / max(flow_duration / 1_000_000, 0.001)

    # Severity
    severity = _weighted_choice(profile["severity_weights"])

    # Extra payload (attack-specific metadata)
    extra: dict = {}
    if attack_type == "brute_force":
        extra["username"] = random.choice(_USERNAMES)
        extra["failed_attempts"] = random.randint(5, 200)
        extra["service"] = {22: "ssh", 3389: "rdp", 80: "http"}.get(dst_port, "unknown")
    elif attack_type == "web_attack":
        extra["user_agent"] = random.choice(_USER_AGENTS)
        extra["http_method"] = random.choice(["GET", "POST"])
        extra["uri"] = random.choice([
            "/login?user=admin'--",
            "/search?q=<script>alert(1)</script>",
            "/etc/passwd",
            "/admin/config.php?file=../../../../etc/shadow",
        ])
    elif attack_type == "malware_c2":
        extra["beacon_interval_sec"] = random.choice([30, 60, 120, 300, 3600])
        extra["c2_domain"] = random.choice([
            "update.microsoft-cdn.net.evil.com",
            "telemetry.google-update.xyz",
            "cdn.delivery-service.io",
        ])
    elif attack_type in ("exfiltration", "backdoor"):
        extra["file_hash"] = random.choice(_FILE_HASHES)
        extra["bytes_uploaded"] = int(fwd_bytes + bwd_bytes)

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "flow_duration": round(flow_duration, 2),
        "total_fwd_packets": total_fwd,
        "total_bwd_packets": total_bwd,
        "total_length_fwd_packets": round(fwd_bytes, 2),
        "total_length_bwd_packets": round(bwd_bytes, 2),
        "flow_bytes_per_sec": round(flow_bytes_ps, 2),
        "flow_packets_per_sec": round(flow_pkts_ps, 2),
        "label": profile["label"],
        "threat_category": profile["threat_category"],
        "severity": severity,
        "status": "new",
        "incident_id": None,
        "mitre_techniques": [],
        "is_true_positive": not is_benign,
        "enrichment_data": None,
        "raw_payload": extra or None,
        "source_dataset": "synthetic",
    }

    return event


# ---------------------------------------------------------------------------
# Batch generator
# ---------------------------------------------------------------------------


def generate_events(
    count: int = 1000,
    attack_type: Optional[str] = None,
    start_time: Optional[datetime] = None,
    window_hours: int = 24,
    seed: Optional[int] = None,
) -> list[dict]:
    """
    Generate ``count`` synthetic events spread across a time window.

    Parameters
    ----------
    count        : total number of events to generate
    attack_type  : if set, all events will be of this type; else mixed
    start_time   : beginning of the time window (default: 24h ago)
    window_hours : duration of the time window in hours
    seed         : random seed for reproducibility

    Returns
    -------
    list of event dicts sorted by timestamp ascending
    """
    if seed is not None:
        random.seed(seed)

    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    window_seconds = window_hours * 3600
    events = []

    for i in range(count):
        offset = timedelta(seconds=random.uniform(0, window_seconds))
        base_ts = start_time + offset
        ev = generate_event(
            attack_type=attack_type,
            base_timestamp=base_ts,
            jitter_seconds=0,
        )
        events.append(ev)

        if (i + 1) % 200 == 0:
            logger.info("Generated %d / %d events …", i + 1, count)

    events.sort(key=lambda e: e["timestamp"])
    logger.info("Total events generated: %d", len(events))
    return events


# ---------------------------------------------------------------------------
# Attack scenario builder (multi-step attack chains)
# ---------------------------------------------------------------------------


def generate_attack_scenario(scenario: str = "apt") -> list[dict]:
    """
    Generate a realistic multi-step attack chain for evaluation.

    Scenarios:
      - 'apt'      : Recon → Brute Force → Lateral Movement → Exfiltration
      - 'ransomware': Port Scan → Malware C2 → Exfiltration → DoS
      - 'web'      : Web Attack → Backdoor → Exfiltration

    Returns events in chronological order.
    """
    base = datetime.now(timezone.utc) - timedelta(hours=2)
    chain: list[dict] = []

    if scenario == "apt":
        steps = [
            ("reconnaissance", 0, 20),
            ("brute_force", 30, 10),
            ("lateral_movement", 60, 5),
            ("malware_c2", 90, 3),
            ("exfiltration", 120, 2),
        ]
    elif scenario == "ransomware":
        steps = [
            ("port_scan", 0, 30),
            ("malware_c2", 20, 5),
            ("exfiltration", 60, 3),
            ("dos", 90, 10),
        ]
    elif scenario == "web":
        steps = [
            ("web_attack", 0, 15),
            ("backdoor", 20, 3),
            ("lateral_movement", 45, 5),
            ("exfiltration", 80, 2),
        ]
    else:
        raise ValueError(f"Unknown scenario '{scenario}'. Choose: apt, ransomware, web")

    src_ip = _random_external_ip()  # Same attacker IP throughout

    for (attack_type, offset_min, n_events) in steps:
        step_base = base + timedelta(minutes=offset_min)
        for _ in range(n_events):
            ev = generate_event(
                attack_type=attack_type,
                base_timestamp=step_base,
                jitter_seconds=60,
            )
            ev["src_ip"] = src_ip  # Consistent attacker IP
            chain.append(ev)

    chain.sort(key=lambda e: e["timestamp"])
    return chain


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synthetic security event generator for SOC Analyst testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available attack types: {', '.join(ALL_ATTACK_TYPES)}",
    )
    parser.add_argument("--count", type=int, default=1000, help="Number of events to generate")
    parser.add_argument(
        "--attack",
        choices=ALL_ATTACK_TYPES,
        default=None,
        help="Generate only this attack type (default: mixed)",
    )
    parser.add_argument(
        "--scenario",
        choices=["apt", "ransomware", "web"],
        default=None,
        help="Generate a multi-step attack scenario chain",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/synthetic/events.json"),
        help="Output JSON file path",
    )
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--window-hours", type=int, default=24, help="Time window in hours")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    args = _parse_args()

    if args.scenario:
        logger.info("Generating '%s' attack scenario …", args.scenario)
        events = generate_attack_scenario(args.scenario)
    else:
        logger.info(
            "Generating %d events (type=%s) …",
            args.count,
            args.attack or "mixed",
        )
        events = generate_events(
            count=args.count,
            attack_type=args.attack,
            window_hours=args.window_hours,
            seed=args.seed,
        )

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(events, fh, indent=2, default=str)

    logger.info("Wrote %d events → %s", len(events), args.output)

    # Print stats
    from collections import Counter
    cats = Counter(e["threat_category"] for e in events)
    print("\n--- Event Distribution ---")
    for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        pct = cnt / len(events) * 100
        print(f"  {cat:<20} {cnt:>5}  ({pct:.1f}%)")
    print(f"  {'TOTAL':<20} {len(events):>5}")


if __name__ == "__main__":
    main()
