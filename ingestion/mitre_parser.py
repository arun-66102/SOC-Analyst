import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

STIX_PATH = PROJECT_ROOT / "data" / "mitre_stix" / "enterprise-attack.json"
OUTPUT_PATH = PROJECT_ROOT / "data" / "mitre_stix" / "techniques.json"


# ============================================================================
# Helpers
# ============================================================================

def get_technique_id(obj):
    """
    Extract the MITRE technique ID (e.g. 'T1055.011') from an
    attack-pattern object's external_references.

    Returns None if no mitre-attack reference is found.
    """

    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")

    return None


def slugify_tactic(phase_name):
    """
    Convert a kill_chain phase_name slug (e.g. 'privilege-escalation')
    into MITRE's standard readable tactic name (e.g. 'Privilege Escalation').
    """

    words = phase_name.split("-")

    return " ".join(word.capitalize() for word in words)


def get_tactics(obj):
    """
    Extract the list of readable tactic names from an attack-pattern's
    kill_chain_phases.
    """

    tactics = []

    for phase in obj.get("kill_chain_phases", []):

        if phase.get("kill_chain_name") != "mitre-attack":
            continue

        tactics.append(
            slugify_tactic(phase.get("phase_name", ""))
        )

    return tactics


# ============================================================================
# Main parser
# ============================================================================

def parse_techniques():
    """
    Parse the MITRE ATT&CK Enterprise STIX bundle and extract a lookup
    table of techniques: {technique_id: {name, tactics, description}}.

    Skips revoked and deprecated techniques.
    """

    print(f"Reading STIX file:\n{STIX_PATH}\n")

    with open(STIX_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data["objects"]

    print(f"Total STIX objects: {len(objects)}")

    techniques = {}

    skipped_revoked = 0
    skipped_no_id = 0

    for obj in objects:

        if obj.get("type") != "attack-pattern":
            continue

        # ----------------------------------------------------------------
        # Skip revoked / deprecated techniques
        # ----------------------------------------------------------------

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped_revoked += 1
            continue

        # ----------------------------------------------------------------
        # Extract technique ID
        # ----------------------------------------------------------------

        technique_id = get_technique_id(obj)

        if technique_id is None:
            skipped_no_id += 1
            continue

        # ----------------------------------------------------------------
        # Build the technique entry
        # ----------------------------------------------------------------

        techniques[technique_id] = {
            "technique_id": technique_id,
            "technique_name": obj.get("name"),
            "tactics": get_tactics(obj),
            "description": obj.get("description"),
        }

    print(f"\nParsed {len(techniques)} active techniques.")
    print(f"Skipped {skipped_revoked} revoked/deprecated techniques.")
    print(f"Skipped {skipped_no_id} objects with no mitre-attack ID.")

    return techniques


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":

    techniques = parse_techniques()

    print(f"\nWriting output to:\n{OUTPUT_PATH}\n")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)

    print("Done.")

    # ------------------------------------------------------------------------
    # Show a couple of sample entries to sanity-check
    # ------------------------------------------------------------------------

    print("\nExample entries:")

    sample_keys = list(techniques.keys())[:2]

    for key in sample_keys:
        print(f"\n{key}:")
        print(json.dumps(techniques[key], indent=2)[:500])