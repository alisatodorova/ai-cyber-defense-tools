"""Download MITRE ATT&CK Enterprise data and extract a trimmed technique index.

The full STIX bundle is ~50MB; we only need technique id/name/description/tactics,
so this pulls it once and writes a much smaller ./attack/techniques.json that
server.py reads at runtime.

Usage:
    python scripts/download_attack_data.py
"""

import json
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEST_DIR = Path(__file__).resolve().parent.parent / "attack"
DEST_FILE = DEST_DIR / "techniques.json"


def external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main() -> None:
    print(f"Downloading ATT&CK STIX bundle from {SOURCE_URL} ...")
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "mcp-hayabusa-installer"})
    with urllib.request.urlopen(req) as resp:
        bundle = json.load(resp)

    objects = bundle.get("objects", [])
    print(f"Loaded {len(objects):,} STIX objects; extracting attack-pattern (technique) entries ...")

    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = external_id(obj)
        if not tid:
            continue

        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques[tid] = {
            "technique_id": tid,
            "name": obj.get("name"),
            "description": obj.get("description"),
            "tactics": tactics,
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "revoked": obj.get("revoked", False),
            "deprecated": obj.get("x_mitre_deprecated", False),
        }

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    with DEST_FILE.open("w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)

    print(f"Wrote {len(techniques):,} techniques to {DEST_FILE}")


if __name__ == "__main__":
    main()
