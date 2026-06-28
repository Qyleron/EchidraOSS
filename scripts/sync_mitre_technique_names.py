"""Download the full MITRE ATT&CK Enterprise technique catalog.

Writes a flat {technique_id: name} JSON file so the Intelligence page can
display the correct name for *any* MITRE id a rule tags -- not just the
handful with a curated entry in classifier/rules/issue_playbook.yaml. This
does not change which techniques Echidra can detect; it only fixes display
names for ids your rules already tag (or might tag in the future).

Usage:
    python scripts/sync_mitre_technique_names.py
    python scripts/sync_mitre_technique_names.py --input local-bundle.json
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

STIX_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUTPUT_PATH = (
    Path(__file__).resolve().parents[1] / "classifier" / "rules" / "mitre_technique_names.json"
)


def fetch_bundle(url: str) -> dict:
    with urllib.request.urlopen(url) as response:
        return json.load(response)


def load_local_bundle(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def extract_technique_names(bundle: dict) -> dict[str, str]:
    names: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                names[ref["external_id"]] = obj["name"]
                break
    return names


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="use a local enterprise-attack.json instead of downloading one",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="where to write the technique id -> name JSON",
    )
    args = parser.parse_args()

    bundle = load_local_bundle(args.input) if args.input else fetch_bundle(STIX_BUNDLE_URL)
    names = extract_technique_names(bundle)

    args.output.write_text(json.dumps(dict(sorted(names.items())), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(names)} technique names to {args.output}")


if __name__ == "__main__":
    main()
