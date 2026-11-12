"""
prepare_mitre.py
Converts the official MITRE ATT&CK Enterprise STIX bundle (enterprise-attack.json)
into three CSV files that PostgreSQL can import:

    mitre_tactics.csv            tactic_id, name, shortname
    mitre_techniques.csv         technique_id, name, is_subtechnique, parent_technique_id
    mitre_technique_tactics.csv  technique_id, tactic_id   (many-to-many link)

Revoked and deprecated objects are excluded.

Source file:
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

Usage:
  python prepare_mitre.py path/to/enterprise-attack.json path/to/output_folder
"""
import csv
import json
import sys
from pathlib import Path


def mitre_id(obj):
    """Return the ATT&CK ID (e.g. T1059.001 or TA0002) of a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref["external_id"]
    return None


def is_active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def main(json_path, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    bundle = json.loads(Path(json_path).read_text(encoding="utf-8"))
    objects = bundle["objects"]

    version = next((o.get("x_mitre_version") for o in objects
                    if o["type"] == "x-mitre-collection"), "unknown")

    # ---- tactics ----
    tactics = [o for o in objects if o["type"] == "x-mitre-tactic" and is_active(o)]
    shortname_to_id = {}
    with open(out / "mitre_tactics.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tactic_id", "name", "shortname"])
        for t in sorted(tactics, key=mitre_id):
            shortname_to_id[t["x_mitre_shortname"]] = mitre_id(t)
            w.writerow([mitre_id(t), t["name"], t["x_mitre_shortname"]])

    # ---- techniques and sub-techniques ----
    techniques = [o for o in objects if o["type"] == "attack-pattern" and is_active(o)]
    links = 0
    with open(out / "mitre_techniques.csv", "w", newline="", encoding="utf-8") as ft, \
         open(out / "mitre_technique_tactics.csv", "w", newline="", encoding="utf-8") as fl:
        wt, wl = csv.writer(ft), csv.writer(fl)
        wt.writerow(["technique_id", "name", "is_subtechnique", "parent_technique_id"])
        wl.writerow(["technique_id", "tactic_id"])
        # parents first, so the file reads naturally
        for o in sorted(techniques, key=lambda x: (mitre_id(x).count("."), mitre_id(x))):
            tid = mitre_id(o)
            is_sub = bool(o.get("x_mitre_is_subtechnique", False))
            parent = tid.split(".")[0] if is_sub else ""
            wt.writerow([tid, o["name"], "true" if is_sub else "false", parent])
            for phase in o.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    wl.writerow([tid, shortname_to_id[phase["phase_name"]]])
                    links += 1

    subs = sum(1 for o in techniques if o.get("x_mitre_is_subtechnique"))
    print(f"ATT&CK Enterprise version {version}")
    print(f"tactics: {len(tactics)}  techniques: {len(techniques) - subs}  "
          f"sub-techniques: {subs}  technique-tactic links: {links}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python prepare_mitre.py enterprise-attack.json output_folder")
    main(sys.argv[1], sys.argv[2])
