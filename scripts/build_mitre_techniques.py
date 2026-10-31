#!/usr/bin/env python3
"""
Build assets/mitre_techniques.json (the MITRE Lookup dataset) from MITRE's
official ATT&CK STIX 2.1 release (github.com/mitre-attack/attack-stix-data).

    # latest Enterprise release
    python3 scripts/build_mitre_techniques.py

    # a specific release, or a local bundle (offline / air-gapped)
    python3 scripts/build_mitre_techniques.py --version 20.0
    python3 scripts/build_mitre_techniques.py --bundle enterprise-attack-20.0.json

Also writes assets/mitre_tactics.json: the tactics in ATT&CK matrix order
(id, name, shortname, description, techniques[{id,name}], attack_version).

Technique schema (one object per technique, in bundle order):
    id, name, description, tactic ("stealth, privilege-escalation"),
    platforms, permissions_required, detection, mitigations[],
    malware[{type,name,description}], tools[...], intrusion_sets[...],
    deprecated (bool), revoked_by (replacement technique ID, if any),
    attack_version

Deprecated/revoked techniques are kept (flagged) so a lookup of an old ID
still resolves; MITRE Lookup labels them. ATT&CK v18 removed the per-
technique detection and permissions fields: for those releases `detection`
lists the technique's Detection Strategies (name and ID) and
`permissions_required` is ["Unknown"], matching the earlier file format.
"""
import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "mitre_techniques.json"
TACTICS_OUT = ROOT / "assets" / "mitre_tactics.json"


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=300) as r:
        return json.load(r)


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_bundle(args):
    if args.bundle:
        return json.loads(Path(args.bundle).read_text()), args.version or "local"
    index = fetch_json(INDEX_URL)
    ent = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    versions = ent["versions"]
    v = next((x for x in versions if x["version"] == args.version), None) if args.version else versions[0]
    if v is None:
        sys.exit(f"ATT&CK version {args.version} not found; available: {', '.join(x['version'] for x in versions[:8])}")
    print(f"Downloading Enterprise ATT&CK {v['version']} ...", file=sys.stderr)
    return fetch_json(v["url"]), v["version"]


def build(bundle, version, legacy=False):
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    rel_uses = defaultdict(list)       # technique stix id -> [software/group objs]
    rel_mitigates = defaultdict(list)  # technique stix id -> [mitigation names]
    rel_detects = defaultdict(list)    # technique stix id -> [detection strategy objs]
    revoked_by = {}                    # technique stix id -> replacement technique stix id
    for r in objs:
        if r.get("type") == "relationship" and r.get("relationship_type") == "revoked-by":
            revoked_by[r["source_ref"]] = r["target_ref"]
    for r in objs:
        if r.get("type") != "relationship" or r.get("revoked") or r.get("x_mitre_deprecated"):
            continue
        src, tgt, kind = by_id.get(r.get("source_ref")), r.get("target_ref"), r.get("relationship_type")
        if src is None or src.get("revoked") or src.get("x_mitre_deprecated"):
            continue
        if kind == "uses" and src["type"] in ("malware", "tool", "intrusion-set"):
            rel_uses[tgt].append(src)
        elif kind == "mitigates" and src["type"] == "course-of-action":
            rel_mitigates[tgt].append(src["name"])
        elif kind == "detects" and src["type"] == "x-mitre-detection-strategy":
            rel_detects[tgt].append(src)

    def related(tid, stype):
        seen, out = set(), []
        for o in rel_uses.get(tid, []):
            if o["type"] == stype and o["id"] not in seen:
                seen.add(o["id"])
                out.append({"type": stype, "name": o["name"], "description": o.get("description", "")})
        return out

    techniques = []
    for t in objs:
        if t.get("type") != "attack-pattern":
            continue
        tid = attack_id(t)
        if not tid:
            continue
        phases = [p["phase_name"] for p in t.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        detection = t.get("x_mitre_detection", "")
        if not detection and rel_detects.get(t["id"]):
            detection = "Detection strategies: " + "; ".join(f"{d['name']} ({attack_id(d)})" for d in rel_detects[t["id"]])
        entry = {
            "id": tid,
            "name": t["name"],
            "description": t.get("description", ""),
            "tactic": ", ".join(phases),
            "platforms": t.get("x_mitre_platforms", []),
            "permissions_required": t.get("x_mitre_permissions_required") or ["Unknown"],
            "detection": detection,
            "mitigations": rel_mitigates.get(t["id"], []),
            "malware": related(t["id"], "malware"),
            "tools": related(t["id"], "tool"),
            "intrusion_sets": related(t["id"], "intrusion-set"),
        }
        if not legacy:
            entry["deprecated"] = bool(t.get("revoked") or t.get("x_mitre_deprecated"))
            # Follow revocation chains (e.g. T1089 -> T1562.001 -> T1685) to the live technique.
            target, hops = revoked_by.get(t["id"]), 0
            while target in revoked_by and hops < 10:
                target, hops = revoked_by[target], hops + 1
            entry["revoked_by"] = attack_id(by_id[target]) if target in by_id else None
            entry["attack_version"] = version
        techniques.append(entry)
    return techniques


def build_tactics(bundle, version, techniques):
    """Tactics in matrix order, each with its live techniques."""
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}
    matrix = next((o for o in objs if o.get("type") == "x-mitre-matrix" and not o.get("x_mitre_deprecated")), None)
    order = matrix.get("tactic_refs", []) if matrix else []
    tactics = [by_id[r] for r in order if r in by_id]
    tactics += [o for o in objs if o.get("type") == "x-mitre-tactic" and o["id"] not in order
                and not o.get("x_mitre_deprecated") and not o.get("revoked")]
    out = []
    for t in tactics:
        short = t["x_mitre_shortname"]
        members = [x for x in techniques if not x.get("deprecated")
                   and short in [p.strip() for p in x["tactic"].split(",")]]
        out.append({
            "id": attack_id(t),
            "name": t["name"],
            "shortname": short,
            "description": t.get("description", ""),
            "techniques": [{"id": x["id"], "name": x["name"]} for x in sorted(members, key=lambda x: x["id"])],
            "attack_version": version,
        })
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", help="ATT&CK Enterprise release, e.g. 20.0 (default: latest)")
    ap.add_argument("--bundle", help="Use a local enterprise-attack STIX bundle instead of downloading")
    ap.add_argument("--out", default=str(OUT), help="Output path (default: assets/mitre_techniques.json)")
    ap.add_argument("--tactics-out", default=str(TACTICS_OUT), help="Tactics output path (default: assets/mitre_tactics.json)")
    ap.add_argument("--legacy", action="store_true", help=argparse.SUPPRESS)  # pre-4.4 schema, for regression checks
    args = ap.parse_args()

    bundle, version = load_bundle(args)
    techniques = build(bundle, version, legacy=args.legacy)
    Path(args.out).write_text(json.dumps(techniques, indent=2, ensure_ascii=False) + "\n")
    active = sum(1 for t in techniques if not t.get("deprecated"))
    print(f"Wrote {len(techniques)} techniques ({active} active) from ATT&CK {version} -> {args.out}", file=sys.stderr)
    if not args.legacy:
        tactics = build_tactics(bundle, version, techniques)
        Path(args.tactics_out).write_text(json.dumps(tactics, indent=2, ensure_ascii=False) + "\n")
        print(f"Wrote {len(tactics)} tactics -> {args.tactics_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
