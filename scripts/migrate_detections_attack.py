#!/usr/bin/env python3
"""
Migrate detections.yaml MITRE mappings to a new ATT&CK release.

Run after regenerating assets/mitre_techniques.json with
build_mitre_techniques.py, passing the PREVIOUS dataset so the script can
tell a rule that listed a technique's full tactic set (follow ATT&CK) from
one whose author picked specific tactics (preserve the choice):

    git show HEAD:assets/mitre_techniques.json > /tmp/mitre_old.json
    python3 scripts/migrate_detections_attack.py --old /tmp/mitre_old.json [--dry-run]

Per mitre entry:
  * deprecated/revoked technique -> its ATT&CK replacement (revoked-by chain)
  * technique_name               -> current "Parent: Sub-technique" name
  * tactics, full set in old     -> the technique's full tactic set now
  * tactics, author-chosen       -> retired tactics (Defense Evasion) mapped to
                                    the successors the technique now has; all
                                    other author choices kept
Tags (attack.tNNNN) follow any ID change. Edits are made line by line so the
file's formatting, ordering, and comments are untouched. A change log is
printed (and written with --log).
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS = ROOT / "detections.yaml"
NEW = ROOT / "assets" / "mitre_techniques.json"

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
    "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
    "stealth": "Stealth", "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access", "discovery": "Discovery",
    "lateral-movement": "Lateral Movement", "collection": "Collection",
    "command-and-control": "Command and Control", "exfiltration": "Exfiltration",
    "impact": "Impact",
}
# Retired tactic name -> the tactics that replaced it.
RETIRED = {"Defense Evasion": ["Stealth", "Defense Impairment"]}
# Rule IDs that never existed in ATT&CK, with the intended technique.
MANUAL_FIX = {"T1543.013": "T1053.005"}
# Reviewed per-rule corrections where a valid ID was the wrong technique.
RULE_OVERRIDES = {
    # Matches EventConsumer / ActiveScriptEventConsumer: WMI event subscription
    # persistence, not T1543.004 (macOS Launch Daemon).
    ("WMIPersistenceEventConsumers", "T1543.004"): "T1546.003",
}


def load(path):
    data = json.loads(Path(path).read_text())
    return {t["id"]: t for t in data}


def phases(t):
    return [TACTIC_NAMES.get(p.strip(), p.strip()) for p in t["tactic"].split(",") if p.strip()]


def full_name(tid, db):
    t = db[tid]
    if "." in tid and tid.split(".")[0] in db:
        return f"{db[tid.split('.')[0]]['name']}: {t['name']}"
    return t["name"]


def resolve(tid, db):
    """Follow revocations/known-bad IDs to a live technique. Returns (id, why)."""
    if tid not in db and tid in MANUAL_FIX:
        return MANUAL_FIX[tid], "not an ATT&CK technique ID"
    t, why, hops = db.get(tid), None, 0
    while t and t.get("deprecated") and t.get("revoked_by") and hops < 10:
        why = why or "deprecated in ATT&CK"
        tid, t, hops = t["revoked_by"], db.get(t["revoked_by"]), hops + 1
    return tid, why


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", required=True, help="Previous mitre_techniques.json")
    ap.add_argument("--new", default=str(NEW))
    ap.add_argument("--detections", default=str(DETECTIONS))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log", help="Write the change log (Markdown) here")
    args = ap.parse_args()

    old, new = load(args.old), load(args.new)
    version = next((t.get("attack_version") for t in new.values() if t.get("attack_version")), "?")
    lines = Path(args.detections).read_text().split("\n")

    rule = None
    id_map = {}  # (rule, old_id) -> new_id, for tags
    log = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m_rule = re.match(r"^([A-Za-z0-9_]+):\s*$", line)
        if m_rule:
            rule = m_rule.group(1)
        m_id = re.match(r'^(\s*- technique_id:\s*)"([^"]+)"\s*$', line)
        if m_id and i + 2 < len(lines):
            m_name = re.match(r'^(\s*technique_name:\s*)"(.*)"\s*$', lines[i + 1])
            m_tac = re.match(r'^(\s*tactics:\s*)\[(.*)\]\s*$', lines[i + 2])
            if not (m_name and m_tac):
                sys.exit(f"{rule}: unexpected mitre block layout at line {i + 1}")
            old_id = m_id.group(2)
            old_name = m_name.group(2)
            old_tac = [x.strip().strip('"').strip("'") for x in m_tac.group(2).split(",") if x.strip()]

            if (rule, old_id) in RULE_OVERRIDES:
                new_id, why = RULE_OVERRIDES[(rule, old_id)], "wrong technique for this rule"
            else:
                new_id, why = resolve(old_id, new)
            if new_id not in new:
                log.append((rule, old_id, f"UNRESOLVED — {old_id} not in ATT&CK {version}; left unchanged"))
                i += 3
                continue
            cur = phases(new[new_id])
            prev = phases(old[old_id]) if old_id in old else None
            if why or prev is None or set(old_tac) == set(prev):
                new_tac = cur  # follow ATT&CK
            else:
                new_tac = []
                for tac in old_tac:
                    if tac in RETIRED:
                        new_tac += [s for s in RETIRED[tac] if s in cur]
                    elif tac in cur or tac in TACTIC_NAMES.values():
                        new_tac.append(tac)
                new_tac = list(dict.fromkeys(new_tac)) or cur
            if set(new_tac) == set(old_tac):
                new_tac = old_tac  # same tactics: keep the author's order
            new_name = full_name(new_id, new)

            changes = []
            if new_id != old_id:
                changes.append(f"ID {old_id} → {new_id} ({why})")
                id_map[(rule, old_id.lower())] = new_id.lower()
            if new_name != old_name:
                changes.append(f'name "{old_name}" → "{new_name}"')
            if new_tac != old_tac:
                changes.append(f"tactics {old_tac} → {new_tac}")
            if changes:
                log.append((rule, old_id, "; ".join(changes)))
            lines[i] = f'{m_id.group(1)}"{new_id}"'
            lines[i + 1] = f'{m_name.group(1)}"{new_name}"'
            lines[i + 2] = m_tac.group(1) + "[" + ", ".join(f'"{t}"' for t in new_tac) + "]"
            i += 3
            continue
        i += 1

    # Tags follow ID changes (per rule, case-insensitive).
    rule = None
    for i, line in enumerate(lines):
        m_rule = re.match(r"^([A-Za-z0-9_]+):\s*$", line)
        if m_rule:
            rule = m_rule.group(1)
        m_tag = re.match(r"^(\s*- attack\.)(t\d{4}(?:\.\d{3})?)\s*$", line, re.IGNORECASE)
        if m_tag and (rule, m_tag.group(2).lower()) in id_map:
            lines[i] = m_tag.group(1) + id_map[(rule, m_tag.group(2).lower())]

    md = [f"# detections.yaml → ATT&CK v{version}", "", f"{len(log)} mapping change(s).", "",
          "| Rule | Was | Change |", "|---|---|---|"]
    md += [f"| `{r}` | {o} | {c} |" for r, o, c in log]
    report = "\n".join(md) + "\n"
    print(report)
    if args.log:
        Path(args.log).write_text(report)
    if not args.dry_run:
        Path(args.detections).write_text("\n".join(lines))
        print(f"Updated {args.detections}", file=sys.stderr)


if __name__ == "__main__":
    main()
