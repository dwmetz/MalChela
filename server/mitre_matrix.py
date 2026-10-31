"""
MITRE ATT&CK matrix for Analyze runs.

Builds a technique-level summary of everything an Analyze run found — mStrings
rule hits, Unpack's packing/embedded-payload techniques, and tool flags mapped
through assets/flag_attack_map.yaml — and renders it as:

  * matrix JSON  (saved next to the summary as mitre_matrix_<ts>.json; drives
                  the PWA's interactive matrix panel)
  * an ATT&CK Navigator layer (navigator_layer_<ts>.json; opens in
                  https://mitre-attack.github.io/attack-navigator/)

The source of truth is the Analyze summary markdown itself (malchela_summary_*.md):
it already embeds every tool's report for every file, so the same parser works
for a run that just finished and for any case saved before this feature existed.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"


# ── Reference data ──────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def techniques() -> dict:
    """ID -> {name, full_name, tactics[shortname], deprecated, revoked_by}."""
    data = json.loads((ASSETS / "mitre_techniques.json").read_text())
    by_id = {t["id"]: t for t in data}
    out = {}
    for t in data:
        tid = t["id"]
        parent = by_id.get(tid.split(".")[0]) if "." in tid else None
        out[tid] = {
            "name": t["name"],
            "full_name": f"{parent['name']}: {t['name']}" if parent else t["name"],
            "tactics": [p.strip() for p in t.get("tactic", "").split(",") if p.strip()],
            "deprecated": bool(t.get("deprecated")),
            "revoked_by": t.get("revoked_by"),
        }
    return out


@lru_cache(maxsize=1)
def tactics() -> list:
    """Tactics in matrix order: [{id, name, shortname, techniques:[{id,name}]}]."""
    return json.loads((ASSETS / "mitre_tactics.json").read_text())


@lru_cache(maxsize=1)
def attack_version() -> str:
    for t in tactics():
        if t.get("attack_version"):
            return str(t["attack_version"])
    return "?"


@lru_cache(maxsize=1)
def _tactic_name_to_short() -> dict:
    m = {t["name"].lower(): t["shortname"] for t in tactics()}
    # Retired in v20: rules or old reports may still say Defense Evasion.
    m["defense evasion"] = "stealth"
    return m


@lru_cache(maxsize=1)
def flag_map() -> list:
    path = ASSETS / "flag_attack_map.yaml"
    if not path.exists():
        return []
    entries = yaml.safe_load(path.read_text()) or []
    out = []
    for e in entries:
        try:
            out.append({
                "tool": e["tool"],
                "re": re.compile(e["match"], re.IGNORECASE),
                "technique": e["technique"],
                "confidence": e.get("confidence", "low"),
            })
        except (KeyError, re.error):
            continue
    return out


def resolve(tid: str) -> Optional[str]:
    """Follow ATT&CK revocations so an old ID in an old report still lands
    on a live technique. None if the ID isn't in the bundled dataset."""
    db = techniques()
    hops = 0
    while tid in db and db[tid]["deprecated"] and db[tid]["revoked_by"] and hops < 10:
        tid, hops = db[tid]["revoked_by"], hops + 1
    return tid if tid in db else None


# ── Parsing the Analyze summary ─────────────────────────────────────────────

_ANCHOR = re.compile(r'^<a id="(file-\d+)"></a>\s*$')
_FILE_HEADING = re.compile(r"^## (.+?)\s*$")
_SHA = re.compile(r"^- \*\*SHA256:\*\*\s*`([0-9a-fA-F]{64})`")
_TOOL_HEADING = re.compile(r"^### [✓✕✗]\s+.*?\(`([A-Za-z0-9_\-]+)`\)\s*$")
_CELL_SPLIT = re.compile(r"(?<!\\)\|")
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _split_sections(md: str) -> list:
    """[(file_name, anchor, sha256, {tool: markdown})] from a summary."""
    files = []
    cur = None
    tool = None
    pending_anchor = None
    for line in md.split("\n"):
        m = _ANCHOR.match(line)
        if m:
            pending_anchor = m.group(1)
            continue
        if pending_anchor:
            h = _FILE_HEADING.match(line)
            if h:
                cur = {"file": h.group(1), "anchor": pending_anchor, "sha256": "", "tools": {}}
                files.append(cur)
                tool = None
                pending_anchor = None
                continue
            if line.strip():
                pending_anchor = None
        if cur is None:
            continue
        s = _SHA.match(line)
        if s and not cur["sha256"]:
            cur["sha256"] = s.group(1).lower()
            continue
        t = _TOOL_HEADING.match(line)
        if t:
            tool = t.group(1)
            cur["tools"].setdefault(tool, [])
            continue
        if tool:
            cur["tools"][tool].append(line)
    for f in files:
        f["tools"] = {k: "\n".join(v) for k, v in f["tools"].items()}
    return files


def _table_rows(md: str, header_first: str) -> list:
    """Rows (as cell lists) of every markdown table whose header starts with
    `header_first`."""
    rows, in_table = [], False
    for line in md.split("\n"):
        s = line.strip()
        if not s.startswith("|"):
            in_table = False
            continue
        cells = [c.strip() for c in _CELL_SPLIT.split(s.strip("|"))]
        if not in_table:
            if cells and cells[0].lower() == header_first.lower():
                in_table = True
                rows.append(("__header__", cells))
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        rows.append(("row", cells))
    return rows


_MORE = re.compile(r"\s*\(\+(\d+) more\)\s*$")
_LAYERS = re.compile(r"\s*\[\u26a0[^\]]*\]\s*$")


def _split_matched(cell: str, rule: str) -> tuple:
    """mStrings' "Matched Strings" cell -> (strings, more, note). The cell is
    up to 8 strings joined with ", " (each cut to 50 chars), then "(+N more)"
    and/or a "[⚠ found after N layers …]" note. The encoded-string-table row
    holds a sentence, not strings, so it comes back as the note."""
    cell = (cell or "").replace("\\|", "|").strip()
    if not cell:
        return [], 0, ""
    if rule.lower().startswith("encoded string table"):
        return [], 0, cell
    note = ""
    m = _LAYERS.search(cell)
    if m:
        note, cell = m.group(0).strip().strip("[]"), cell[:m.start()]
    more = 0
    m = _MORE.search(cell)
    if m:
        more, cell = int(m.group(1)), cell[:m.start()]
    strings = [x for x in (y.strip() for y in cell.split(", ")) if x]
    return strings, more, note


def _mstrings_hits(md: str) -> list:
    hits, header = [], None
    for kind, cells in _table_rows(md, "Count"):
        if kind == "__header__":
            header = [c.lower() for c in cells]
            continue
        if not header or "id" not in header:
            continue
        get = lambda col: cells[header.index(col)] if col in header and header.index(col) < len(cells) else ""
        try:
            count = int(get("count") or 0)
        except ValueError:
            continue
        rule = get("rule")
        strings, more, note = _split_matched(get("matched strings"), rule)
        rule_tactics = [_tactic_name_to_short().get(x.strip().lower()) for x in get("tactic").split(",")]
        rule_tactics = [x for x in rule_tactics if x]
        for tid in _TID.findall(get("id")):
            hits.append({"technique": tid, "tool": "mstrings", "source": rule,
                         "count": count, "confidence": "high", "tactics": rule_tactics,
                         "strings": strings, "more": more, "note": note})
    return hits


def _unpack_hits(md: str) -> list:
    hits = []
    for kind, cells in _table_rows(md, "ID"):
        if kind == "__header__" or not cells:
            continue
        for tid in _TID.findall(cells[0]):
            name = cells[1] if len(cells) > 1 else ""
            hits.append({"technique": tid, "tool": "unpack", "source": name or "Unpack",
                         "count": 1, "confidence": "high", "tactics": []})
    return hits


def _flag_hits(tool: str, md: str) -> list:
    hits, seen = [], set()
    entries = [e for e in flag_map() if e["tool"] == tool]
    if not entries:
        return hits
    for line in md.split("\n"):
        text = re.sub(r"^\s*[-*]\s*(\*\*\[!\]\*\*\s*)?", "", line).strip()
        if not text:
            continue
        for e in entries:
            if e["re"].search(text) and (e["technique"], text) not in seen:
                # A flag matched in a table row ("| Packed | Possibly (PyInstaller) |")
                # reads better as "Packed: Possibly (PyInstaller)".
                if text.startswith("|"):
                    cells = [c.strip() for c in text.strip("|").split("|") if c.strip()]
                    text = ": ".join(cells) if cells else text
                seen.add((e["technique"], text))
                hits.append({"technique": e["technique"], "tool": tool, "source": text,
                             "count": 1, "confidence": e["confidence"], "tactics": []})
    return hits


def tool_hits(tool: str, md: str) -> list:
    """Technique hits in one tool's report (raw IDs, not yet resolved)."""
    if tool == "mstrings":
        return _mstrings_hits(md)
    if tool == "unpack":
        return _unpack_hits(md)
    return _flag_hits(tool, md)


def extract_hits(summary_md: str, run_label: str = "") -> list:
    """Every ATT&CK technique hit in an Analyze summary, one dict per
    (file, tool, source, technique)."""
    out = []
    for f in _split_sections(summary_md):
        for tool, md in f["tools"].items():
            for h in tool_hits(tool, md):
                tid = resolve(h["technique"])
                if not tid:
                    continue
                h.update({"technique": tid, "file": f["file"], "sha256": f["sha256"],
                          "anchor": f["anchor"], "run": run_label})
                out.append(h)
    return out


# ── Matrix ──────────────────────────────────────────────────────────────────

def build_matrix(hits: list, target: str = "", runs: Optional[list] = None) -> dict:
    """Group hits by technique. Each technique records which tactics it's
    plotted under (the rule's chosen tactics where mStrings gave them, else
    the technique's ATT&CK tactics), the distinct files that hit it, and a
    score (distinct files; low-confidence-only techniques score 0.5/file)."""
    db = techniques()
    techs: dict = {}
    for h in hits:
        tid = h["technique"]
        t = techs.setdefault(tid, {
            "id": tid,
            "name": db[tid]["full_name"],
            "tactics": [],
            "files": [],
            "hits": [],
            "confidence": "low",
        })
        tacs = h.get("tactics") or db[tid]["tactics"]
        # Keep only tactics the technique actually belongs to in this ATT&CK
        # version, so a cell never lands in a column the matrix doesn't have
        # for it; fall back to the technique's own set.
        valid = [x for x in tacs if x in db[tid]["tactics"]] or db[tid]["tactics"]
        for tac in valid:
            if tac not in t["tactics"]:
                t["tactics"].append(tac)
        key = h.get("sha256") or h.get("file")
        if key not in [x["key"] for x in t["files"]]:
            t["files"].append({"key": key, "file": h.get("file"), "sha256": h.get("sha256")})
        hit = {k: h.get(k) for k in ("file", "sha256", "anchor", "tool", "source", "count", "confidence", "run")}
        hit.update({k: h[k] for k in ("strings", "more", "note", "report") if h.get(k)})  # mStrings detail / standalone report path
        t["hits"].append(hit)
        if h["confidence"] == "high":
            t["confidence"] = "high"
    for t in techs.values():
        n = len(t["files"])
        t["score"] = n if t["confidence"] == "high" else n * 0.5
        t["tools"] = sorted({x["tool"] for x in t["hits"]})
    tac_order = [x["shortname"] for x in tactics()]
    return {
        "schema": "malchela-mitre-matrix/1",
        "attack_version": attack_version(),
        "generated": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "runs": runs or [],
        "tactics": [{"id": x["id"], "name": x["name"], "shortname": x["shortname"]} for x in tactics()],
        "techniques": sorted(techs.values(), key=lambda t: (min((tac_order.index(x) for x in t["tactics"] if x in tac_order), default=99), t["id"])),
        "file_count": len({h.get("sha256") or h.get("file") for h in hits}),
    }


def merge(matrices: list, target: str = "") -> dict:
    """Combine several saved matrices (e.g. every Analyze run in a case)
    into one. Rebuilt from the hit lists, so scores are per distinct file
    across all runs."""
    hits = []
    runs = []
    for m in matrices:
        runs += m.get("runs") or []
        for t in m.get("techniques", []):
            tid = resolve(t["id"])
            if not tid:
                continue
            for h in t.get("hits", []):
                hits.append({**h, "technique": tid, "tactics": [x for x in t.get("tactics", [])]})
    return build_matrix(hits, target=target, runs=runs)


def navigator_layer(matrix: dict, name: str = "MalChela Analyze") -> dict:
    """ATT&CK Navigator layer (format 4.5) for the matrix."""
    db = techniques()
    entries = []
    parents_with_subs = set()
    max_score = 0
    for t in matrix["techniques"]:
        files = sorted({x["file"] for x in t["hits"] if x.get("file")})
        sources = sorted({f'{x["tool"]}: {x["source"]}' for x in t["hits"]})
        comment = "; ".join(sources)[:1500]
        meta = [{"name": "files", "value": ", ".join(files)[:500]},
                {"name": "tools", "value": ", ".join(t["tools"])},
                {"name": "confidence", "value": t["confidence"]}]
        max_score = max(max_score, t["score"])
        for tac in t["tactics"]:
            entries.append({
                "techniqueID": t["id"],
                "tactic": tac,
                "score": t["score"],
                "color": "",
                "comment": comment,
                "enabled": True,
                "metadata": meta,
                "showSubtechniques": False,
            })
            if "." in t["id"]:
                parents_with_subs.add((t["id"].split(".")[0], tac))
    # Expand parents that have hit sub-techniques so they're visible.
    for parent, tac in parents_with_subs:
        existing = [e for e in entries if e["techniqueID"] == parent and e["tactic"] == tac]
        if existing:
            existing[0]["showSubtechniques"] = True
        elif parent in db and tac in db[parent]["tactics"]:
            entries.append({"techniqueID": parent, "tactic": tac, "enabled": True,
                            "showSubtechniques": True, "metadata": [], "comment": "", "color": ""})
    return {
        "name": name,
        "versions": {"attack": attack_version().split(".")[0], "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": f"Generated by MalChela Analyze from {matrix.get('target') or 'an Analyze run'} "
                       f"({matrix.get('file_count', 0)} file(s) with ATT&CK findings). Score = distinct files; "
                       f"low-confidence (flag-only) techniques score 0.5 per file.",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max(1, max_score)},
        "legendItems": [{"label": "Hit (score = files)", "color": "#ff6666"}],
        "metadata": [{"name": "generator", "value": "MalChela"}],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


# ── Files ───────────────────────────────────────────────────────────────────

def save_for_summary(summary_path: Path, summary_md: str, target: str) -> dict:
    """Write mitre_matrix_<ts>.json and navigator_layer_<ts>.json next to a
    summary (same timestamp suffix). Returns the matrix plus file paths."""
    ts = summary_path.stem.replace("malchela_summary_", "")
    matrix = build_matrix(extract_hits(summary_md, run_label=summary_path.name), target=target,
                          runs=[summary_path.name])
    mpath = summary_path.with_name(f"mitre_matrix_{ts}.json")
    lpath = summary_path.with_name(f"navigator_layer_{ts}.json")
    mpath.write_text(json.dumps(matrix, indent=2, ensure_ascii=False))
    lpath.write_text(json.dumps(navigator_layer(matrix, name=f"MalChela — {Path(target).name or target}"), indent=2))
    return {"matrix": matrix, "matrix_path": str(mpath), "layer_path": str(lpath)}


# ── Case-wide matrix ────────────────────────────────────────────────────────

def report_tools() -> set:
    """Tools whose standalone reports can carry ATT&CK techniques."""
    return {"mstrings", "unpack"} | {e["tool"] for e in flag_map()}


_REPORT_SHA = re.compile(r"\*\*SHA-?256:?\*\*:?\s*`([0-9a-fA-F]{64})`")
_REPORT_PATH = re.compile(r"^\*\*(?:File|Binary|Path|Input):?\*\*:?\s*`([^`]+)`", re.MULTILINE)


def _sha256_file(path: Path, cap: int = 1 << 30) -> str:
    try:
        if not path.is_file() or path.stat().st_size > cap:
            return ""
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _case_reports(case_dir: Path) -> list:
    """(tool, report path, target) for every standalone tool report in the case:
    case.yaml's file list plus any report found in a tool folder (so reports
    copied in by hand count too). Analyze summaries are handled separately."""
    tools = report_tools()
    seen, out = set(), []
    manifest = case_dir / "case.yaml"
    entries = []
    try:
        # Null-only loader: case.yaml values are strings (see common_config).
        data = yaml.load(manifest.read_text(), Loader=_StrLoader) if manifest.exists() else {}
        entries = (data or {}).get("files") or []
    except (OSError, yaml.YAMLError):
        entries = []
    for e in entries:
        if not isinstance(e, dict) or e.get("tool") not in tools or not e.get("path"):
            continue
        p = (case_dir / str(e["path"])).resolve()
        if case_dir.resolve() not in p.parents or p in seen:
            continue
        seen.add(p)
        out.append((e["tool"], p, str(e.get("target") or "")))
    for tool in sorted(tools):
        tdir = case_dir / tool
        if not tdir.is_dir():
            continue
        for p in sorted(tdir.glob("*")):
            if p.suffix.lower() not in (".md", ".txt") or not p.is_file():
                continue
            p = p.resolve()
            if p not in seen:
                seen.add(p)
                out.append((tool, p, ""))
    return out


class _StrLoader(yaml.SafeLoader):
    """SafeLoader that keeps every scalar a string except null, so dates,
    hashes, and numbers in case.yaml aren't reinterpreted."""


_StrLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag == "tag:yaml.org,2002:null"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _report_file_identity(md: str, target: str, sha_cache: dict) -> tuple:
    """(display name, sha256) for the file a standalone report is about: the
    SHA-256 the report prints, else a hash of the file it names. case.yaml's
    target isn't always a usable path (codesign_check records a bare file
    name, tiquery a hash), so the report's own File/Binary line is tried too."""
    m = _REPORT_SHA.search(md)
    sha = m.group(1).lower() if m else ""
    pm = _REPORT_PATH.search(md)
    candidates = [c for c in (target, pm.group(1) if pm else "") if c]
    path = next((c for c in candidates if Path(c).is_file()), candidates[0] if candidates else "")
    if not sha and path and Path(path).is_file():
        if path not in sha_cache:
            sha_cache[path] = _sha256_file(Path(path))
        sha = sha_cache[path]
    name = Path(path).name if path else (sha[:16] if sha else "?")
    return name, sha


def for_case(case_dir: Path, case_name: str) -> dict:
    """Combined matrix for a case: every Analyze run (parsed from its summary,
    falling back to the saved matrix JSON) plus every standalone report from a
    tool that emits ATT&CK techniques. Analyze also saves its tools' reports
    into the case, so a hit already counted from a summary is not counted
    again from the matching standalone report."""
    hits, runs = [], []
    adir = case_dir / "analyze"
    if adir.is_dir():
        for summary in sorted(adir.glob("malchela_summary_*.md")):
            ts = summary.stem.replace("malchela_summary_", "")
            try:
                hits += extract_hits(summary.read_text(), run_label=summary.name)
                runs.append(summary.name)
                continue
            except OSError:
                pass
            mj = adir / f"mitre_matrix_{ts}.json"
            try:
                m = json.loads(mj.read_text())
            except (OSError, ValueError):
                continue
            runs += m.get("runs") or [summary.name]
            for t in m.get("techniques", []):
                tid = resolve(t["id"])
                if tid:
                    hits += [{**h, "technique": tid, "tactics": list(t.get("tactics", []))} for h in t.get("hits", [])]

    def key(h):
        return (h["technique"], h.get("tool"), h.get("source"), h.get("sha256") or h.get("file"))

    seen = {key(h) for h in hits}
    sha_cache: dict = {}
    reports = 0
    for tool, path, target in _case_reports(case_dir):
        try:
            md = path.read_text(errors="replace")
        except OSError:
            continue
        found = tool_hits(tool, md)
        if not found:
            continue
        name, sha = _report_file_identity(md, target, sha_cache)
        added = False
        for h in found:
            tid = resolve(h["technique"])
            if not tid:
                continue
            h.update({"technique": tid, "file": name, "sha256": sha, "anchor": "",
                      "run": f"{tool} report {path.name}", "report": str(path.relative_to(case_dir.resolve()))})
            if key(h) in seen:
                continue
            seen.add(key(h))
            hits.append(h)
            added = True
        reports += added
    merged = build_matrix(hits, target=f"case {case_name}", runs=runs)
    merged["case"] = case_name
    merged["reports"] = reports
    return merged
