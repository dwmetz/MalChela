#!/usr/bin/env python3
"""
malchela_server.py
MalChela Remote API Server
Exposes MalChela tools, file browser, and case management to the MalChela PWA.

Configuration is loaded from server_config.yaml in the same directory as this
script. If no config file is found, sensible defaults are used. Any value can
also be overridden with an environment variable (see CONFIG DEFAULTS below).

Supported platforms: Kali Linux, REMnux/Ubuntu, macOS
"""

import os
import re
import sys
import json
import zipfile
import subprocess
import shutil
import traceback
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import yaml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _safe_error(e: Exception) -> str:
    """Log exception server-side; return safe message string for HTTP clients."""
    logger.error("Server error:\n%s", traceback.format_exc())
    return "Internal server error"

# ── Config Loader ─────────────────────────────────────────────────────────────

# Locate server_config.yaml next to this script
_SCRIPT_DIR = Path(__file__).parent.resolve()
_CONFIG_FILE = _SCRIPT_DIR / "server_config.yaml"

def _load_config() -> dict:
    """
    Load configuration from server_config.yaml if present.
    Falls back to environment variables, then built-in defaults.
    Priority: config file > environment variables > defaults.
    """
    # Built-in defaults — self-locate relative to this script's parent (the repo root)
    defaults = {
        "malchela_root": str(_SCRIPT_DIR.parent),
        "browser_root":  str(Path.home()),
        "port":          8675,
    }

    cfg = dict(defaults)

    # Layer in environment variables
    if os.environ.get("MALCHELA_ROOT"):
        cfg["malchela_root"] = os.environ["MALCHELA_ROOT"]
    if os.environ.get("MALCHELA_BROWSER_ROOT"):
        cfg["browser_root"] = os.environ["MALCHELA_BROWSER_ROOT"]
    if os.environ.get("MALCHELA_PORT"):
        cfg["port"] = int(os.environ["MALCHELA_PORT"])

    # Layer in config file (highest priority)
    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE) as f:
                file_cfg = yaml.safe_load(f) or {}
            # "auto" means self-locate relative to this script
            if file_cfg.get("malchela_root") in (None, "auto", ""):
                file_cfg.pop("malchela_root", None)
            cfg.update({k: v for k, v in file_cfg.items() if v is not None})
            print(f"[MalChela Server] Loaded config from {_CONFIG_FILE}")
        except Exception as e:
            print(f"[MalChela Server] Warning: Could not parse server_config.yaml: {e}")
            print(f"[MalChela Server] Falling back to defaults.")
    else:
        print(f"[MalChela Server] No server_config.yaml found — using defaults.")
        print(f"[MalChela Server] To customize, copy server_config.yaml to {_CONFIG_FILE}")

    return cfg

_CFG = _load_config()

# ── Configuration ─────────────────────────────────────────────────────────────

MALCHELA_ROOT   = Path(_CFG["malchela_root"]).resolve()
BINARY_DIR      = MALCHELA_ROOT / "target" / "release"
API_DIR         = MALCHELA_ROOT / "api"
YARA_DIR        = MALCHELA_ROOT / "yara_rules"
OUTPUT_DIR      = MALCHELA_ROOT / "saved_output"
CASES_DIR       = OUTPUT_DIR / "cases"
UPLOADS_DIR     = MALCHELA_ROOT / "uploads"
BROWSER_ROOT    = Path(_CFG["browser_root"]).resolve()
PORT            = int(_CFG["port"])

# Extra tool search paths from config — injected into PATH so shutil.which finds them
EXTRA_TOOL_PATHS: List[str] = _CFG.get("tool_paths", [])
if EXTRA_TOOL_PATHS:
    extra = os.pathsep.join(str(p) for p in EXTRA_TOOL_PATHS)
    os.environ["PATH"] = extra + os.pathsep + os.environ.get("PATH", "")


def find_tool(binary: str) -> Optional[str]:
    """
    Locate a tool binary. Checks in order:
    1. BINARY_DIR (cargo-compiled MalChela tools)
    2. PATH (including any tool_paths from server_config.yaml)
    3. Absolute path (if binary is a full path)
    """
    # MalChela cargo binary
    cargo_path = BINARY_DIR / binary
    if cargo_path.exists():
        return str(cargo_path)
    # PATH search
    found = shutil.which(binary)
    if found:
        return found
    # Absolute path given directly
    if Path(binary).is_absolute() and Path(binary).exists():
        return binary
    return None

# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=str(_SCRIPT_DIR), static_url_path='')
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS", "PATCH"]}})

@app.route('/')
def index():
    """Serve the PWA."""
    resp = send_from_directory(str(_SCRIPT_DIR), 'malchela_pwa.html')
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.route('/manifest.json')
def manifest():
    """Serve the PWA manifest."""
    return send_from_directory(str(_SCRIPT_DIR), 'manifest.json')

@app.route('/icons/<path:filename>')
def serve_icon(filename):
    """Serve SVG icons from server/icons/."""
    icons_dir = str((_SCRIPT_DIR / 'icons').resolve())
    return send_from_directory(icons_dir, filename)

# ── Helpers ───────────────────────────────────────────────────────────────────

def run_binary(binary: str, args: List[str], timeout: int = 120) -> dict:
    """
    Run a MalChela binary from the project root.
    All binaries must be invoked from MALCHELA_ROOT per project requirements.
    """
    binary_path = BINARY_DIR / binary
    if not binary_path.exists():
        return {"success": False, "error": f"Binary not found: {binary}"}

    cmd = [str(binary_path)] + args
    try:
        result = subprocess.run(
            cmd,  # shell=False (list form) — not vulnerable to shell injection
            cwd=str(MALCHELA_ROOT),  # Required — resolves API keys, YARA rules, Sigma rules
            capture_output=True,
            text=True,
            timeout=timeout
        )
        stdout = _strip_cli_noise(result.stdout.strip())
        stderr = result.stderr.strip()
        return {
            "success": True,
            "output": stdout,
            "stderr": stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Tool timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": _safe_error(e)}


# Patterns that are CLI-only noise, irrelevant or confusing in the PWA context
_CLI_NOISE_PATTERNS = [
    r"Output was not saved\..*",
    r"Use -o with -t, -j, or -m to export results\.?",
    r"To save output, use:.*",
    r"Run with -o to save.*",
    r"Note: MITRE Tactic IDs can be referenced with MITRE_lookup tool\.?",
]

def _strip_cli_noise(output: str) -> str:
    """Remove CLI-specific save reminders that are meaningless in the PWA."""
    lines = output.split('\n')
    cleaned = []
    for line in lines:
        skip = any(re.search(p, line, re.IGNORECASE) for p in _CLI_NOISE_PATTERNS)
        if not skip:
            cleaned.append(line)
    # Strip trailing blank lines left by removed lines
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return '\n'.join(cleaned)


def _strip_color_tags(text: str) -> str:
    """Remove [color_name] prefixes emitted by common_ui::styled_line."""
    return re.sub(
        r'^\[(?:green|red|yellow|stone|highlight|highlight_hash|NOTE|cyan|orange|dim)\]',
        '',
        text,
        flags=re.MULTILINE,
    )


def _register_cli_case_output(tool: str, case_name: str, target: str,
                               fmt: str, window_secs: int = 30) -> None:
    """
    After a CLI run with --case, find the newly written output file and
    register it in case.yaml so the case browser picks it up.
    """
    import time
    case_name = _sanitize_case_name(case_name) or case_name
    case_dir = CASES_DIR / case_name
    tool_dir = case_dir / tool
    if not tool_dir.exists():
        return

    cutoff = time.time() - window_secs
    new_files = sorted(
        [f for f in tool_dir.iterdir()
         if f.is_file() and f.stat().st_mtime >= cutoff],
        key=lambda f: f.stat().st_mtime,
    )
    if not new_files:
        return

    latest    = new_files[-1]
    filename  = latest.name
    rel_path  = f"{tool}/{filename}"
    ts_str    = datetime.now().isoformat()

    yaml_file = case_dir / "case.yaml"
    if yaml_file.exists():
        with open(yaml_file) as fh:
            meta = yaml.safe_load(fh) or {}
    else:
        meta = {
            "name":        case_name,
            "created":     ts_str,
            "description": "",
            "tags":        [],
            "status":      "open",
            "files":       [],
        }

    files = meta.get("files", [])
    if not any(e.get("path") == rel_path for e in files):
        files.append({
            "filename":  filename,
            "path":      rel_path,
            "tool":      tool,
            "target":    target,
            "timestamp": ts_str,
        })
        meta["files"]    = files
        meta["modified"] = ts_str
        with open(yaml_file, "w") as fh:
            yaml.dump(meta, fh, default_flow_style=False)


def safe_path(raw: str) -> Optional[Path]:
    """
    Resolve and jail-check a path against BROWSER_ROOT.
    Returns None if the path escapes the jail.
    """
    if not raw:
        return None
    try:
        browser_root = str(BROWSER_ROOT.resolve())
        resolved_str = os.path.realpath(raw)
        # Explicit prefix check that CodeQL recognizes as path sanitization
        if not (resolved_str == browser_root or
                resolved_str.startswith(browser_root + os.sep)):
            return None
        return Path(resolved_str)
    except Exception:
        return None


_CASE_NAME_RE = re.compile(r'[^\w\-.]')
_SAFE_ARG_RE  = re.compile(r'^[^\|&;`$<>!]+$')

def _sanitize_case_name(name: str) -> Optional[str]:
    """Sanitize a case name for safe filesystem use — only allow word chars, hyphens, dots."""
    if not name:
        return None
    clean = _CASE_NAME_RE.sub('_', name.strip())
    if not clean or '..' in clean:
        return None
    return clean[:128]


def read_api_key(filename: str) -> Optional[str]:
    """Read an API key from the api/ directory."""
    key_path = API_DIR / filename
    if key_path.exists():
        return key_path.read_text().strip()
    return None

# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check — confirms server and binary availability."""
    binaries = [
        "fileanalyzer", "fileminer", "hashit", "hashcheck",
        "malhash", "mstrings", "mzhash", "mzcount", "xmzhash",
        "nsrlquery", "combine_yara", "strings_to_yara", "extract_samples",
        "tiquery", "about", "MITRE_lookup",
    ]
    available = {b: (BINARY_DIR / b).exists() for b in binaries}
    return jsonify({
        "status": "ok",
        "malchela_root": str(MALCHELA_ROOT),
        "binaries": available,
        "vt_key_configured": read_api_key("vt-api.txt") is not None,
        "mb_key_configured": read_api_key("mb-api.txt") is not None,
    })

# ── Tools YAML ────────────────────────────────────────────────────────────────

TOOLS_YAML_PATH        = MALCHELA_ROOT / "tools.yaml"
TOOLS_YAML_BACKUP_DIR  = OUTPUT_DIR / "tools_yaml_backups"
VOL3_PLUGINS_YAML_PATH = MALCHELA_ROOT / "config" / "vol3_plugins.yaml"

def _find_preset_yaml(filename: str) -> Optional[Path]:
    """Find a preset yaml file — checks server/presets/ first, then fallback locations."""
    search_paths = [
        _SCRIPT_DIR / "presets" / filename,              # server/presets/ — primary
        MALCHELA_ROOT / "presets" / filename,            # root presets/ fallback
        MALCHELA_ROOT / filename,                        # root fallback
        MALCHELA_ROOT / "MalChelaGUI" / "remnux" / filename,  # legacy GUI location
    ]
    for p in search_paths:
        if p.exists():
            return p
    return None


@app.route("/tools_yaml", methods=["GET"])
def get_tools_yaml():
    """Return parsed tools.yaml as JSON for dynamic sidebar building."""
    if not TOOLS_YAML_PATH.exists():
        return jsonify({"success": False, "error": "tools.yaml not found"}), 404
    try:
        with open(TOOLS_YAML_PATH) as f:
            data = yaml.safe_load(f) or {}
        tools = data.get("tools", [])
        edition = data.get("edition", "")

        # For each tool, check if binary/command is available
        result = []
        for tool in tools:
            cmd = tool.get("command", [])
            binary = cmd[0] if cmd else ""
            exec_type = tool.get("exec_type", "cargo")

            available = False
            if exec_type == "cargo":
                available = (BINARY_DIR / binary).exists()
            else:
                available = find_tool(binary) is not None

            result.append({
                "name":          tool.get("name", ""),
                "description":   tool.get("description", ""),
                "command":       cmd,
                "input_type":    tool.get("input_type", "file"),
                "category":      tool.get("category", "Utilities"),
                "exec_type":     exec_type,
                "optional_args": tool.get("optional_args", []),
                "file_position": tool.get("file_position", "last"),
                "available":     available,
            })

        return jsonify({"success": True, "edition": edition, "tools": result})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)}), 500


@app.route("/tools_yaml/raw", methods=["GET"])
def get_tools_yaml_raw():
    """Return raw tools.yaml content for editing."""
    if not TOOLS_YAML_PATH.exists():
        return jsonify({"success": False, "error": "tools.yaml not found"}), 404
    return jsonify({"success": True, "content": TOOLS_YAML_PATH.read_text()})


@app.route("/tools_yaml/raw", methods=["POST"])
def save_tools_yaml_raw():
    """Save raw yaml content back to tools.yaml after validation."""
    data = request.json or {}
    content = data.get("content", "")
    try:
        # Validate it's valid yaml before saving
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        logger.error("YAML parse error: %s", e)
        return jsonify({"success": False, "error": "Invalid YAML"}), 400
    TOOLS_YAML_PATH.write_text(content)
    return jsonify({"success": True})


@app.route("/tools_yaml/backup", methods=["POST"])
def backup_tools_yaml():
    """Back up tools.yaml with a custom or timestamped name to tools_yaml_backups/."""
    if not TOOLS_YAML_PATH.exists():
        return jsonify({"success": False, "error": "tools.yaml not found"}), 404
    TOOLS_YAML_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    data = request.json or {}
    custom_name = data.get("filename", "").strip()

    if custom_name:
        # Sanitize — only allow safe filename characters
        safe_name = re.sub(r'[^\w\-.]', '_', custom_name)
        if not safe_name.endswith('.yaml'):
            safe_name += '.yaml'
        backup_path = TOOLS_YAML_BACKUP_DIR / safe_name
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = TOOLS_YAML_BACKUP_DIR / f"tools_{timestamp}.yaml"

    shutil.copy2(str(TOOLS_YAML_PATH), str(backup_path))
    return jsonify({"success": True, "backup": str(backup_path), "filename": backup_path.name})


@app.route("/tools_yaml/restore", methods=["POST"])
def restore_tools_yaml():
    """
    Restore tools.yaml from a specified yaml file path.
    Expects: { "path": "/path/to/tools_backup.yaml" }
    """
    data = request.json or {}
    raw_path = data.get("path", "").strip()
    if not raw_path:
        return jsonify({"success": False, "error": "No path provided"}), 400

    # Try absolute path first, then as filename within backup dir
    restore_path = safe_path(raw_path)
    if not restore_path or not restore_path.exists():
        candidate = TOOLS_YAML_BACKUP_DIR / secure_filename(Path(raw_path).name)
        if candidate.exists():
            restore_path = candidate
        else:
            return jsonify({"success": False, "error": f"File not found: {raw_path}"}), 404

    # Validate it's valid yaml before restoring
    try:
        with open(restore_path) as f:
            yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("YAML parse error in restore: %s", e)
        return jsonify({"success": False, "error": "Invalid YAML"}), 400
    shutil.copy2(str(restore_path), str(TOOLS_YAML_PATH))
    return jsonify({"success": True, "restored_from": str(restore_path)})


@app.route("/tools_yaml/load_default", methods=["POST"])
def load_default_tools_yaml():
    """Load default_tools.yaml into tools.yaml (backs up current first)."""
    src = _find_preset_yaml("default_tools.yaml")
    if not src:
        return jsonify({"success": False, "error": "default_tools.yaml not found. Place it in the MalChela root or MalChelaGUI/remnux/"}), 404
    if TOOLS_YAML_PATH.exists():
        TOOLS_YAML_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy2(str(TOOLS_YAML_PATH), str(TOOLS_YAML_BACKUP_DIR / f"tools_{ts}.yaml"))
    shutil.copy2(str(src), str(TOOLS_YAML_PATH))
    return jsonify({"success": True, "loaded_from": str(src)})


@app.route("/tools_yaml/load_remnux", methods=["POST"])
def load_remnux_tools_yaml():
    """Load remnux_tools.yaml into tools.yaml (backs up current first)."""
    src = _find_preset_yaml("remnux_tools.yaml")
    if not src:
        return jsonify({"success": False, "error": "remnux_tools.yaml not found. Place it in the MalChela root or MalChelaGUI/remnux/"}), 404
    if TOOLS_YAML_PATH.exists():
        TOOLS_YAML_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy2(str(TOOLS_YAML_PATH), str(TOOLS_YAML_BACKUP_DIR / f"tools_{ts}.yaml"))
    shutil.copy2(str(src), str(TOOLS_YAML_PATH))
    return jsonify({"success": True, "loaded_from": str(src)})


@app.route("/tools/generic", methods=["POST"])
def run_generic_tool():
    """
    Run any non-cargo tool defined in tools.yaml generically.
    Handles binary/script exec_types with optional_args and file_position.
    """
    data        = request.json or {}
    command     = data.get("command", [])
    input_path  = data.get("input_path", "")
    extra_args  = data.get("extra_args", "").strip()
    optional_args = data.get("optional_args", [])
    file_position = data.get("file_position", "last")
    exec_type     = data.get("exec_type", "binary")

    if not command:
        return jsonify({"success": False, "error": "No command specified"}), 400

    binary = command[0]
    # Handle case where binary has embedded args e.g. "/usr/bin/r2 -i"
    if ' ' in binary:
        import shlex as _shlex2
        parts = _shlex2.split(binary)
        binary = parts[0]
        # Prepend the embedded args to optional_args
        resolved_optional = list(parts[1:]) + list(resolved_optional)
    resolved = find_tool(binary)
    if not resolved:
        return jsonify({"success": False, "error": f"Command not found: {binary}. Add its directory to tool_paths in server_config.yaml"})

    # For script exec_type, resolve optional_args (script paths) relative to MALCHELA_ROOT
    resolved_optional = []
    for arg in optional_args:
        p = Path(arg)
        if not p.is_absolute():
            candidate = MALCHELA_ROOT / arg
            resolved_optional.append(str(candidate) if candidate.exists() else arg)
        else:
            resolved_optional.append(arg)

    # Build args list
    args = list(resolved_optional) if resolved_optional else []

    path_obj = safe_path(input_path) if input_path else None

    if file_position == "first" and path_obj:
        args = [str(path_obj)] + args
    elif path_obj:
        args.append(str(path_obj))

    # Append any extra user args (strip shell metacharacters)
    if extra_args:
        import shlex as _shlex
        parsed = _shlex.split(extra_args)
        args.extend(a for a in parsed if _SAFE_ARG_RE.match(a))

    try:
        result = subprocess.run(
            [resolved] + args,
            cwd=str(MALCHELA_ROOT),
            capture_output=True,
            timeout=120
        )
        # Safe decode — handles binary/non-UTF8 output from tools like r2
        def _safe_decode(b):
            try: return b.decode('utf-8')
            except UnicodeDecodeError: return b.decode('latin-1', errors='replace')

        stdout = _safe_decode(result.stdout)
        stderr = _safe_decode(result.stderr)
        output = stdout + (f"\n[stderr]\n{stderr}" if stderr.strip() else "")
        output = _strip_cli_noise(output.strip())
        return jsonify({"success": True, "output": output, "returncode": result.returncode})
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"Command not found: {binary}. Is it installed and in PATH?"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Tool timed out after 120s. If this tool requires interactive input it may not be suitable for remote execution."})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


# ── Home & About ──────────────────────────────────────────────────────────────

def _run_interactive(binary: str, stdin_input: str = "\n", timeout: int = 15) -> dict:
    """Run an interactive binary, send stdin to satisfy prompts, return output."""
    binary_path = BINARY_DIR / binary
    if not binary_path.exists():
        return {"success": False, "error": f"Binary not found: {binary}"}
    try:
        result = subprocess.run(
            [str(binary_path), f"--{binary.split('_')[0]}"],
            cwd=str(MALCHELA_ROOT),
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout + (f"\n{result.stderr}" if result.stderr.strip() else "")
        return {"success": True, "output": output.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": _safe_error(e)}


@app.route("/home", methods=["GET"])
def home_screen():
    """
    Return home screen: ASCII crab art, version, and a random koan.
    Koans are loaded live from assets/koans/crabby_koans.yaml.
    Update check is skipped (causes timeout).
    """
    import random

    ascii_art = r"""
                ▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒                                
              ▒▒▒▒▒▒                ▒▒▒▒▒▒                              
              ▒▒▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒▒▒▒▒▒▒            ▒▒▒▒▒▒▒▒▒▒                            
            ▒▒▒▒      ██        ██      ▒▒▒▒                            
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
            ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                            
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
                ▒▒▒▒    ▒▒▒▒▒▒▒▒    ▒▒▒▒                                
    """

    # Load koans from the project's yaml file
    koans = []
    koans_path = MALCHELA_ROOT / "assets" / "koans" / "crabby_koans.yaml"
    try:
        with open(koans_path) as f:
            koan_data = yaml.safe_load(f)
        # Handle both list-of-strings and list-of-dicts formats
        if isinstance(koan_data, list):
            for item in koan_data:
                if isinstance(item, str):
                    koans.append(item)
                elif isinstance(item, dict):
                    # Common yaml structures: {koan: "..."} or {text: "..."}
                    koans.append(next(iter(item.values())))
        elif isinstance(koan_data, dict):
            # Could be {koans: [...]}
            for v in koan_data.values():
                if isinstance(v, list):
                    koans.extend([str(k) for k in v])
    except Exception:
        koans = ["To `cat` in haste is to grep in regret."]

    koan = random.choice(koans) if koans else "The hash that cannot be verified was never truly known."

    output = (
        f"{ascii_art}\n"
        f"            https://bakerstreetforensics.com\n\n"
        f"            MalChela Analysis Toolkit v4.2\n\n"
        f"{koan}"
    )
    return jsonify({"success": True, "output": output})


@app.route("/about", methods=["GET"])
def about_screen():
    """
    Run the standalone 'about' binary, but replace its art output with the
    canonical art string (same as home) to ensure consistent rendering.
    """
    binary_path = BINARY_DIR / "about"
    if not binary_path.exists():
        return jsonify({"success": False, "error": "about binary not found"})

    # Canonical art — matches home screen exactly
    canonical_art = (
        "                ▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒                                \n"
        "              ▒▒▒▒▒▒                ▒▒▒▒▒▒                              \n"
        "              ▒▒▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒                              \n"
        "            ▒▒▒▒▒▒▒▒▒▒            ▒▒▒▒▒▒▒▒▒▒                            \n"
        "            ▒▒▒▒      ██        ██      ▒▒▒▒                            \n"
        "            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            \n"
        "            ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                            \n"
        "              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              \n"
        "                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  \n"
        "              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              \n"
        "            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            \n"
        "                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  \n"
        "                ▒▒▒▒    ▒▒▒▒▒▒▒▒    ▒▒▒▒                                "
    )

    try:
        result = subprocess.run(
            [str(binary_path)],
            cwd=str(MALCHELA_ROOT),
            input="\n",
            capture_output=True,
            text=True,
            timeout=15
        )
        raw = result.stdout + (f"\n{result.stderr}" if result.stderr.strip() else "")

        # Strip art lines from binary output, keep only text below art
        text_lines = []
        art_done = False
        for line in raw.split('\n'):
            has_art = '▒' in line or '█' in line
            if has_art:
                art_done = True
                continue
            if art_done:
                text_lines.append(line)

        text_content = '\n'.join(text_lines).strip()
        output = canonical_art + '\n\n' + text_content
        return jsonify({"success": True, "output": output})

    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Timed out"})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})

# ── File Browser ──────────────────────────────────────────────────────────────

@app.route("/browse", methods=["GET"])
def browse():
    """
    List directory contents within BROWSER_ROOT jail.
    Query param: path (default: /home/dwmetz)
    Returns files and subdirectories with metadata.
    """
    raw_path = request.args.get("path", str(BROWSER_ROOT))
    target = safe_path(raw_path)

    if target is None:
        return jsonify({"success": False, "error": "Path outside allowed root"}), 403
    if not target.exists():
        return jsonify({"success": False, "error": "Path does not exist"}), 404
    if not target.is_dir():
        return jsonify({"success": False, "error": "Path is not a directory"}), 400

    entries = []
    try:
        for entry in sorted(target.iterdir()):
            try:
                stat = entry.stat()
                entries.append({
                    "name": entry.name,
                    "path": str(entry),
                    "type": "directory" if entry.is_dir() else "file",
                    "size": stat.st_size if entry.is_file() else None,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
            except PermissionError:
                continue  # Skip entries we can't read
    except PermissionError:
        return jsonify({"success": False, "error": "Permission denied"}), 403

    return jsonify({
        "success": True,
        "path": str(target),
        "parent": str(target.parent) if target != BROWSER_ROOT else None,
        "entries": entries,
    })

# ── File Upload ───────────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Accept file uploads from the PWA (iPad or desktop browser).
    Files are saved to UPLOADS_DIR (MalChela/uploads/) and are
    immediately browseable via the standard /browse endpoint.
    Supports multipart/form-data with field name 'file'.
    """
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file in request"}), 400

    files = request.files.getlist('file')
    if not files:
        return jsonify({"success": False, "error": "No files selected"}), 400

    saved = []
    errors = []

    for f in files:
        if not f.filename:
            continue
        filename = secure_filename(f.filename)
        if not filename:
            errors.append(f"Invalid filename: {f.filename}")
            continue
        dest = UPLOADS_DIR / filename
        # If file already exists, append timestamp to avoid collision
        if dest.exists():
            stem = dest.stem
            suffix = dest.suffix
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = UPLOADS_DIR / f"{stem}_{ts}{suffix}"
        try:
            f.save(str(dest))
            saved.append({
                "filename": dest.name,
                "path": str(dest),
                "size": dest.stat().st_size,
            })
        except Exception as e:
            errors.append(f"{f.filename}: {_safe_error(e)}")

    return jsonify({
        "success": len(saved) > 0,
        "saved": saved,
        "errors": errors,
        "uploads_dir": str(UPLOADS_DIR),
    })


@app.route("/uploads", methods=["GET"])
def list_uploads():
    """List files in the uploads directory."""
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(UPLOADS_DIR.iterdir()):
        if f.is_file():
            stat = f.stat()
            files.append({
                "filename": f.name,
                "path": str(f),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return jsonify({"success": True, "files": files, "uploads_dir": str(UPLOADS_DIR)})

# ── Tool Endpoints ────────────────────────────────────────────────────────────

_FMT_FLAG = {"txt": "-t", "md": "-m", "json": "-j"}

@app.route("/tools/fileanalyzer", methods=["POST"])
def fileanalyzer():
    """Analyze a file for hashes, entropy, PE structure, YARA matches, VirusTotal status."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = _sanitize_case_name(data.get("case_name", "").strip()) or ""
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("fileanalyzer", args)
    if case_name and result.get("success"):
        _register_cli_case_output("fileanalyzer", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/fileminer", methods=["POST"])
def fileminer():
    """
    Scan a folder for file type mismatches and metadata.
    FileMiner outputs a table then prompts interactively.
    We capture stdout until the prompt appears, then terminate.
    """
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400

    binary_path = BINARY_DIR / "fileminer"
    if not binary_path.exists():
        return jsonify({"success": False, "error": "Binary not found: fileminer"})

    import threading

    try:
        proc = subprocess.Popen(
            [str(binary_path), str(path)],
            cwd=str(MALCHELA_ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        output_lines = []
        done = threading.Event()

        def read_output():
            for line in proc.stdout:
                output_lines.append(line)
                # Stop reading once we hit the interactive prompt
                if "Select a file" in line or "press 'x'" in line.lower():
                    break
            done.set()

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()

        # Wait up to 60s for the table to be fully output
        done.wait(timeout=60)

        # Terminate cleanly
        try:
            proc.stdin.write("x\n")
            proc.stdin.flush()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

        output = "".join(output_lines).strip()
        stderr_out = proc.stderr.read().strip() if proc.stderr else ""
        if stderr_out:
            output += f"\n[stderr]\n{stderr_out}"

        rows = _parse_fileminer_output(output)

        import sys
        if rows:
            print(f"DEBUG fileminer rows[0]: {rows[0]}", file=sys.stderr)

        return jsonify({
            "success": True,
            "output": output,
            "returncode": 0,
            "rows": rows,
        })

    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


def _parse_fileminer_output(output: str) -> list:
    """
    Parse FileMiner table output using fixed column positions derived from the header row.
    The table uses fixed-width columns — we find │ positions from the header separator
    and slice each line accordingly, rather than splitting on │ (which fails on continuation lines).
    """
    lines = output.split('\n')

    # Find the header separator line (┌...┐ or ├...┤) to derive column boundary positions
    col_positions = []
    for line in lines:
        if line.startswith('┌') or line.startswith('├'):
            # Find all │ equivalent positions — in separator lines these are ┬ or ┼
            positions = [i for i, ch in enumerate(line) if ch in ('┬', '┼', '┐', '┤')]
            if len(positions) >= 8:
                col_positions = positions
                break

    if not col_positions:
        return []

    # Column slices: from position after previous │ to position of next │
    # Table structure: │ # │ Filename │ Path │ Type │ Size │ SHA256 │ Ext │ Inferred │ Mismatch │ Suggested │
    # col_positions gives us the right-edge of each column

    rows = []
    current_cells = [''] * 9  # 9 data columns (skip row number)
    in_data = False

    for line in lines:
        if not line.startswith('│'):
            if line.startswith('├') or line.startswith('┌'):
                in_data = True
            if line.startswith('└') or line.startswith('├'):
                # Row boundary — save current if populated
                if any(c.strip() for c in current_cells):
                    row = _cells_to_row(current_cells)
                    if row:
                        rows.append(row)
                    current_cells = [''] * 9
            continue

        if not in_data:
            continue

        # Skip header row
        if '# ' in line[:6] or 'Filename' in line:
            continue

        # Use col_positions to slice the line into cells
        # First cell (index 0) is the row number — skip it
        # Remaining cells map to our 9 data columns
        try:
            prev = 0
            all_cells = []
            for pos in col_positions:
                cell = line[prev+1:pos].strip() if pos <= len(line) else ''
                all_cells.append(cell)
                prev = pos
            # all_cells[0] = row number, [1..9] = data columns
            if len(all_cells) >= 10:
                is_new_row = all_cells[0].isdigit()
                if is_new_row:
                    if any(c.strip() for c in current_cells):
                        row = _cells_to_row(current_cells)
                        if row:
                            rows.append(row)
                    current_cells = [all_cells[i] for i in range(1, 10)]
                else:
                    # Continuation — append non-empty cells without separator
                    for i in range(9):
                        part = all_cells[i+1] if i+1 < len(all_cells) else ''
                        if part:
                            # Path-like cells (0=filename, 1=path, 4=sha256): no space
                            sep = '' if i in (0, 1, 4) else ' '
                            current_cells[i] = current_cells[i] + sep + part
        except Exception:
            continue

    # Don't forget the last row
    if any(c.strip() for c in current_cells):
        row = _cells_to_row(current_cells)
        if row:
            rows.append(row)

    return rows


def _cells_to_row(cells: list) -> Optional[dict]:
    """Convert fixed-width sliced cells into a structured dict."""
    if len(cells) < 4:
        return None
    try:
        filename = cells[0].strip()
        path     = cells[1].strip()

        # Path cell contains the full path including filename — use directly
        # Strip any whitespace artifacts from fixed-width slicing
        full_path = path if path else filename

        return {
            "filename":  filename,
            "path":      path,
            "full_path": full_path,
            "type":      cells[2].strip() if len(cells) > 2 else "",
            "size":      cells[3].strip() if len(cells) > 3 else "",
            "sha256":    cells[4].strip() if len(cells) > 4 else "",
            "ext":       cells[5].strip() if len(cells) > 5 else "",
            "inferred":  cells[6].strip() if len(cells) > 6 else "",
            "mismatch":  cells[7].strip() if len(cells) > 7 else "",
            "suggested": cells[8].strip() if len(cells) > 8 else "",
        }
    except Exception:
        return None


# ── Analyze (auto-mode) ─────────────────────────────────────────────────────
#
# "Analyze" takes a single file, a folder, or a .app bundle and does what a
# human would do by hand with FileMiner's suggestions: run every suggested
# tool against every file, then produce one mechanical rollup report on top
# of the individual per-tool reports that already get saved (and, per the
# case.yaml fix, registered) the normal way.
#
# This intentionally reuses FileMiner's own suggestion engine rather than
# re-deriving "which tool for which file type" here — that mapping lives in
# fileminer/src/main.rs's ScanResult.suggested_tools and nowhere else, so
# calling fileminer with --no-prompt (clean JSON to stdout, no interactive
# table/keypress loop) keeps this endpoint from drifting out of sync with it.

_ANALYZE_MAX_FILES = 25  # keep this a synchronous, single-sample/bundle operation;
                         # corpus-scale scans belong to MZHash/MZCount/XMZHash.


_ZIP_PASSWORDS = ["", "infected", "malware", "virus"]  # "" tried first = no password


def _maybe_extract_zip(target: Path) -> tuple:
    """If target is a .zip (the only way to upload a directory-based sample
    like a .app bundle through the PWA's file-only upload widget), extract
    it into a sibling '<stem>_extracted' directory and return the extracted
    directory as the new analyze target, plus a note for the rollup. Tries
    no password first, then the same common malware-zip passwords Extract
    Samples uses. Uses the zipfile stdlib module rather than shelling out to
    7z (what Extract Samples itself uses) — this only needs to run without
    an extra 7zip dependency on whatever host Analyze runs on; it only
    handles classic ZipCrypto-protected zips, not AES-encrypted ones.
    Returns (target, None) unchanged if target isn't a .zip."""
    if target.suffix.lower() != ".zip":
        return target, None

    extract_dir = target.parent / f"{target.stem}_extracted"

    for pwd in _ZIP_PASSWORDS:
        shutil.rmtree(extract_dir, ignore_errors=True)
        try:
            with zipfile.ZipFile(target) as zf:
                zf.extractall(extract_dir, pwd=pwd.encode() if pwd else None)
            note = f"Auto-extracted `{target.name}`" + (f" (password: `{pwd}`)" if pwd else "")
            return extract_dir, note
        except RuntimeError:
            continue  # wrong password — try the next one
        except zipfile.BadZipFile as e:
            raise ValueError(f"Not a valid zip file: {e}")

    raise ValueError(
        f"{target.name} is password-protected with a password not in the common list "
        f"(infected/malware/virus). Extract it manually with Extract Samples first."
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Auto-run mode: classify a file/folder/bundle via FileMiner's suggestion
    engine, run every suggested tool against every file found, and write one
    combined rollup report alongside the individual reports.
    """
    data        = request.json or {}
    raw_path    = data.get("path", "")
    case_name   = _sanitize_case_name(data.get("case_name", "").strip()) or ""

    target = safe_path(raw_path)
    if target is None:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    if not target.exists():
        return jsonify({"success": False, "error": "Path does not exist"}), 404

    extraction_note = None
    try:
        target, extraction_note = _maybe_extract_zip(target)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)})

    # A .app bundle is a directory on disk, so it's already handled the same
    # way as any other folder — FileMiner's WalkDir walks into it naturally.
    single_file_mode = target.is_file()
    scan_dir = target.parent if single_file_mode else target

    fm_args = [str(scan_dir), "--no-prompt"]
    if case_name:
        fm_args += ["--case", case_name]

    fm_result = run_binary("fileminer", fm_args, timeout=120)
    if not fm_result.get("success"):
        return jsonify({"success": False, "error": fm_result.get("error", "fileminer failed to run")})

    try:
        fm_data = json.loads(fm_result["output"])
    except (ValueError, KeyError) as e:
        return jsonify({"success": False, "error": f"Could not parse fileminer output: {e}"})

    scan_results = fm_data.get("results", [])

    if single_file_mode:
        try:
            target_resolved = target.resolve()
        except Exception:
            target_resolved = target
        scan_results = [
            r for r in scan_results
            if _paths_match(r.get("filepath", ""), target_resolved)
        ]
        if not scan_results:
            return jsonify({
                "success": False,
                "error": "Selected file was not found in fileminer's scan results (it may be a hidden/skipped file type)."
            })

    if len(scan_results) > _ANALYZE_MAX_FILES:
        return jsonify({
            "success": False,
            "error": (
                f"{len(scan_results)} files found — Analyze is meant for a single sample or small bundle "
                f"(limit {_ANALYZE_MAX_FILES} files). For corpus-scale scans, use MZHash/MZCount/XMZHash instead."
            ),
        })

    per_file_results = []
    for res in scan_results:
        filepath  = res.get("filepath", "")
        sha256    = res.get("sha256", "")
        md5       = res.get("md5", "")
        suggested = res.get("suggested_tools", [])  # [[label, slug], ...]

        tool_runs = []
        for pair in suggested:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            label, slug = pair

            if slug == "tiquery":
                args = [sha256] if sha256 else None
            elif slug == "nsrlquery":
                args = [md5] if md5 else None
            else:
                args = [filepath]

            if args is None:
                tool_runs.append({
                    "label": label, "tool": slug, "success": False,
                    "output": "", "error": "Missing hash required for this tool.",
                })
                continue

            # Always save a markdown report — case or not — so the rollup can
            # embed each tool's actual formatted output (headers, tables)
            # instead of raw CLI stdout. Independent of any case's own
            # save-format preference; -m is genuinely the richer artifact,
            # and this is Analyze's own internal read-back, not the user's
            # saved case file (that's still whatever -m/-t/-j produces).
            args = args + ["-o", "-m"]
            if case_name:
                args = args + ["--case", case_name]

            result = run_binary(slug, args, timeout=90)
            markdown = _read_tool_markdown(slug, case_name) if result.get("success") else ""

            if case_name and result.get("success"):
                reg_target = sha256 if slug == "tiquery" else (md5 if slug == "nsrlquery" else filepath)
                _register_cli_case_output(slug, case_name, reg_target, "md")

            tool_runs.append({
                "label":    label,
                "tool":     slug,
                "success":  result.get("success", False),
                "output":   result.get("output", ""),
                "error":    result.get("error", ""),
                "markdown": markdown,
            })

        per_file_results.append({
            "filename": res.get("filename", ""),
            "filepath": filepath,
            "filetype": res.get("filetype", ""),
            "sha256":   sha256,
            "md5":      md5,
            "tool_runs": tool_runs,
        })

    rollup_md = _build_analyze_rollup(str(target), per_file_results, extraction_note)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # The "analyze" subfolder matters here, not just cosmetically: it's what
    # lets _register_cli_case_output("analyze", ...) below find the file it
    # just find via its case_dir/<tool>/ mtime-window scan. Without it the
    # rollup saves fine but silently never lands in case.yaml.
    rollup_dir = (CASES_DIR / case_name / "analyze") if case_name else (OUTPUT_DIR / "analyze")
    rollup_dir.mkdir(parents=True, exist_ok=True)
    rollup_path = rollup_dir / f"malchela_summary_{ts}.md"
    rollup_path.write_text(rollup_md)

    if case_name:
        _register_cli_case_output("analyze", case_name, str(target), "md")

    return jsonify({
        "success":         True,
        "target":          str(target),
        "file_count":      len(per_file_results),
        "results":         per_file_results,
        "rollup_path":     str(rollup_path),
        "rollup_content":  rollup_md,
        "extraction_note": extraction_note,
    })


def _paths_match(candidate: str, resolved_target: Path) -> bool:
    """Best-effort path equality — fileminer reports paths as given, so
    compare resolved forms to tolerate trailing slashes / relative prefixes."""
    if not candidate:
        return False
    try:
        return Path(candidate).resolve() == resolved_target
    except Exception:
        return candidate == str(resolved_target)


_TIQUERY_VT_ROW = re.compile(r"^\s*VT\s+FOUND\s+.*?(\d+)/(\d+)", re.MULTILINE)
_MD_HEADING = re.compile(r"^(#{1,6})( .*)$", re.MULTILINE)


def _read_tool_markdown(tool: str, case_name: str) -> str:
    """Read back the .md report a tool just wrote (Analyze always requests
    -o -m, case or not — see the dispatch loop below) so the rollup can embed
    genuinely formatted content instead of raw CLI stdout. Picks the
    most-recently-modified report_*.md in the tool's output dir; safe because
    dispatch is fully sequential — nothing else writes there between this
    tool's run and this read."""
    tool_dir = (CASES_DIR / case_name / tool) if case_name else (OUTPUT_DIR / tool)
    if not tool_dir.exists():
        return ""
    md_files = sorted(tool_dir.glob("report_*.md"), key=lambda p: p.stat().st_mtime)
    return md_files[-1].read_text() if md_files else ""


def _demote_markdown_headings(md: str, shift: int = 2) -> str:
    """Shift a tool's own ATX headings down by `shift` levels so its '# ...
    Report' nests under the rollup's '## <filename>' section instead of
    colliding with it."""
    return _MD_HEADING.sub(lambda m: "#" * min(len(m.group(1)) + shift, 6) + m.group(2), md)


_MD_MITRE_ROW = re.compile(r"^\|\s*(\d+)\s*\|[^|]*\|[^|]*\|\s*([^|]+?)\s*\|[^|]*\|[^|]*\|\s*$", re.MULTILINE)


def _extract_mitre_tactics(markdown: str) -> tuple:
    """Parse mstrings' markdown 'Detections' table (Count | Rule | Matched
    Strings | Tactic | Technique | ID) into (raw_total, tactic_counts).
    Scoped to a single mstrings run's markdown, so the digit-first/6-column
    heuristic isn't at risk of matching some other tool's table. A rule
    mapped to multiple tactics (comma-separated) credits its count to each
    tactic — that's how ATT&CK tagging works — so tactic_counts can sum to
    more than raw_total; raw_total is the true per-file match count."""
    raw_total = 0
    tactics: dict = {}
    for count_str, tactic_field in _MD_MITRE_ROW.findall(markdown):
        count = int(count_str)
        raw_total += count
        for tactic in tactic_field.split(","):
            tactic = tactic.strip()
            if tactic:
                tactics[tactic] = tactics.get(tactic, 0) + count
    return raw_total, tactics


_TIQUERY_TAG_ROW = re.compile(r"^\|\s*[^\s|]+\s*\|\s*FOUND\s*\|\s*([^|]+?)\s*\|[^|]*\|[^|]*\|\s*$", re.MULTILINE)


def _extract_tiquery_tags(markdown: str) -> list:
    """Pull non-empty Family/Tags values from tiquery's markdown Results
    table (Source | Status | Family / Tags | Detections | Link), for sources
    that returned a FOUND hit. \\s*FOUND\\s* between pipes only matches a cell
    that's exactly "FOUND" — "NOT FOUND" has "NOT " in the way, so it's
    naturally excluded. Order-preserving, exact-text dedup only — sources use
    their own naming conventions, so no attempt is made to merge near-
    duplicate family names across sources."""
    tags = []
    seen = set()
    for tag in _TIQUERY_TAG_ROW.findall(markdown):
        tag = tag.strip()
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


_MD_FLAG_BULLET = re.compile(r"^-\s*\*\*\[!\]\*\*\s*(.+)$", re.MULTILINE)
_CODESIGN_WARN_LINE = re.compile(r"^\s*⚠\s+(.+)$", re.MULTILINE)


def _extract_flags(tool: str, markdown: str) -> list:
    """Pull '[!]'-style flag/indicator lines from a tool's markdown report.
    macho_info and plist_analyzer emit an identical '- **[!]** ...' bullet
    list under their own 'Flags / Indicators' heading; codesign_check's
    markdown just wraps its raw colorized stdout in a code fence, where the
    same kind of finding shows up as a '⚠  ...' line instead (its "No
    suspicious indicators" clean case uses '✓', so it's naturally excluded
    here) — scoped to codesign_check specifically so this pattern can't
    match some other tool's content."""
    if tool == "codesign_check":
        return [m.strip() for m in _CODESIGN_WARN_LINE.findall(markdown)]
    return [m.strip() for m in _MD_FLAG_BULLET.findall(markdown)]


_MSTRINGS_FS_IOC_BLOCK = re.compile(r"## Potential Filesystem IOCs\n\n((?:- `.+`\n)+)")
_MSTRINGS_NET_IOC_BLOCK = re.compile(r"## Potential Network IOCs\n\n((?:- `.+`\n)+)")
_MD_BACKTICK_BULLET = re.compile(r"- `(.+)`")


def _extract_mstrings_iocs(markdown: str) -> tuple:
    """Pull filesystem/network IOC bullets out of mstrings' own markdown
    sections ('## Potential Filesystem IOCs' / '## Potential Network IOCs',
    each a plain '- `ioc`' bullet list — the only place mstrings emits that
    exact bullet pattern, so no cross-section ambiguity)."""
    def _bullets(block_pattern):
        m = block_pattern.search(markdown)
        return _MD_BACKTICK_BULLET.findall(m.group(1)) if m else []
    return _bullets(_MSTRINGS_FS_IOC_BLOCK), _bullets(_MSTRINGS_NET_IOC_BLOCK)


def _flag_verdict(tool_runs: list) -> tuple:
    """Best-effort malicious flag for the triage banner — not a full
    multi-source verdict, just enough signal without parsing every tool's
    ad-hoc text output. Two signals, checked in order:
      1. FileAnalyzer's own VirusTotal line (PE / generic-unknown files only —
         FileAnalyzer isn't suggested for Mach-O).
      2. tiquery's VT row detection ratio (suggested for PE, Mach-O, and
         generic-unknown — the one source common across file types, so this
         is what actually catches Mach-O malware)."""
    for run in tool_runs:
        if not run.get("success"):
            continue
        output = run.get("output") or ""
        if "VirusTotal: Malicious" in output:
            return True, "VirusTotal: Malicious"
        m = _TIQUERY_VT_ROW.search(output)
        if m and int(m.group(1)) > 0:
            return True, f"VirusTotal: {m.group(1)}/{m.group(2)} (via tiquery)"
    return False, ""


def _build_analyze_rollup(target: str, per_file_results: list, extraction_note: str = None) -> str:
    """Mechanical rollup only — every tool's captured output concatenated
    under per-file/per-tool headings. No synthesis, no narrative; that's a
    separate, human (or LLM-assisted) step on top of this.

    Files are grouped by SHA256 for display: duplicate content saved under
    different names (common with carved/exported network artifacts) gets one
    write-up instead of the same tool output repeated verbatim per filename.
    This only changes what's shown here — every path was still analyzed and
    still has its own saved report and case.yaml entry."""
    groups: dict = {}
    order: list = []
    for f in per_file_results:
        key = f["sha256"] or f["filepath"]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    flagged = []
    dup_groups = []
    mitre_tactics: dict = {}
    mitre_total = 0
    malware_tags: list = []
    malware_tags_seen: set = set()
    flag_findings: list = []  # (filename, tool, flag_text)
    fs_iocs: list = []
    fs_iocs_seen: set = set()
    net_iocs: list = []
    net_iocs_seen: set = set()
    for key in order:
        members = groups[key]
        is_flagged, reason = _flag_verdict(members[0]["tool_runs"])
        if is_flagged:
            flagged.append(members[0]["filename"])
        if len(members) > 1:
            dup_groups.append(members)
        for run in members[0]["tool_runs"]:
            if run.get("tool") == "mstrings" and run.get("success") and run.get("markdown"):
                raw_total, tactics = _extract_mitre_tactics(run["markdown"])
                mitre_total += raw_total
                for tactic, count in tactics.items():
                    mitre_tactics[tactic] = mitre_tactics.get(tactic, 0) + count
                fs, net = _extract_mstrings_iocs(run["markdown"])
                for ioc in fs:
                    if ioc not in fs_iocs_seen:
                        fs_iocs_seen.add(ioc)
                        fs_iocs.append(ioc)
                for ioc in net:
                    if ioc not in net_iocs_seen:
                        net_iocs_seen.add(ioc)
                        net_iocs.append(ioc)
            if is_flagged and run.get("tool") == "tiquery" and run.get("success") and run.get("markdown"):
                for tag in _extract_tiquery_tags(run["markdown"]):
                    if tag not in malware_tags_seen:
                        malware_tags_seen.add(tag)
                        malware_tags.append(tag)
            if run.get("success") and run.get("markdown") and run.get("tool") in ("macho_info", "plist_analyzer", "codesign_check"):
                for flag_text in _extract_flags(run["tool"], run["markdown"]):
                    flag_findings.append((members[0]["filename"], run["tool"], flag_text))

    lines = [
        f"# MalChela Summary — {target}",
        "",
        f"Generated: {datetime.now().isoformat()}",
        f"Files analyzed: {len(per_file_results)}",
    ]
    if extraction_note:
        lines.append(f"_{extraction_note}_")
    lines += [
        "",
        "## Triage Summary",
        "",
    ]
    if len(order) != len(per_file_results):
        lines.append(
            f"- **{len(order)} unique file(s)** across {len(per_file_results)} path(s) "
            f"({len(per_file_results) - len(order)} duplicate instance(s) collapsed below)"
        )
    else:
        lines.append(f"- **{len(order)} file(s)** analyzed")
    if flagged:
        lines.append(f"- **⚠ {len(flagged)} flagged malicious** (VirusTotal): " + ", ".join(f"`{n}`" for n in flagged))
    else:
        lines.append("- No files flagged malicious by VirusTotal")
    if malware_tags:
        lines.append("- **Malware tags** (tiquery): " + ", ".join(f"`{t}`" for t in malware_tags))
    if mitre_total:
        by_tactic = sorted(mitre_tactics.items(), key=lambda kv: kv[1], reverse=True)
        breakdown = ", ".join(f"{t} ({c})" for t, c in by_tactic)
        lines.append(f"- **{mitre_total} MITRE ATT&CK finding(s)** (mstrings), by tactic: {breakdown}")
    if fs_iocs:
        lines.append("- **Filesystem IOCs** (mstrings): " + ", ".join(f"`{i}`" for i in fs_iocs))
    if net_iocs:
        lines.append("- **Network IOCs** (mstrings): " + ", ".join(f"`{i}`" for i in net_iocs))
    if flag_findings:
        flagged_files = len({f[0] for f in flag_findings})
        lines.append(f"- **{len(flag_findings)} flag(s)/indicator(s)** across {flagged_files} file(s):")
        for filename, tool, text in flag_findings:
            lines.append(f"  - `{filename}` ({tool}): {text}")
    for members in dup_groups:
        names = ", ".join(f"`{m['filename']}`" for m in members)
        lines.append(f"- **Duplicate content:** {names} share SHA256 `{members[0]['sha256']}`")
    lines.append("")

    for key in order:
        members = groups[key]
        primary = members[0]
        lines.append(f"## {primary['filename']}")
        lines.append("")
        if len(members) > 1:
            other_names = ", ".join(f"`{m['filename']}`" for m in members[1:])
            lines.append(f"- **Also found as:** {other_names} — identical content, tool output shown once")
        lines.append(f"- **Path:** `{primary['filepath']}`")
        lines.append(f"- **Type:** {primary['filetype']}")
        if primary["sha256"]:
            lines.append(f"- **SHA256:** `{primary['sha256']}`")
        if primary["md5"]:
            lines.append(f"- **MD5:** `{primary['md5']}`")
        lines.append("")

        if not primary["tool_runs"]:
            lines.append("_No suggested tools for this file type._")
            lines.append("")
            continue

        for run in primary["tool_runs"]:
            status = "✓" if run["success"] else "✕"
            lines.append(f"### {status} {run['label']} (`{run['tool']}`)")
            lines.append("")
            if run["success"]:
                if run.get("markdown"):
                    lines.append(_demote_markdown_headings(run["markdown"]))
                else:
                    # Fallback for the rare case the .md read-back came up empty
                    # (tool didn't actually write one) — raw stdout, code-fenced.
                    lines.append("```")
                    lines.append(run["output"] or "(no output)")
                    lines.append("```")
            else:
                lines.append(f"**Error:** {run['error'] or 'Tool run failed.'}")
            lines.append("")

    return "\n".join(lines)


@app.route("/tools/hashit", methods=["POST"])
def hashit():
    """Generate MD5, SHA1, SHA256 hashes for a single file."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("hashit", args)
    if case_name and result.get("success"):
        _register_cli_case_output("hashit", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/hashcheck", methods=["POST"])
def hashcheck():
    """Check if a hash exists in a provided hash set file. Args: hashset hash"""
    data        = request.json or {}
    hash_value  = data.get("hash", "").strip()
    hashset     = safe_path(data.get("hashset", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not hash_value or not hashset:
        return jsonify({"success": False, "error": "Missing hash or hashset path"}), 400
    # CLI: hashcheck ./hashes.tsv <hash>  — hashset first, then hash
    args = [str(hashset), hash_value]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("hashcheck", args)
    if case_name and result.get("success"):
        _register_cli_case_output("hashcheck", case_name, hash_value, save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/malhash", methods=["POST"])
def malhash():
    """Query a hash against VirusTotal and MalwareBazaar."""
    data = request.json or {}
    hash_value = data.get("hash", "").strip()
    if not hash_value:
        return jsonify({"success": False, "error": "Missing hash"}), 400
    return jsonify(run_binary("malhash", [hash_value]))


@app.route("/tools/mstrings", methods=["POST"])
def mstrings():
    """Extract strings, map to MITRE ATT&CK, identify IOCs."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("mstrings", args, timeout=180)
    if case_name and result.get("success"):
        _register_cli_case_output("mstrings", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/plist_analyzer", methods=["POST"])
def plist_analyzer():
    """Parse macOS .plist files and .app bundle Info.plist for malware indicators."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("plist_analyzer", args)
    if case_name and result.get("success"):
        _register_cli_case_output("plist_analyzer", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/macho_info", methods=["POST"])
def macho_info():
    """Parse Mach-O binary: architecture, linked libraries, sections with entropy, stripped symbols."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("macho_info", args)
    if case_name and result.get("success"):
        _register_cli_case_output("macho_info", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/codesign_check", methods=["POST"])
def codesign_check():
    """Inspect macOS code signing: signature type, team ID, entitlements, ad-hoc/unsigned detection."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("codesign_check", args)
    if case_name and result.get("success"):
        _register_cli_case_output("codesign_check", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/fileminer/session", methods=["POST"])
def fileminer_session_save():
    """Create or update a FileMiner session JSON with the current rows and executed-tool list."""
    data          = request.json or {}
    case_name     = _sanitize_case_name(data.get("case_name", "").strip()) or ""
    analyzed_path = data.get("analyzed_path", "")
    rows          = data.get("rows", [])
    executed      = data.get("executed", [])

    if case_name:
        session_dir = MALCHELA_ROOT / "saved_output" / "cases" / case_name / "fileminer"
    else:
        session_dir = MALCHELA_ROOT / "saved_output" / "fileminer"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_path = session_dir / "session.json"

    now = datetime.utcnow().isoformat() + "Z"
    # Preserve original creation timestamp if the file already exists
    created = now
    if session_path.exists():
        try:
            existing = json.loads(session_path.read_text())
            created = existing.get("created", now)
        except Exception:
            pass

    payload = {
        "analyzed_path": analyzed_path,
        "case":          case_name or None,
        "created":       created,
        "last_updated":  now,
        "rows":          rows,
        "executed":      executed,
    }
    session_path.write_text(json.dumps(payload, indent=2))
    rel = str(session_path.relative_to(MALCHELA_ROOT))
    return jsonify({"success": True, "path": rel})


@app.route("/tools/fileminer/session", methods=["GET"])
def fileminer_session_load():
    """Load a FileMiner session JSON by its path on disk."""
    path_str = request.args.get("path", "").strip()
    if not path_str:
        return jsonify({"success": False, "error": "No path specified"})
    # Resolve relative paths against MALCHELA_ROOT (the save route returns relative paths)
    candidate = Path(path_str) if Path(path_str).is_absolute() else MALCHELA_ROOT / path_str
    session_path = safe_path(str(candidate))
    if not session_path or not session_path.exists():
        return jsonify({"success": False, "error": "Session file not found"})
    try:
        payload = json.loads(session_path.read_text())
        return jsonify({"success": True, "session": payload})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/tools/mzhash", methods=["POST"])
def mzhash():
    """Recursively hash MZ files. Supports algorithm selection and overwrite flag."""
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    algorithms = data.get("algorithms", [])  # list of "md5","sha1","sha256"
    overwrite   = data.get("overwrite", False)
    args = [str(path)]
    for algo in algorithms:
        args += ["-a", algo.lower()]
    if overwrite:
        args.append("--overwrite")
    return jsonify(run_binary("mzhash", args, timeout=300))


@app.route("/tools/mzcount", methods=["POST"])
def mzcount():
    """Recursively count files by format in a directory."""
    data        = request.json or {}
    path        = safe_path(data.get("path", ""))
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    # mzcount supports txt (-t) and md (-m) only; map json to md
    if save_format not in ("txt", "md"):
        save_format = "md"
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    args = [str(path)]
    if case_name:
        fmt_flag = "-t" if save_format == "txt" else "-m"
        args += ["-o", fmt_flag, "--case", case_name]
    result = run_binary("mzcount", args)
    if case_name and result.get("success"):
        _register_cli_case_output("mzcount", case_name, str(path), save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/xmzhash", methods=["POST"])
def xmzhash():
    """Recursively hash non-MZ/ZIP/PDF files. Supports algorithm selection and overwrite."""
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    algorithms = data.get("algorithms", [])
    overwrite   = data.get("overwrite", False)
    args = [str(path)]
    for algo in algorithms:
        args += ["-a", algo.lower()]
    if overwrite:
        args.append("--overwrite")
    return jsonify(run_binary("xmzhash", args, timeout=300))


@app.route("/tools/nsrlquery", methods=["POST"])
def nsrlquery():
    """Query an MD5 hash against the NSRL database."""
    data        = request.json or {}
    hash_value  = data.get("hash", "").strip()
    case_name   = data.get("case_name", "").strip()
    save_format = data.get("save_format", "md").lower()
    if save_format not in _FMT_FLAG:
        save_format = "md"
    if not hash_value:
        return jsonify({"success": False, "error": "Missing hash"}), 400
    args = [hash_value]
    if case_name:
        args += ["-o", _FMT_FLAG[save_format], "--case", case_name]
    result = run_binary("nsrlquery", args)
    if case_name and result.get("success"):
        _register_cli_case_output("nsrlquery", case_name, hash_value, save_format)
        result["saved_to_case"] = True
    return jsonify(result)


@app.route("/tools/combine_yara", methods=["POST"])
def combine_yara():
    """Combine all YARA rules in a directory into a single file."""
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    return jsonify(run_binary("combine_yara", [str(path)]))


@app.route("/tools/extract_samples", methods=["POST"])
def extract_samples():
    """Extract password-protected malware archives. Args: path [password]"""
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    password = data.get("password", "").strip()
    args = [str(path)]
    if password:
        args.append(password)
    return jsonify(run_binary("extract_samples", args))


@app.route("/tools/strings_to_yara", methods=["POST"])
def strings_to_yara():
    """
    Generate a YARA rule from a strings file.
    Supports two modes:
      - File mode: strings_file path (existing file on server)
      - Paste mode: strings array (server writes a temp file)
    Optional: copy_to_yara_rules=true copies the .yar to yara_rules/ for use by fileanalyzer.
    CLI: strings_to_yara RuleName Author Description Hash /path/to/strings.txt
    """
    import tempfile
    data             = request.json or {}
    rule_name        = data.get("rule_name", "").strip()
    author           = data.get("author", "").strip()
    description      = data.get("description", "").strip()
    hash_val         = data.get("hash", "").strip()
    strings_file_path = data.get("strings_file", "")
    strings_list     = data.get("strings", [])
    copy_to_rules    = data.get("copy_to_yara_rules", False)

    if not rule_name:
        return jsonify({"success": False, "error": "rule_name is required"}), 400
    rule_name_safe = re.sub(r'[^\w\-.]', '_', rule_name)[:64]

    temp_file = None

    if strings_list:
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.txt', dir=str(UPLOADS_DIR),
                prefix=f'yara_strings_{rule_name}_', delete=False
            )
            tmp.write('\n'.join(strings_list))
            tmp.close()
            strings_file = Path(tmp.name)
            temp_file = strings_file
        except Exception as e:
            return jsonify({"success": False, "error": f"Could not write temp strings file: {_safe_error(e)}"}), 500
    elif strings_file_path:
        strings_file = safe_path(strings_file_path)
        if not strings_file:
            return jsonify({"success": False, "error": "strings_file path is required"}), 400
        if not strings_file.exists():
            return jsonify({"success": False, "error": f"Strings file not found: {strings_file}"}), 404
    else:
        return jsonify({"success": False, "error": "Provide strings_file path or strings array"}), 400

    args = [rule_name, author or "", description or "", hash_val or "", str(strings_file)]
    result = run_binary("strings_to_yara", args, timeout=30)

    # Clean up temp file
    if temp_file and temp_file.exists():
        try:
            temp_file.unlink()
        except Exception:
            pass

    # Optionally copy generated .yar to yara_rules/ so fileanalyzer picks it up
    if result.get("success") and copy_to_rules:
        yar_name = f"{rule_name_safe}.yar"
        # strings_to_yara writes to saved_output/strings_to_yara/ — find it
        yar_src = OUTPUT_DIR / "strings_to_yara" / yar_name
        if not yar_src.exists():
            # Try alternate naming
            yar_src = OUTPUT_DIR / "strings_to_yara" / f"{rule_name_safe}.yara"
        if yar_src.exists():
            YARA_DIR.mkdir(parents=True, exist_ok=True)
            dest = YARA_DIR / yar_src.name
            shutil.copy2(str(yar_src), str(dest))
            result["copied_to_yara_rules"] = str(dest)
        else:
            result["copy_warning"] = f"Could not find {yar_name} in saved_output/strings_to_yara/ to copy"

    return jsonify(result)


@app.route("/tools/tiquery", methods=["POST"])
def tiquery():
    """Threat Intel Query — multi-source hash or URL lookup."""
    data = request.json or {}
    hash_val   = data.get("hash", "").strip()
    url_val    = data.get("url", "").strip()
    bulk_path  = safe_path(data.get("bulk", "")) if data.get("bulk") else None
    qr_path    = safe_path(data.get("qr", "")) if data.get("qr") else None
    sources    = data.get("sources", "").strip()
    output_fmt = data.get("output_fmt", "").strip()

    args = []
    timeout = 120

    if qr_path:
        if not qr_path.exists():
            return jsonify({"success": False, "error": f"QR image not found: {qr_path}"}), 404
        args = ["--qr", str(qr_path)]
    elif bulk_path:
        if not bulk_path.exists():
            return jsonify({"success": False, "error": f"Bulk file not found: {bulk_path}"}), 404
        args = ["--bulk", str(bulk_path)]
        timeout = 600
        # Count hashes for progress reporting
        try:
            lines = [l.strip() for l in bulk_path.read_text().splitlines() if l.strip()]
            _tiquery_progress["total"] = len(lines)
            _tiquery_progress["done"]  = 0
            _tiquery_progress["running"] = True
        except Exception:
            pass
    elif hash_val:
        args = [hash_val]
    elif url_val:
        args = [url_val]
    else:
        return jsonify({"success": False, "error": "Provide hash, url, bulk, or qr path"}), 400

    download    = data.get("download", False)
    verbose_vt  = data.get("verbose_vt", False)

    if download:
        args.append("--download")
    if verbose_vt:
        args.append("--verbose-vt")

    if sources:
        args += ["--sources", sources]

    if output_fmt in ("json", "csv"):
        args.append(f"--{output_fmt}")

    # Run — for bulk mode track progress by watching stderr line count
    if bulk_path:
        import threading
        result_holder = {}

        def run_and_track():
            binary_path = BINARY_DIR / "tiquery"
            if not binary_path.exists():
                result_holder['result'] = {"success": False, "error": "tiquery binary not found"}
                return
            try:
                proc = subprocess.Popen(
                    [str(binary_path)] + args,
                    cwd=str(MALCHELA_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout_lines = []
                stderr_lines = []

                # Read stdout, count result blocks to track progress
                for line in proc.stdout:
                    decoded = line.decode('utf-8', errors='replace')
                    stdout_lines.append(decoded)
                    # Each "tiquery <hash>" line = one hash completed
                    if decoded.strip().startswith('tiquery '):
                        _tiquery_progress["done"] += 1

                proc.wait(timeout=timeout)
                stderr_data = proc.stderr.read().decode('utf-8', errors='replace')
                stdout = _strip_cli_noise(''.join(stdout_lines).strip())
                result_holder['result'] = {
                    "success": True,
                    "output": stdout,
                    "stderr": stderr_data.strip(),
                    "returncode": proc.returncode,
                }
            except subprocess.TimeoutExpired:
                proc.kill()
                result_holder['result'] = {"success": False, "error": "tiquery timed out"}
            except Exception as e:
                result_holder['result'] = {"success": False, "error": _safe_error(e)}
            finally:
                _tiquery_progress["running"] = False

        t = threading.Thread(target=run_and_track, daemon=True)
        t.start()
        t.join(timeout=timeout + 5)
        _tiquery_progress["running"] = False
        return jsonify(result_holder.get('result', {"success": False, "error": "Unknown error"}))

    return jsonify(run_binary("tiquery", args, timeout=timeout))


# Shared progress state for bulk tiquery
_tiquery_progress = {"total": 0, "done": 0, "running": False}


@app.route("/tools/tiquery/progress", methods=["GET"])
def tiquery_progress():
    """Poll progress for bulk tiquery runs."""
    return jsonify(_tiquery_progress)


@app.route("/tools/mitre_lookup", methods=["POST"])
def mitre_lookup():
    """
    MITRE ATT&CK technique lookup by ID (e.g. T1027, T1027.004) or keyword.
    Optional: full=true for untruncated output.
    CLI: MITRE_lookup [--full] -- <query>
    """
    data  = request.json or {}
    query = data.get("query", "").strip()
    full  = data.get("full", False)

    if not query:
        return jsonify({"success": False, "error": "Query required"}), 400

    args = []
    if full:
        args.append("--full")
    args += ["--", query]

    return jsonify(run_binary("MITRE_lookup", args, timeout=30))


@app.route("/tools/check_output", methods=["POST"])
def check_output():
    """Check if a tool's saved_output directory already has files."""
    data = request.json or {}
    tool = data.get("tool", "").strip()
    if not tool or "/" in tool or ".." in tool:
        return jsonify({"success": False, "error": "Invalid tool name"}), 400
    tool_dir = OUTPUT_DIR / tool
    if not tool_dir.exists():
        return jsonify({"success": True, "exists": False, "file_count": 0})
    files = [f for f in tool_dir.iterdir() if f.is_file()]
    return jsonify({"success": True, "exists": len(files) > 0, "file_count": len(files), "path": str(tool_dir)})


@app.route("/tools/tshark", methods=["POST"])
def tshark():
    """
    Run TShark on a PCAP file.
    Supports: display filter (-Y), output format (-T), fields (-e),
              include headers (-E header=y), export objects (--export-objects),
              save decoded output (-w)
    """
    data           = request.json or {}
    pcap_path      = safe_path(data.get("pcap_path", ""))
    display_filter = data.get("display_filter", "").strip()
    output_type    = data.get("output_type", "text").strip()
    fields         = data.get("fields", [])
    include_headers= data.get("include_headers", False)
    export_objects = data.get("export_objects", False)
    export_protocol= data.get("export_protocol", "http").strip()
    extra_args     = data.get("extra_args", "").strip()
    case_name      = data.get("case_name", "").strip()

    if not pcap_path:
        return jsonify({"success": False, "error": "PCAP path required"}), 400
    if not pcap_path.exists():
        return jsonify({"success": False, "error": f"File not found: {pcap_path}"}), 404

    tshark_bin = find_tool("tshark")
    if not tshark_bin:
        return jsonify({"success": False, "error": "TShark not found. Install Wireshark/TShark or add to tool_paths"}), 404

    args = ["-r", str(pcap_path)]

    if export_objects:
        # Route to case folder if case is active, else saved_output/tshark
        if case_name:
            export_dir = CASES_DIR / case_name / "tshark" / "exports" / export_protocol
        else:
            export_dir = OUTPUT_DIR / "tshark" / "exports" / export_protocol
        export_dir.mkdir(parents=True, exist_ok=True)
        args += ["--export-objects", f"{export_protocol},{str(export_dir)}"]
    else:
        if display_filter:
            args += ["-Y", display_filter]

        if output_type == "fields" and fields:
            args += ["-T", "fields"]
            for f in fields:
                args += ["-e", f]
            if include_headers:
                args += ["-E", "header=y"]
        elif output_type != "text":
            args += ["-T", output_type]

    if extra_args:
        import shlex as _shlex
        parsed = _shlex.split(extra_args)
        args.extend(a for a in parsed if _SAFE_ARG_RE.match(a))

    try:
        result = subprocess.run(
            [tshark_bin] + args,
            cwd=str(MALCHELA_ROOT),
            capture_output=True, text=True, timeout=300
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        # TShark writes progress to stderr — only include if there's a real error
        if result.returncode != 0 and stderr:
            return jsonify({"success": True, "output": stderr, "stderr": "", "returncode": result.returncode})
        return jsonify({"success": True, "output": stdout, "stderr": stderr, "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "TShark timed out after 300s"})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/vol3/plugins", methods=["GET"])
def get_vol3_plugins():
    """Return parsed vol3_plugins.yaml for the plugin picker."""
    if not VOL3_PLUGINS_YAML_PATH.exists():
        return jsonify({"success": False, "error": "vol3_plugins.yaml not found"}), 404
    try:
        with open(VOL3_PLUGINS_YAML_PATH) as f:
            data = yaml.safe_load(f) or {}
        return jsonify({"success": True, "plugins": data})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)}), 500


@app.route("/tools/vol3", methods=["POST"])
def run_vol3():
    """
    Run Volatility 3.
    CLI: vol3 -f <image> [--dump-dir <dir>] <plugin> [plugin_args]
    """
    data        = request.json or {}
    image_path  = safe_path(data.get("image_path", ""))
    plugin      = data.get("plugin", "").strip()
    plugin_args = data.get("plugin_args", {})
    dump_dir    = data.get("dump_dir", "").strip()
    case_name   = data.get("case_name", "").strip()
    extra_args  = data.get("extra_args", "").strip()

    if not image_path:
        return jsonify({"success": False, "error": "Memory image path required"}), 400
    if not image_path.exists():
        return jsonify({"success": False, "error": f"Image not found: {image_path}"}), 404
    if not plugin:
        return jsonify({"success": False, "error": "Plugin required"}), 400

    vol3 = find_tool("vol3")
    if not vol3:
        return jsonify({"success": False, "error": "vol3 not found. Add its directory to tool_paths in server_config.yaml"}), 404

    DUMP_PLUGINS = {"windows.dumpfiles", "windows.memdump", "windows.memmap",
                    "windows.ssdt", "windows.dlldump", "windows.moddump",
                    "windows.driverscan", "linux.memdump", "linux.dmesg"}

    resolved_dump_dir = None
    if plugin in DUMP_PLUGINS:
        if dump_dir:
            d = safe_path(dump_dir)
            if d:
                d.mkdir(parents=True, exist_ok=True)
                resolved_dump_dir = str(d)
        elif case_name:
            d = CASES_DIR / case_name / "vol3" / plugin
            d.mkdir(parents=True, exist_ok=True)
            resolved_dump_dir = str(d)
        else:
            d = OUTPUT_DIR / "vol3" / plugin
            d.mkdir(parents=True, exist_ok=True)
            resolved_dump_dir = str(d)

    args = ["-f", str(image_path)]

    if resolved_dump_dir:
        output_flag = "--output-dir" if plugin == "windows.memmap" else "--dump-dir"
        args += [output_flag, resolved_dump_dir]

    args.append(plugin)

    if plugin == "windows.memmap" and "dump" not in plugin_args:
        args.append("--dump")

    for arg_name, val in plugin_args.items():
        if not val or val == "false":
            continue
        clean_name = "--" + arg_name.lstrip("-")
        if val == "true":
            args.append(clean_name)
        else:
            args += [clean_name, str(val)]

    # Add extra args if provided (strip shell metacharacters)
    if extra_args:
        import shlex as _shlex
        parsed = _shlex.split(extra_args)
        args.extend(a for a in parsed if _SAFE_ARG_RE.match(a))

    try:
        result = subprocess.run(
            [vol3] + args,
            cwd=str(MALCHELA_ROOT),
            capture_output=True, text=True, timeout=600
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        output = stdout or stderr
        dump_info = f"\n\n[Output saved to: {resolved_dump_dir}]" if resolved_dump_dir else ""
        return jsonify({
            "success":    True,
            "output":     output + dump_info,
            "stderr":     stderr if stdout else "",
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "vol3 timed out after 600s"})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/tools/yarax", methods=["POST"])
def yarax():
    """
    Run YARA-X (yr) scan against a file or directory.
    CLI: yr scan [--recursive] [extra_args] <rules_path> <target_path>
    """
    data        = request.json or {}
    rules_path  = safe_path(data.get("rules_path", ""))
    target_path = safe_path(data.get("target_path", ""))
    recursive   = data.get("recursive", False)
    extra_args  = data.get("extra_args", "").strip()

    if not rules_path:
        return jsonify({"success": False, "error": "Rule file path required"}), 400
    if not target_path:
        return jsonify({"success": False, "error": "Target path required"}), 400
    if not rules_path.exists():
        return jsonify({"success": False, "error": f"Rule file not found: {rules_path}"}), 404
    if not target_path.exists():
        return jsonify({"success": False, "error": f"Target not found: {target_path}"}), 404

    yr = find_tool("yr")
    if not yr:
        return jsonify({"success": False, "error": "YARA-X (yr) not found. Add its directory to tool_paths in server_config.yaml"}), 404

    args = ["scan"]
    if recursive:
        args.append("--recursive")
    if extra_args:
        import shlex as _shlex
        parsed = _shlex.split(extra_args)
        args.extend(a for a in parsed if _SAFE_ARG_RE.match(a))
    args += [str(rules_path), str(target_path)]

    try:
        result = subprocess.run(
            [yr] + args,
            cwd=str(MALCHELA_ROOT),
            capture_output=True, text=True, timeout=300
        )
        stdout = _strip_cli_noise(result.stdout.strip())
        stderr = result.stderr.strip()
        return jsonify({"success": True, "output": stdout, "stderr": stderr, "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "YARA-X scan timed out after 300s"})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


def file_hash():
    """
    Compute SHA256 of a remote file — used by TI Query single hash Browse button.
    Returns the hash for populating the hash input field without uploading the file.
    """
    import hashlib
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    if not path.is_file():
        return jsonify({"success": False, "error": "Path is not a file"}), 400
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return jsonify({"success": True, "sha256": sha256.hexdigest(), "filename": path.name})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/api_keys", methods=["GET"])
def get_api_keys():
    """Return status of all API keys — whether each file exists and is non-empty."""
    keys = [
        # Tier 1
        {"id": "vt",  "name": "VirusTotal",        "file": "vt-api.txt",  "tier": 1},
        {"id": "mb",  "name": "MalwareBazaar",      "file": "mb-api.txt",  "tier": 1},
        {"id": "otx", "name": "AlienVault OTX",     "file": "otx-api.txt", "tier": 1},
        # Tier 2
        {"id": "md",  "name": "MetaDefender Cloud", "file": "md-api.txt",  "tier": 2},
        {"id": "mp",  "name": "Malpedia",            "file": "mp-api.txt",  "tier": 2},
        {"id": "ha",  "name": "Hybrid Analysis",     "file": "ha-api.txt",  "tier": 2},
        {"id": "mw",  "name": "MWDB",                "file": "mw-api.txt",  "tier": 2},
        {"id": "tr",  "name": "Triage",              "file": "tr-api.txt",  "tier": 2},
        {"id": "fs",  "name": "FileScan.IO",         "file": "fs-api.txt",  "tier": 2},
        {"id": "ms",  "name": "Malshare",            "file": "ms-api.txt",  "tier": 2},
        # URL Sources
        {"id": "url", "name": "urlscan.io",          "file": "url-api.txt", "tier": "url"},
        {"id": "gsb", "name": "Google Safe Browsing","file": "gsb-api.txt", "tier": "url"},
    ]

    result = []
    for key in keys:
        path = API_DIR / key["file"]
        configured = path.exists() and path.read_text().strip() != ""
        result.append({
            "id":         key["id"],
            "name":       key["name"],
            "file":       key["file"],
            "tier":       key["tier"],
            "configured": configured,
        })

    return jsonify({"success": True, "keys": result})


@app.route("/api_keys/<key_id>", methods=["GET"])
def get_api_key_value(key_id):
    """Return the actual value of a specific API key (for reveal)."""
    # Map id to filename
    file_map = {
        "vt": "vt-api.txt", "mb": "mb-api.txt", "otx": "otx-api.txt",
        "md": "md-api.txt", "mp": "mp-api.txt", "ha": "ha-api.txt",
        "mw": "mw-api.txt", "tr": "tr-api.txt", "fs": "fs-api.txt",
        "ms": "ms-api.txt", "url": "url-api.txt", "gsb": "gsb-api.txt",
    }
    filename = file_map.get(key_id)
    if not filename:
        return jsonify({"success": False, "error": "Unknown key ID"}), 404

    path = API_DIR / filename
    if not path.exists():
        return jsonify({"success": True, "value": ""})

    return jsonify({"success": True, "value": path.read_text().strip()})


@app.route("/api_keys/<key_id>", methods=["POST"])
def set_api_key(key_id):
    """Write a new value for a specific API key."""
    file_map = {
        "vt": "vt-api.txt", "mb": "mb-api.txt", "otx": "otx-api.txt",
        "md": "md-api.txt", "mp": "mp-api.txt", "ha": "ha-api.txt",
        "mw": "mw-api.txt", "tr": "tr-api.txt", "fs": "fs-api.txt",
        "ms": "ms-api.txt", "url": "url-api.txt", "gsb": "gsb-api.txt",
    }
    filename = file_map.get(key_id)
    if not filename:
        return jsonify({"success": False, "error": "Unknown key ID"}), 404

    data = request.json or {}
    value = data.get("value", "").strip()

    API_DIR.mkdir(parents=True, exist_ok=True)
    path = API_DIR / filename
    path.write_text(value + "\n" if value else "")

    return jsonify({"success": True, "configured": bool(value)})
def read_file():
    """Read any file within the browser jail — used by View Reports."""
    data = request.json or {}
    path = safe_path(data.get("path", ""))
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    if not path.is_file():
        return jsonify({"success": False, "error": "Not a file"}), 400
    try:
        content = path.read_text(errors='replace')
        return jsonify({"success": True, "content": content})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})

# ── Case Management ───────────────────────────────────────────────────────────

CASE_ARCHIVES_DIR = OUTPUT_DIR / "case_archives"

@app.route("/cases", methods=["GET"])
def list_cases():
    """List all existing cases with status."""
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    cases = []
    for case_dir in sorted(CASES_DIR.iterdir()):
        if case_dir.is_dir():
            yaml_file = case_dir / "case.yaml"
            meta = {}
            if yaml_file.exists():
                try:
                    with open(yaml_file) as f:
                        meta = yaml.safe_load(f) or {}
                except Exception:
                    pass
            all_files = [f for f in case_dir.rglob("*") if f.is_file() and f.name != "case.yaml"]
            cases.append({
                "name":        case_dir.name,
                "path":        str(case_dir),
                "created":     meta.get("created"),
                "description": meta.get("description"),
                "tags":        meta.get("tags", []),
                "status":      meta.get("status", "open"),
                "file_count":  len(all_files),
            })
    return jsonify({"success": True, "cases": cases})


@app.route("/cases", methods=["POST"])
def create_case():
    """Create a new case directory with case.yaml."""
    data = request.json or {}
    name = _sanitize_case_name(data.get("name", "").strip().replace(" ", "_"))
    if not name:
        return jsonify({"success": False, "error": "Case name is required"}), 400

    case_dir = CASES_DIR / name
    if case_dir.exists():
        return jsonify({"success": False, "error": "Case already exists"}), 409

    case_dir.mkdir(parents=True)
    case_meta = {
        "name":        name,
        "created":     datetime.now().isoformat(),
        "description": data.get("description", ""),
        "tags":        data.get("tags", []),
        "status":      "open",
        "files":       [],
        "notes":       "",
    }
    with open(case_dir / "case.yaml", "w") as f:
        yaml.dump(case_meta, f, default_flow_style=False)

    return jsonify({"success": True, "case": case_meta}), 201


@app.route("/cases/<case_name>", methods=["GET"])
def get_case(case_name):
    """Get case details including saved outputs."""
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404

    yaml_file = case_dir / "case.yaml"
    meta = {}
    if yaml_file.exists():
        with open(yaml_file) as f:
            meta = yaml.safe_load(f) or {}

    outputs = []
    for f in sorted(case_dir.rglob("*")):
        if f.is_file() and f.name != "case.yaml":
            rel = f.relative_to(case_dir)
            outputs.append({
                "filename":     f.name,
                "display_name": str(rel),
                "path":         str(f),
                "size":         f.stat().st_size,
                "modified":     datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })

    return jsonify({"success": True, "case": meta, "outputs": outputs})


@app.route("/cases/<case_name>", methods=["PATCH"])
def update_case(case_name):
    """Update case metadata (description, tags, status)."""
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404

    yaml_file = case_dir / "case.yaml"
    meta = {}
    if yaml_file.exists():
        with open(yaml_file) as f:
            meta = yaml.safe_load(f) or {}

    data = request.json or {}
    for field in ["notes", "tags", "description", "status"]:
        if field in data:
            meta[field] = data[field]
    meta["modified"] = datetime.now().isoformat()

    with open(yaml_file, "w") as f:
        yaml.dump(meta, f, default_flow_style=False)

    return jsonify({"success": True, "case": meta})


@app.route("/cases/<case_name>/delete", methods=["POST"])
def delete_case(case_name):
    """Permanently delete a case directory."""
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404
    try:
        shutil.rmtree(str(case_dir))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/cases/<case_name>/archive", methods=["POST"])
def archive_case(case_name):
    """Zip a case to saved_output/case_archives/ and return path info for optional download."""
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404

    CASE_ARCHIVES_DIR.mkdir(parents=True, exist_ok=True)
    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_stem = CASE_ARCHIVES_DIR / f"{case_name}_{timestamp}"
    try:
        zip_path = Path(shutil.make_archive(str(archive_stem), "zip", str(CASES_DIR), case_name))
        return jsonify({
            "success":  True,
            "filename": zip_path.name,
            "path":     str(zip_path),
        })
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/cases/<case_name>/archive/download", methods=["GET"])
def download_archive(case_name):
    """Serve a previously created case archive zip for download."""
    filename = request.args.get("file", "").strip()
    if not filename or ".." in filename or "/" in filename:
        return jsonify({"success": False, "error": "Invalid filename"}), 400
    zip_path = CASE_ARCHIVES_DIR / filename
    if not zip_path.exists():
        return jsonify({"success": False, "error": "Archive not found"}), 404
    return send_from_directory(
        str(CASE_ARCHIVES_DIR),
        filename,
        as_attachment=True,
        download_name=filename,
    )


@app.route("/cases/import", methods=["POST"])
def import_case():
    """
    Import a case from a zip file on the server filesystem.
    Expects: { "path": "/absolute/path/to/case_archive.zip", "overwrite": false }
    """
    data      = request.json or {}
    zip_path  = safe_path(data.get("path", ""))
    overwrite = data.get("overwrite", False)

    if not zip_path or not zip_path.exists():
        return jsonify({"success": False, "error": "Zip file not found"}), 404
    if not zip_path.suffix == ".zip":
        return jsonify({"success": False, "error": "File must be a .zip archive"}), 400

    import zipfile as _zipfile
    try:
        with _zipfile.ZipFile(str(zip_path), "r") as zf:
            # Detect case name from top-level folder in zip
            top_dirs = {Path(n).parts[0] for n in zf.namelist() if n}
            if len(top_dirs) != 1:
                return jsonify({"success": False, "error": "Zip must contain exactly one top-level case folder"}), 400
            case_name = top_dirs.pop()
            dest = CASES_DIR / case_name
            if dest.exists():
                if not overwrite:
                    return jsonify({"success": False, "error": f"Case '{case_name}' already exists", "conflict": True, "case_name": case_name}), 409
                shutil.rmtree(str(dest))
            zf.extractall(str(CASES_DIR))
        return jsonify({"success": True, "case_name": case_name})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/cases/archives", methods=["GET"])
def list_archives():
    """List available case archives for import."""
    CASE_ARCHIVES_DIR.mkdir(parents=True, exist_ok=True)
    archives = []
    for f in sorted(CASE_ARCHIVES_DIR.glob("*.zip"), reverse=True):
        archives.append({
            "filename": f.name,
            "path":     str(f),
            "size":     f.stat().st_size,
            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
        })
    return jsonify({"success": True, "archives": archives})

@app.route("/cases/<case_name>/save", methods=["POST"])
def save_to_case(case_name):
    """
    Save tool output to a case.
    Supports format: txt (default), json, md
    Structure: cases/<case_name>/<tool>/report_<timestamp>.<ext>
    """
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404

    data   = request.json or {}
    tool   = data.get("tool", "unknown")
    output = data.get("output", "")
    target = data.get("target", "")
    fmt    = data.get("format", "txt").lower().strip(".")
    if fmt not in ("txt", "json", "md"):
        fmt = "txt"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tool_dir  = case_dir / tool
    tool_dir.mkdir(parents=True, exist_ok=True)
    filename  = f"report_{timestamp}.{fmt}"
    filepath  = tool_dir / filename
    rel_path  = f"{tool}/{filename}"

    clean_output = _strip_color_tags(output)
    if fmt == "json":
        import json as json_mod
        content = json_mod.dumps({
            "tool": tool, "target": target,
            "timestamp": timestamp, "output": clean_output
        }, indent=2)
    elif fmt == "md":
        tool_title = tool.replace("_", " ").title()
        content = (
            f"# {tool_title} Report\n\n"
            f"| Field | Value |\n|-------|-------|\n"
            f"| Target | `{target}` |\n"
            f"| Tool | {tool} |\n"
            f"| Timestamp | {timestamp} |\n\n"
            f"---\n\n"
            f"```\n{clean_output}\n```\n"
        )
    else:
        content = f"Tool: {tool}\nTarget: {target}\nTimestamp: {timestamp}\n{'─'*60}\n{clean_output}\n"

    filepath.write_text(content)

    # Update case.yaml
    yaml_file = case_dir / "case.yaml"
    if yaml_file.exists():
        with open(yaml_file) as f:
            meta = yaml.safe_load(f) or {}
        files = meta.get("files", [])
        files.append({"filename": filename, "path": rel_path,
                      "tool": tool, "target": target, "timestamp": timestamp})
        meta["files"] = files
        meta["modified"] = datetime.now().isoformat()
        with open(yaml_file, "w") as f:
            yaml.dump(meta, f, default_flow_style=False)

    return jsonify({"success": True, "filename": rel_path})


@app.route("/cases/search", methods=["POST"])
def search_cases():
    """
    Full-text search across all cases — metadata and saved output file contents.
    Returns cases with matches, including which files matched and snippets.
    """
    data  = request.json or {}
    query = data.get("query", "").strip().lower()
    if not query:
        return jsonify({"success": False, "error": "Query required"}), 400

    results = []

    for case_dir in sorted(CASES_DIR.iterdir()):
        if not case_dir.is_dir():
            continue

        case_name = case_dir.name
        yaml_file = case_dir / "case.yaml"
        meta = {}
        if yaml_file.exists():
            try:
                with open(yaml_file) as f:
                    meta = yaml.safe_load(f) or {}
            except Exception:
                pass

        matched_files = []
        meta_match = (
            query in case_name.lower() or
            query in (meta.get("description") or "").lower() or
            any(query in t.lower() for t in meta.get("tags", []))
        )

        # Search inside all output files
        for f in sorted(case_dir.rglob("*")):
            if not f.is_file() or f.name == "case.yaml":
                continue
            try:
                content = f.read_text(errors='replace')
                if query in content.lower():
                    # Find snippet around first match
                    idx = content.lower().find(query)
                    start = max(0, idx - 60)
                    end   = min(len(content), idx + len(query) + 60)
                    snippet = content[start:end].replace('\n', ' ').strip()
                    if start > 0: snippet = '…' + snippet
                    if end < len(content): snippet = snippet + '…'
                    matched_files.append({
                        "display_name": str(f.relative_to(case_dir)),
                        "path": str(f.relative_to(case_dir)),
                        "snippet": snippet,
                    })
            except Exception:
                continue

        if meta_match or matched_files:
            results.append({
                "name":        case_name,
                "description": meta.get("description", ""),
                "tags":        meta.get("tags", []),
                "created":     meta.get("created", ""),
                "meta_match":  meta_match,
                "file_matches": matched_files,
                "match_count": len(matched_files),
            })

    return jsonify({"success": True, "results": results, "query": query})
def get_case_notes(case_name):
    """Get case notes file list for Notebook save-to-case browser."""
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404
    notes_files = sorted(case_dir.glob("*.md")) + sorted(case_dir.glob("notes*.txt"))
    return jsonify({"success": True, "files": [str(f.relative_to(case_dir)) for f in notes_files]})


@app.route("/cases/<case_name>/notes/append", methods=["POST"])
def append_case_notes(case_name):
    """
    Append notebook content to a case notes file.
    Creates notes.md if no filename specified.
    """
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    if not case_dir.exists():
        return jsonify({"success": False, "error": "Case not found"}), 404

    data     = request.json or {}
    content  = data.get("content", "")
    filename = data.get("filename", "notes.md").strip()

    # Safety — only allow simple filenames, no path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"success": False, "error": "Invalid filename"}), 400

    filepath  = case_dir / filename
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Append with timestamp separator
    separator = f"\n\n---\n*Appended {timestamp}*\n\n"
    existing  = filepath.read_text() if filepath.exists() else ""
    filepath.write_text(existing + (separator if existing else "") + content)

    return jsonify({"success": True, "filename": filename})


@app.route("/notebook/save", methods=["POST"])
def notebook_save():
    """Save notebook content to an arbitrary path within the browser jail."""
    data    = request.json or {}
    path    = safe_path(data.get("path", ""))
    content = data.get("content", "")
    if not path:
        return jsonify({"success": False, "error": "Invalid or missing path"}), 400
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return jsonify({"success": True, "path": str(path)})
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)})


@app.route("/cases/<case_name>/output", methods=["GET"])
def get_case_output(case_name):
    """
    Read a saved output file from a case.
    Accepts path as query param to support subdirectory paths e.g. tiquery/report_xyz.txt
    """
    case_dir = CASES_DIR / case_name
    try:
        case_dir.resolve().relative_to(CASES_DIR.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid case name"}), 400
    filename = request.args.get("path", "")
    if not filename:
        return jsonify({"success": False, "error": "Missing path parameter"}), 400

    filepath = (case_dir / filename).resolve()

    # Jail check — ensure path stays within the case directory
    try:
        filepath.relative_to(case_dir.resolve())
    except ValueError:
        return jsonify({"success": False, "error": "Invalid path"}), 403

    if not filepath.exists():
        return jsonify({"success": False, "error": "File not found"}), 404

    try:
        content = filepath.read_text(errors='replace')
    except Exception as e:
        return jsonify({"success": False, "error": _safe_error(e)}), 500

    return jsonify({"success": True, "content": content})


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    errors = []
    if not MALCHELA_ROOT.exists():
        errors.append(f"  malchela_root not found: {MALCHELA_ROOT}")
    if not BINARY_DIR.exists():
        errors.append(f"  binary dir not found: {BINARY_DIR}")
    if not BROWSER_ROOT.exists():
        errors.append(f"  browser_root not found: {BROWSER_ROOT}")
    if errors:
        print("[MalChela Server] ERROR — configuration problems detected:")
        for e in errors:
            print(e)
        print("[MalChela Server] Check server_config.yaml and retry.")
        sys.exit(1)

    print(f"[MalChela Server] ─────────────────────────────────────")
    print(f"[MalChela Server] Server dir    : {_SCRIPT_DIR}")
    print(f"[MalChela Server] MalChela root : {MALCHELA_ROOT}")
    print(f"[MalChela Server] Binaries      : {BINARY_DIR}")
    print(f"[MalChela Server] Browser jail  : {BROWSER_ROOT}")
    print(f"[MalChela Server] Cases dir     : {CASES_DIR}")
    print(f"[MalChela Server] Vol3 plugins   : {VOL3_PLUGINS_YAML_PATH}")
    print(f"[MalChela Server] Presets       : {_SCRIPT_DIR / 'presets'}")
    print(f"[MalChela Server] Icons         : {_SCRIPT_DIR / 'icons'}")
    print(f"[MalChela Server] Backups       : {TOOLS_YAML_BACKUP_DIR}")
    print(f"[MalChela Server] Port          : {PORT}")
    print(f"[MalChela Server] ─────────────────────────────────────")
    print(f"[MalChela Server] Starting — http://0.0.0.0:{PORT}")
    print(f"[MalChela Server] Health check  : http://0.0.0.0:{PORT}/health")
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)  # Suppress the dev server warning
    app.run(host="0.0.0.0", port=PORT, debug=False)
