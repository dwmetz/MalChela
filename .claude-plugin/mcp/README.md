## Prerequisites

Before installing the MalChela Claude Code plugin, the following must be in place
on your local machine:

### 1. Clone and build MalChela
```bash
git clone https://github.com/dwmetz/MalChela.git
cd MalChela
./release.sh
```
This compiles all MalChela tools to `target/release/`. Requires Rust, YARA, and
platform dependencies — see the main [MalChela README](https://github.com/dwmetz/MalChela#readme)
for full build requirements.

### 2. Set MALCHELA_DIR
Set the environment variable to the root of your local MalChela installation:

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export MALCHELA_DIR=/path/to/MalChela
```

### 3. Configure API keys
Place your API key files in `$MALCHELA_DIR/api/`. All keys are optional but
required for their respective lookups:

**Hash Sources — Tier 1**

| File | Service |
|------|---------|
| `vt-api.txt` | VirusTotal |
| `mb-api.txt` | MalwareBazaar |
| `otx-api.txt` | AlienVault OTX |

**Hash Sources — Tier 2**

| File | Service |
|------|---------|
| `md-api.txt` | MetaDefender Cloud |
| `mp-api.txt` | Malpedia |
| `ha-api.txt` | Hybrid Analysis |
| `mw-api.txt` | MWDB |
| `tr-api.txt` | Triage |
| `fs-api.txt` | FileScan.IO |
| `ms-api.txt` | Malshare |
| `iq-api.txt` | InQuest Labs |

**URL Sources**

| File | Service |
|------|---------|
| `url-api.txt` | urlscan.io |
| `gsb-api.txt` | Google Safe Browsing |

MalChela will prompt you on first run if a required key is missing.

### 4. Install the plugin

**Via Anthropic community marketplace:**
```bash
claude plugin marketplace add anthropics/claude-plugins-community
claude plugin install malchela@claude-community
```

**Via self-hosted marketplace:**
```bash
claude plugin marketplace add dwmetz/MalChela
claude plugin install malchela@malchela-marketplace
```

---

# MalChela MCP Server

This directory contains the Node.js MCP (Model Context Protocol) server that exposes MalChela's malware analysis tools directly to Claude Desktop. Once configured, Claude has persistent, structured access to MalChela's full analysis suite without any manual briefing or context-pasting each session.

For background on how this fits into the broader MalChela + AI workflow, see the [Baker Street Forensics blog](https://bakerstreetforensics.com).

---

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or later
- MalChela built from source (`cargo build --release` run from the MalChela root)
- API keys configured (see below)
- [Claude Desktop](https://claude.ai/download)

---

## API Key Setup

MalChela reads API keys from plain text files in the `api/` subdirectory of the MalChela project root. All keys are optional but required for their respective lookups. These files are excluded from version control via `.gitignore`.

**Hash Sources — Tier 1**

| File | Service |
|---|---|
| `vt-api.txt` | [VirusTotal](https://www.virustotal.com) |
| `mb-api.txt` | [MalwareBazaar](https://bazaar.abuse.ch) |
| `otx-api.txt` | [AlienVault OTX](https://otx.alienvault.com) |

**Hash Sources — Tier 2**

| File | Service |
|---|---|
| `md-api.txt` | [MetaDefender Cloud](https://metadefender.opswat.com) |
| `mp-api.txt` | [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) |
| `ha-api.txt` | [Hybrid Analysis](https://hybrid-analysis.com) |
| `mw-api.txt` | [MWDB](https://mwdb.cert.pl) |
| `tr-api.txt` | [Triage](https://tria.ge) |
| `fs-api.txt` | [FileScan.IO](https://www.filescan.io) |
| `ms-api.txt` | [Malshare](https://malshare.com) |
| `iq-api.txt` | [InQuest Labs](https://labs.inquest.net) |

**URL Sources**

| File | Service |
|---|---|
| `url-api.txt` | [urlscan.io](https://urlscan.io) |
| `gsb-api.txt` | [Google Safe Browsing](https://safebrowsing.google.com) |

The easiest way to configure keys is via MalChela's built-in config tool:

```bash
cd /path/to/MalChela
cargo run -p config
```

Alternatively, create them manually:

```bash
echo "your-api-key" > /path/to/MalChela/api/vt-api.txt
```

---

## Installation

```bash
cd /path/to/MalChela/mcp
npm install
```

---

## Claude Desktop Configuration

Merge the relevant block from `example_config.json` into your Claude Desktop configuration file.

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

Open `example_config.json` in this directory and update the paths to match your system, then copy the block into your Claude Desktop config. If you already have other MCP servers configured, add the `malchela` entry alongside them — do not replace the entire file.

After saving, restart Claude Desktop. The MalChela tools will appear in Claude's tool list automatically.

---

## Available Tools

Once configured, the following MalChela tools are available to Claude — 17 map 1:1 to a compiled MalChela binary, plus two MCP-only tools with no binary of their own: `set_case` (session state) and `analyze` (an orchestrator that shells out to the other 17 in sequence). Unlike the PWA, the MCP server uses a **mandatory case model** — call `set_case` once at the start of a session before running any other tool; every subsequent tool's output is saved to that case automatically.

**Case Management**

| Tool | Description |
|---|---|
| `set_case` | Set (or create) the active investigation case for the session. All later tool output is saved to it automatically. Call this first. |

**File Analysis**

| Tool | Description |
|---|---|
| `fileanalyzer` | Hashes, entropy, packing detection, PE metadata, YARA rule matches, and VirusTotal status. Best first step for any unknown file. |
| `fileminer` | Scans a folder for file type mismatches and metadata anomalies; suggests follow-up tools per file. Entry point for an unknown directory or sample set. |
| `analyze` | One-shot auto-triage: runs `fileminer` against a file, folder, `.app` bundle, `.dmg`, or `.pkg`, then automatically dispatches every tool `fileminer` suggests, producing a combined rollup report. `.dmg`/`.pkg` targets are auto-unwrapped via `dpp_extract` first. Requires an active case (`set_case` first). |

**Strings Analysis**

| Tool | Description |
|---|---|
| `mstrings` | String extraction with IOC detection and MITRE ATT&CK mapping via Sigma-style rules. Supports macOS Mach-O binaries and `.app` bundles (main executable auto-resolved). |

**Threat Intel**

| Tool | Description |
|---|---|
| `tiquery` | Multi-source hash lookup across MalwareBazaar, VirusTotal, AlienVault OTX, and InQuest Labs — combined results matrix with detections, families, and source links. |
| `nsrlquery` | Checks a hash (MD5 or SHA1) against the NIST NSRL known-good database. |

**Hashing Tools**

| Tool | Description |
|---|---|
| `hashit` | Generates MD5, SHA1, and SHA256 hashes for a single file. |
| `hashcheck` | Checks a hash against a local lookup file of known hashes. |
| `mzhash` | Recursively hashes files with MZ headers (Windows PE/DLL) — one hash file per algorithm plus a path lookup table. |
| `xmzhash` | Like `mzhash` but inverted — hashes files that do *not* have MZ, ZIP, or PDF headers (Linux/Mac/unusual samples). |
| `mzcount` | Counts and summarizes file types within a directory for quick triage. |

**YARA Tools**

| Tool | Description |
|---|---|
| `strings_to_yara` | Converts a text file of extracted strings into a formatted YARA rule draft. Typically used after `mstrings`. |
| `combine_yara` | Merges multiple YARA rule files from a folder into a single consolidated ruleset. |

**Mac Analysis**

| Tool | Description |
|---|---|
| `plist_analyzer` | Parses `.plist` files and `.app` bundle `Info.plist` for malware indicators: hidden background agent, ATS disabled, custom URL schemes, env injection, and more. |
| `macho_info` | Parses Mach-O binaries: architecture, PIE/ASLR status, linked libraries, RPATH entries, section entropy, symbol status, and deprecated crypto library detection. |
| `codesign_check` | Inspects macOS code signing: Developer-signed vs. ad-hoc vs. unsigned, Team ID, Bundle ID, entitlements, and the `get-task-allow` flag. |

**Utilities**

| Tool | Description |
|---|---|
| `extract_samples` | Extracts password-protected malware archives (ZIP/RAR) using common passwords. |
| `dpp_extract` | Unwraps a `.dmg` or `.pkg` container (UDIF → HFS+/APFS → XAR → PBZX/CPIO) to reach the real payload files inside, including PKG Scripts archives. `analyze` calls this automatically for `.dmg`/`.pkg` targets. |

### Recommended analysis workflow

For initial triage of an unknown file, ask Claude to run the tools in this order:

1. `set_case` — create or select the case everything below will be saved to
2. `fileanalyzer` — establish baseline: hashes, entropy, PE headers, initial VT verdict
3. `mstrings` — extract strings, surface IOCs and ATT&CK technique indicators
4. `tiquery` — pull full community threat intel with AV verdicts
5. `nsrlquery` — confirm or rule out known-good status

Or skip the manual sequencing entirely and let `analyze` do it in one call.

You don't need to invoke these individually — just describe what you want to Claude:

> "Analyze /path/to/suspicious.exe using MalChela and give me a full triage report."

Claude will run the appropriate tools in sequence and synthesize the results.

---

## Notes

- All tools must be run from the MalChela workspace root. The MCP server handles this automatically via the `MALCHELA_DIR` environment variable — you do not need to `cd` manually.
- `tiquery` and `nsrlquery` take a **hash string** as their argument, not a file path. Claude handles this automatically, extracting the hash from `fileanalyzer` output and passing it correctly.
- The `MALCHELA_DIR` path in your `claude_desktop_config.json` must point to the MalChela root (where `vt-api.txt` lives), not to the `mcp/` subdirectory.
- `analyze` requires an active case — call `set_case` first, or it will return an error.

---

## Kali Linux / Remote Server Setup

If you're running MalChela on a remote Kali system (such as a Raspberry Pi field kit) rather than locally on your Mac, see the **Approach 1** section of the [MalChela Meets AI](https://bakerstreetforensics.com) blog post for instructions on integrating MalChela into the `mcp-kali-server` setup instead.

---

## Troubleshooting

**Tools don't appear in Claude Desktop after restart**
Verify the path in `args` points to the correct `index.js` and that `MALCHELA_DIR` is set to the MalChela root. Check that `npm install` completed without errors.

**`malhash` returns no results**
Confirm `vt-api.txt` exists in the MalChela root and contains a valid API key with no trailing whitespace or newline issues. The `config` tool handles this correctly; manual creation can sometimes introduce invisible characters.

**`fileanalyzer` or `mstrings` fails with "workspace root not found"**
The binary is not being run from the MalChela root directory. Verify `MALCHELA_DIR` in your config points to the correct path and that the `mcp/index.js` is using it in the `cd` command.

**NSRL queries return "Offline or Error"**
The NSRL database requires a local copy to be present. This is expected behavior if the NSRL database has not been set up — it does not affect other tools.
