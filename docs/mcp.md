# AI Integration & MCP Support

MalChela exposes its full tool suite — including Analyze and the Mac Analysis stack — to AI agents like Claude through the **Model Context Protocol (MCP)**. Once configured, Claude has persistent, structured access to MalChela's full analysis suite without any manual briefing or context-pasting each session.

For a detailed walkthrough of AI-assisted analysis approaches, see the blog post: [MalChela Meets AI: Three Paths to Smarter Malware Analysis](https://bakerstreetforensics.com).

---

## Prerequisites

- MalChela built from source — see [Installation](install.md). This compiles all MalChela tools to `target/release/`.
- [Node.js](https://nodejs.org/) v18 or later
- [Claude Desktop](https://claude.ai/download) (or Claude Code, via the plugin marketplace — see below)
- API keys configured for whichever lookups you want available (see [API Configuration](configuration/api-configuration.md))

### Set MALCHELA_DIR

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export MALCHELA_DIR=/path/to/MalChela
```

The MCP server uses this to locate the workspace root — where `vt-api.txt` lives, not the `mcp/` subdirectory — and shells out to the compiled binaries under `$MALCHELA_DIR/target/release/`.

---

## Installation

**Via Anthropic community marketplace (Claude Code):**

```bash
claude plugin marketplace add anthropics/claude-plugins-community
claude plugin install malchela@claude-community
```

**Via self-hosted marketplace (Claude Code):**

```bash
claude plugin marketplace add dwmetz/MalChela
claude plugin install malchela@malchela-marketplace
```

**Manual install (Claude Desktop):**

```bash
cd /path/to/MalChela/.claude-plugin/mcp
npm install
```

Then merge the relevant block from `example_config.json` into your Claude Desktop configuration file:

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

Open `example_config.json` and update the paths to match your system, then copy the `malchela` block into your Claude Desktop config — if you already have other MCP servers configured, add it alongside them rather than replacing the whole file. Restart Claude Desktop afterward; the MalChela tools appear in Claude's tool list automatically.

---

## Available Tools

17 tools map 1:1 to a compiled MalChela binary. Two more are MCP-only, with no binary of their own: `set_case` (session state) and `analyze` (an orchestrator that shells out to the other 17 in sequence).

Unlike the PWA, the MCP server uses a **mandatory case model** — call `set_case` once at the start of a session before running any other tool; every subsequent tool's output is saved to that case automatically.

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

---

## Recommended Analysis Workflow

For initial triage of an unknown file, ask Claude to run the tools in this order:

1. `set_case` — create or select the case everything below will be saved to
2. `fileanalyzer` — establish baseline: hashes, entropy, PE headers, initial VT verdict
3. `mstrings` — extract strings, surface IOCs and ATT&CK technique indicators
4. `tiquery` — pull full community threat intel with AV verdicts
5. `nsrlquery` — confirm or rule out known-good status

Or skip the manual sequencing entirely and let `analyze` do it in one call. You don't need to invoke tools individually — just describe what you want:

> "Analyze /path/to/suspicious.exe using MalChela and give me a full triage report."

Claude will run the appropriate tools in sequence and synthesize the results.

---

## Agentic Coding Environments

For agentic coding environments (OpenCode and similar), MalChela ships an [`AGENTS.md`](https://github.com/dwmetz/MalChela/blob/main/.claude-plugin/mcp/AGENTS.md) describing available tools and usage patterns for autonomous discovery.

---

## Kali Linux / Remote Server Setup

If you're running MalChela on a remote Kali system (such as a Raspberry Pi field kit) rather than locally on your Mac, see the **Approach 1** section of the [MalChela Meets AI](https://bakerstreetforensics.com) blog post for instructions on integrating MalChela into the `mcp-kali-server` setup instead.

---

## Troubleshooting

**Tools don't appear in Claude Desktop after restart**
Verify the path in `args` points to the correct `index.js` and that `MALCHELA_DIR` is set to the MalChela root. Check that `npm install` completed without errors.

**`tiquery` returns no results**
Confirm the relevant API key file (e.g. `vt-api.txt`) exists in the MalChela root and contains a valid key with no trailing whitespace or newline issues.

**`fileanalyzer` or `mstrings` fails with "workspace root not found"**
The binary is not being run from the MalChela root directory. Verify `MALCHELA_DIR` in your config points to the correct path and that `mcp/index.js` is using it in the `cd` command.

**`analyze` fails with an error about no active case**
Call `set_case` first — `analyze` requires an active case, unlike the PWA where Save-to-Case is opt-in.

**NSRL queries return "Offline or Error"**
The NSRL database requires a local copy to be present. This is expected behavior if the NSRL database has not been set up — it does not affect other tools. See also [Offline Mode](configuration/offline-mode.md), which intentionally skips this call when enabled.
