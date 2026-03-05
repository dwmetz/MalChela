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

MalChela reads API keys from two plain text files in the project root:

| File | Service |
|---|---|
| `vt-api.txt` | [VirusTotal](https://www.virustotal.com) — free tier sufficient |
| `mb-api.txt` | [MalwareBazaar](https://bazaar.abuse.ch) — free, no key required for basic queries |

These files are already listed in `.gitignore` and will never be committed to the repository.

The easiest way to set them up is via MalChela's built-in config tool, run from the MalChela root:

```bash
cd /path/to/MalChela
cargo run -p config
```

Alternatively, create them manually:

```bash
echo "your-virustotal-api-key" > vt-api.txt
echo "your-malwarebazaar-api-key" > mb-api.txt
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

Once configured, the following MalChela tools are available to Claude:

| Tool | Description |
|---|---|
| `malchela_fileanalyzer` | Hashes, entropy, packing detection, PE metadata, YARA scan, VirusTotal lookup |
| `malchela_mstrings` | String extraction, Sigma rule matching, IOC detection, MITRE ATT&CK mapping |
| `malchela_malhash` | Query a hash against VirusTotal and MalwareBazaar |
| `malchela_nsrlquery` | Query a file hash against the NIST NSRL known-good database |
| `malchela_hashit` | Generate MD5, SHA1, and SHA256 hashes for a single file |
| `malchela_fileminer` | Scan a directory for file type mismatches and metadata anomalies |

### Recommended analysis workflow

For initial triage of an unknown file, ask Claude to run the tools in this order:

1. `malchela_fileanalyzer` — establish baseline: hashes, entropy, PE headers, initial VT verdict
2. `malchela_mstrings` — extract strings, surface IOCs and ATT&CK technique indicators
3. `malchela_malhash` — pull full community threat intel with AV verdicts
4. `malchela_nsrlquery` — confirm or rule out known-good status

You don't need to invoke these individually — just describe what you want to Claude:

> "Analyze /path/to/suspicious.exe using MalChela and give me a full triage report."

Claude will run the appropriate tools in sequence and synthesize the results.

---

## Notes

- All tools must be run from the MalChela workspace root. The MCP server handles this automatically via the `MALCHELA_DIR` environment variable — you do not need to `cd` manually.
- `malchela_malhash` takes a **hash string** as its argument, not a file path. Claude handles this automatically, extracting the hash from `fileanalyzer` output and passing it correctly.
- The `MALCHELA_DIR` path in your `claude_desktop_config.json` must point to the MalChela root (where `vt-api.txt` lives), not to the `mcp/` subdirectory.

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
