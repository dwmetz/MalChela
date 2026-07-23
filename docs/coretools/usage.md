## Getting Started

Before runnning MalChela for the first time, you need to build the release binaries. There is a script provided in the workspace root.

### Building the Releases

```bash
chmod +x release.sh
./release.sh
```

## Execution

MalChela supports three main workflows:

### Direct Tool Execution (CLI)
```bash
./target/release/toolname [input] [flags]
```

### MalChela CLI Launcher Menu
```bash
./target/release/malchela
```

### MalChela Web Interface
```bash
python server/malchela_server.py
```
Then open your browser to `http://localhost:8675`.

## CLI Usage Notes

- Tools that accept paths (files or folders) should be run from the `target/release` directory after building with `release.sh`:
  ```bash
  ./target/release/fileanalyzer /path/to/file -o
  ```
  

Most tools now support a `--case <name>` argument to redirect saved output to a specific case folder under `saved_output/cases/`. Cases must be initiated with either a file or folder as the input. Hash-only workflows can be added to an existing case but cannot start one.

Note: Some tools (e.g., `mstrings`, `fileanalyzer`) require the `-o` flag to trigger output saving—even when `--case` is specified. Others (like `strings_to_yara` or `mzcount`) save automatically when a case is provided. Refer to the Tool Behavior Reference below for details.

### Output Formats

All tools that support saving reports use the following scheme:
`saved_output/<tool>/report_<timestamp>.<ext>`

To save output, use:

```bash
-o -t   # text
-o -j   # json
-o -m   # markdown
```

- `-o` enables saving (CLI output is not saved by default)


If a `--case` argument is supplied, the report will be saved to:
`saved_output/cases/<case_name>/<tool>/report_<timestamp>.<ext>`

Example:

```bash
cargo run -p mstrings — path/to/file — -o -j
```
- If `-o` is used without a format (`-t`, `-j`, or `-m`), an error will be shown



## Web Interface Notes


### Web Interface Features Summary

- Categorized tool list with input type detection (file, folder, hash)
- Arguments textbox and dynamic path browser
- Console output with ANSI coloring
- Status bar displays CLI-equivalent command
- Alphabetical sorting of tools within categories
- Tool descriptions shown alongside tool names


### Web Interface Walkthrough

Layout

- Top Toolbar: navigation and utility buttons (see below)
- Left Panel: Tool categories and selections — collapsible via the toolbar's Hide Tools Panel button, so the console can use the full width
- Center Panel: Dynamic tool input options
- Console Panel: Output display

### Top Toolbar

Left to right:

| Button | Opens |
|--------|-------|
| Home | The landing screen — ASCII art, koan, and an **At a Glance** card (case counts, `detections.yaml` rule count, API key/tool availability, and an update-available check). |
| Analyze | The [Analyze](analyze.md) target picker — point it at a file, folder, `.app` bundle, `.dmg`, or `.pkg` and it auto-runs every tool File Miner suggests. |
| Cases | The [case management](../cases.md) browser. |
| Hide Tools Panel | Collapses/expands the left tool sidebar. Persists across reloads. |
| About | Version and feature summary. |
| Configuration ⚙ | Dropdown: **Server Config** (server URL), **API Keys** (see [API Configuration](../configuration/api-configuration.md) — this is also where [Offline Mode](../configuration/offline-mode.md) lives), **tools.yaml** (see [tools.yaml reference](../configuration/tools-yaml.md)). |
| Upload Files | Upload a local file to the server for analysis (useful when the browser and the MalChela server aren't on the same machine). |
| MITRE Lookup | The standalone [MITRE ATT&CK lookup panel](mitre_lookup.md) — no internet required. |
| Notebook | A scratchpad for recording strings/IOCs/notes across a session — see below. |
| View Reports | Browse and open any previously saved report directly. |
| User Guide | Opens this documentation site in a new tab. |

On narrow screens, everything past the first divider collapses into a **⋯ More** overflow menu with the same items.

Running Tools

- Select a tool
- Fill in input fields
- Configure options (save report, format, etc.)
- Click Run


Save Report

- Formats:
>- .txt		Analyst-readable summary
>- .json	Machine-parsable, structured output
>- .md 		Shareable in tickets, wikis, etc.
>- Location: saved_output/<tool>/report_<timestamp>.<ext> (only one file is generated per run)


### Notebook

- An integrated notepad for recording strings, indicators or notes
- Supports saving as text, markdown and YAML formats
- Integrated “Open in VS Code” button for saved notes
- Any line starting with `hash:` is ignored when using the Notebook as a source for String_to_Yara to generate YARA rules

## Tool Behavior Reference
| Tool            | Input Type             | Supports `-o` | Prompts if Missing | Notes                             |
|-----------------|------------------------|---------------|--------------------|-----------------------------------|
| combine_yara    | folder                 | ❌            | ✅                 | Combines multiple YARA rules      |
| extract_samples | file                   | ❌            | ✅                 | Extracts archive contents         |
| fileanalyzer    | file                   | ✅            | ✅                 | Uses YARA + heuristics            |
| hashit          | file                   | ✅            | ✅                 | Generates hashes                  |
| hashcheck       | hash and lookup file    | ❌            | ✅                 | Checks files against known hashes |
| fileminer   | folder                 | ✅            | ✅                 | Identifies mismatches             |
| mstrings        | file                   | ✅            | ✅                 | Maps strings to MITRE             |
| mzhash          | folder                 | ✅            | ✅                 | Hashes files with MZ header       |
| nsrlquery       | file                   | ✅            | ✅                 | Queries CIRCL                     |
| strings_to_yara | text file and metadata | Case Only     | ✅                 | Saves to case folder if `--case` is provided              |
| mzcount         | folder                 | ❌            | ✅                 | Will save to case folder if `--case` is provided          |
| xmzhash         | folder                 | ✅            | ✅                 | Hashes files without known headers|