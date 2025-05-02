# MalChela User Guide

📘 This guide covers MalChela v2.1.0 (May 2025)

## 🦀 Introduction

**MalChela** is a modular toolkit for digital forensic analysts, malware researchers, and threat intelligence teams. It provides both a Command Line Interface (CLI) and a Graphical User Interface (GUI) for running analysis tools in a unified environment.


## 🛠 Installation

### Prerequisites

	•	Rust and Cargo
	•	Git
	•	Unix-like environment (Linux, macOS, or Windows with WSL)

### Clone the Repository
```
git clone https://github.com/dwmetz/MalChela.git

cd MalChela
```
### Build Tools

```
cargo build                 # Build all tools
cargo build -p fileanalyzer # Build individual tool
```
### Windows Notes

	•	Best experience via WSL2
	•	GUI is not supported natively on Windows

## 🚀 Getting Started

MalChela supports three main workflows:

1. **Direct Tool Execution (CLI):**
   ```bash
   cargo run -p toolname -- [input] [flags]
   ```
2. **MalChela CLI Launcher Menu:**
   ```bash
   cargo run -p malchela
   ```
3. **MalChela GUI Launcher:**
   ```bash
   cargo run -p MalChelaGUI
   ```

## 🔧 CLI Usage Notes

- Tools that accept paths (files or folders) can be run with `--` after the `cargo run` command to specify inputs and save output:
  ```bash
  cargo run -p fileanalyzer -- /path/to/file -o
  ```
- The `-o` flag (or `--output`) enables report saving for tools that support it. By default cli output will not be saved.


## 📁 Adding Third-Party Tools

To integrate a new tool into the GUI:

```yaml
- name: toolname
  description: "Short summary of tool purpose"
  command: ["toolname"]
  input_type: file  # or folder or hash
  category: "File Analysis"  # or other GUI category
  optional_args: []
  exec_type: binary  # or cargo / script
  file_position: last  # or first, if required
```

> Tools now require `exec_type` (e.g., `cargo`, `binary`, `script`) to define how they are launched, and `file_position` to clarify argument order when needed.

Ensure the tool:
- Accepts CLI arguments in the form `toolname [args] [input]`
- Outputs results to stdout
- Is installed and available in `$PATH`

## 📂 YARA Rules

YARA rules for tools like `fileanalyzer` are stored in the `yara_rules` folder in the workspace. You can modify or add rules here.

## ✨ GUI Features Summary

- Categorized tool list with input type detection (file, folder, hash)
- Arguments textbox and dynamic path browser
- Console output with ANSI coloring
- Save Report checkbox toggles `-o` flag
- Status bar displays CLI-equivalent command
- Alphabetical sorting of tools within categories
- Tool descriptions are now shown alongside tool names
- Saved reports are cleaned of internal formatting tags like [green], [reset], etc.

## 💻 GUI Walkthrough

Layout

	•	Top Bar: Title and status
	•	Left Panel: Tool categories and selections
	•	Center Panel: Dynamic tool input options
	•	Bottom Panel: Console output

Running Tools

	1.	Select a tool
	2.	Fill in input fields
	3.	Configure options (save report, format, etc.)
	4.	Click Run
	> - The GUI uses `exec_type` to determine whether a tool is launched using `cargo`, a native binary, or a script like `python3`.
	> - Input file position is handled based on the `file_position` value in `tools.yaml`.

Save Report

	•	Formats: .txt, .json, .md
	•	Location: saved_output/<tool>/report_<timestamp>.<ext> (only one file is generated per run)

Scratchpad

	•	Save as .txt, .md, or .yaml
	•	Tip: hash: lines are ignored when used for strings_to_yara

Configuration Panel

	•	Stores API keys in vt-api.txt and mb-api.txt
	•	Keys are required for malhash, fileanalyzer (for VT)

### 📄 Output Formats

	•	.txt	Analyst-readable summary
	•	.json	Machine-parsable, structured output
	•	.md 	Shareable in tickets, wikis, etc.

### 🧮 Tool-Specific Notes

	•	fileanalyzer: YARA rules come from yara_rules/ folder (generates a single clean report in GUI mode)
	•	mstrings: Maps strings to MITRE ATT&CK from detections.yaml
	•	mzcount: Table view toggle via GUI or CLI 
	•	mzmd5/xmzmd5: Build “known-good” or “bad” hash sets
	•	strings_to_yara: CLI/GUI dual support; hash: lines ignored
	•	combine_yara: Recursive merge of .yar files
	•	malhash: Needs API keys to run; avoids double-saving in GUI mode
	•	nsrlquery: Matches against local NSRL DB
	•	extract_samples: Recursive ZIP extractor
	•	mismatchminer: Identifies mismatches (generates a single clean report in GUI mode)
	•	hashit: Generates hashes (generates a single clean report in GUI mode)


### 🧪 Tool Behavior Reference

| Tool          | Input Type | Supports `-o` | Prompts if Missing | Notes |
|---------------|-------------|----------------|---------------------|-------|
| combine_yara | folder      | ❌             | ✅                  | Identifies mismatches || extract_samples | file      | ❌             | ✅                  | Extracts archive contents |
| fileanalyzer  | file        | ✅             | ✅                  | Uses YARA + heuristics |
| hashit | file      | ✅             | ✅                  | Generates hashes || malhash       | hash        | ✅             | ❌                  | Uses vt-cli + bazaar-cli |
| mismatchminer | folder      | ✅             | ✅                  | Identifies mismatches |
| mstrings      | file        | ✅             | ✅                  | Maps strings to MITRE |
| nsrlquery | file      | ✅             | ✅                  | Queries CIRCL || strings_to_yara | file      | ❌             | ✅                  | Generates YARA rules |
| mzmd5         | folder      | ❌             | ✅                  | MD5 only; no output flag |
| mzcount         | folder      | ❌             | ✅                  | file counts |
| strings_to_yara        | text file and metadata      | ❌             | ✅                  | Combined yara rule |
| xmzmd5        | folder      | ❌             | ✅                  | Extended MD5 scan |

## 📝 Scratchpad Tips (strings_to_yara)

- Any line starting with `hash:` is ignored when generating YARA rules
- Supports markdown and YAML save formats
- Integrated "Open in VS Code" button for saved notes

## ⚠️ Known Limitations & WSL Notes

	•	CLI works in WSL
	•	GUI requires macOS or Linux (may work in WSLg on Win11)
	•	Paths must be POSIX-style
	•	If `exec_type` is omitted or misconfigured in `tools.yaml`, the GUI may attempt to run the tool incorrectly.
	•	GUI execution behavior no longer depends on the `category` field.

## 🖥️ Advanced Installation (macOS)

To install MalChela as a native macOS app:
1. Build with `cargo build --release`
2. Copy the binary and support files to an `.app` bundle
3. Use Platypus or a wrapper to define icon and behavior

Bundle as .app

```
cargo install cargo-bundle
cd MalChelaGUI
cargo bundle --release
```

	•	Output: target/release/bundle/osx/MalChela.app
	•	Move to /Applications or Dock

### 🦀 Support & Contribution

	•	GitHub: https://github.com/dwmetz/MalChela
	•	Issues/PRs welcome
	•	Extend via tools.yaml for external tools
---
For more information, visit [https://bakerstreetforensics.com](https://bakerstreetforensics.com).


