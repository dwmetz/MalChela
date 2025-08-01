**Note:** `FileMiner` replaces the deprecated `MismatchMiner`.

**FileMiner** is a command-line tool that recursively scans a directory to analyze files by magic bytes and hash, identifying mismatches between file extensions and true types. It is useful for forensic triage, anomaly detection, and preparing follow-up analysis using other tools in the MalChela suite.

![File Miner](../images/fileminer.png)

<p align="center"><strong>Figure 5.6.1:</strong> File Miner</p>

![File Miner with Subtool Output](../images/fileminer_with_subtool_output.png)

<p align="center"><strong>Figure 5.6.2:</strong> File Miner with Subtool Output</p>


## Function Overview

- Identifies file types using magic byte detection (`infer`)
- Computes SHA-256 hashes for all files
- Detects extension mismatches
- Suggests relevant analysis tools (e.g., FileAnalyzer, mStrings, malhash)
- Outputs results in a styled table or optional JSON format
- Integrates with case management via the `--case` flag
- Automatically launches in GUI when a folder-based case is created or restored
- Results populate an interactive table in the GUI
- Users can launch suggested tools on a per-file basis directly from the GUI

## CLI Usage

```sh
cargo run -p fileminer -- [OPTIONS] [DIR]
```

### Options

| Option                      | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `DIR`                      | Directory to analyze. Optional — will prompt if not supplied.             |
| `--json`                   | Save results to JSON. Defaults to `fileminer_output.json` unless `--output` is used. |
| `--output <filename>`      | Overrides the default output file name. Used internally by the GUI.       |
| `--case <case-name>`       | Saves output under `saved_output/<case-name>/fileminer/`. Also passes case name to downstream tools. |
| `-m`, `--mismatches-only`  | Only display entries with extension mismatches.                            |

### Examples

```sh
# Analyze interactively
cargo run -p fileminer --

# Analyze directory and save JSON
cargo run -p fileminer -- /path/to/files --json

# Save to specific case folder
cargo run -p fileminer -- /path/to/files --case case123

# Filter mismatches only
cargo run -p fileminer -- /path/to/files -m

# Combine all
cargo run -p fileminer -- /path/to/files --case suspicious_usb -m
```

## GUI Usage Notes

- When a new case is created or restored using a folder, FileMiner runs automatically in the GUI.
- Results are saved under `saved_output/cases/<case-name>/fileminer/`.
- FileMiner displays an interactive table of results with suggested tools per file.
- Suggested tools can be launched directly from within the GUI results panel.