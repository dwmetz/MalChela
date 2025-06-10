
**Note:** `FileMiner` replaces the deprecated `MismatchMiner`.

**FileMiner** is a command-line tool that recursively scans a directory to analyze files by magic bytes and hash, identifying mismatches between file extensions and true types. It is useful for forensic triage, anomaly detection, and preparing follow-up analysis using other tools in the MalChela suite.

## Function Overview

- Identifies file types using magic byte detection (`infer`)
- Computes SHA-256 hashes for all files
- Detects extension mismatches
- Suggests relevant analysis tools (e.g., FileAnalyzer, mStrings, malhash)
- Outputs results in a styled table or optional JSON format
- Integrates with case management via the `--case` flag

## CLI Usage

```sh
cargo run -p fileminer -- [OPTIONS] [DIR]
```

### Options

| Option                      | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `DIR`                      | Directory to analyze. Optional — will prompt if not supplied.             |
| `--json`                   | Save results to `fileminer_output.json` in `saved_output` directory.       |
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