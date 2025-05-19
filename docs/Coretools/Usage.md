
## Getting Started

MalChela supports three main workflows:

1. **Direct Tool Execution (CLI):**
   ```bash
   cargo run -p toolname — [input] [flags]
   ```
2. **MalChela CLI Launcher Menu:**
   ```bash
   cargo run -p malchela
   ```
3. **MalChela GUI Launcher:**
   ```bash
   cargo run -p MalChelaGUI
   ```

## CLI Usage Notes

- Tools that accept paths (files or folders) can be run with `—` after the `cargo run` command to specify inputs and save output:
  ```bash
  cargo run -p fileanalyzer — /path/to/file -o
  ```
  
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


Example:

```bash
cargo run -p mstrings — path/to/file — -o -j
```
- If `-o` is used without a format (`-t`, `-j`, or `-m`), an error will be shown



## GUI Usage Notes


### GUI Features Summary

- Categorized tool list with input type detection (file, folder, hash)
- Arguments textbox and dynamic path browser
- Console output with ANSI coloring
- Save Report checkbox toggles `-o` flag
- Status bar displays CLI-equivalent command
- Alphabetical sorting of tools within categories
- Tool descriptions are now shown alongside tool names
- Saved reports are cleaned of internal formatting tags like [green], [reset], etc.

### GUI Walkthrough

Layout

- Top Bar: Title and status
- Left Panel: Tool categories and selections
- Center Panel: Dynamic tool input options
- Bottom Panel: Console output

Running Tools

- Select a tool
- Fill in input fields
- Configure options (save report, format, etc.)
- Click Run


Save Report

- Formats:
>- .txt		Analyst-readable summary
>- .json	Machine-parsable, structured output
>- .md 		Shareable in tickets, wikis, etc. .txt, .json, .md
>- Location: saved_output/<tool>/report_<timestamp>.<ext> (only one file is generated per run)
		


### 📝 Scratchpad  

- An integrated notepad for recording strings, indicators or notes
- Supports saving as text, markdown and YAML formats
- Integrated “Open in VS Code” button for saved notes
- Any line starting with `hash:` is ignored when using the Scratchpad as a source for String_to_Yara to generate YARA rules

## Tool Behavior Reference
| Tool            | Input Type             | Supports `-o` | Prompts if Missing | Notes                             |
|-----------------|------------------------|---------------|--------------------|-----------------------------------|
| combine_yara    | folder                 | ❌            | ✅                 | Combines multiple YARA rules      |
| extract_samples | file                   | ❌            | ✅                 | Extracts archive contents         |
| fileanalyzer    | file                   | ✅            | ✅                 | Uses YARA + heuristics            |
| hashit          | file                   | ✅            | ✅                 | Generates hashes                  |
| malhash         | hash                   | ✅            | ✅                 | Uses vt-cli + bazaar-cli          |
| mismatchminer   | folder                 | ✅            | ✅                 | Identifies mismatches             |
| mstrings        | file                   | ✅            | ✅                 | Maps strings to MITRE             |
| nsrlquery       | file                   | ✅            | ✅                 | Queries CIRCL                     |
| strings_to_yara | text file and metadata | ❌            | ✅                 | Generates YARA rules              |
| mzmd5           | folder                 | ❌            | ✅                 | MD5 only; no output flag          |
| mzcount         | folder                 | ❌            | ✅                 | Tallies file types                |
| xmzmd5          | folder                 | ❌            | ✅                 | Extended MD5 scan                 |