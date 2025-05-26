FileAnalyzer performs deep static analysis on a single file. It extracts hashes, entropy, file type metadata, YARA rule matches, NSRL validation, and — for PE files — rich header details including import/export tables, compile timestamp, and section flags. Ideal for triaging unknown executables or confirming known file traits.

![File Analyzer](../images/fileanalyzer.png)

<p align="center"><strong>Figure 9:</strong> File Analyzer</p>

- YARA rules for `fileanalyzer` are stored in the `yara_rules` folder in the workspace. You can modify or add rules here.

---

### 🔧 CLI Syntax

```bash
cargo run -p fileanalyzer -- /path_to_file/ -o -t
```

If no file path is provided, the tool will prompt you to enter it interactively.

```bash
Enter the path to the file you want to analyze:
```

Use `-o` to save output and include one of the following format flags:
- `-t` → Save as `.txt`
- `-j` → Save as `.json`
- `-m` → Save as `.md`

