mStrings extracts strings from files and classifies them using regular expressions, YARA rules, and MITRE ATT&CK mappings. It highlights potential indicators of compromise and suspicious behavior, grouping matches by tactic and technique. Ideal for quickly surfacing malicious capabilities in binaries, scripts, and documents.

![MStrings](../images/mstrings.png)

<p align="center"><strong>Figure 14:</strong> MStrings</p>

---

### 🔧 CLI Syntax

```bash
cargo run -p mstrings -- /path_to_file/
```

Scans the specified file and prints results in the terminal.

```bash
cargo run -p mstrings -- /path_to_file/ -o -t
```

Saves the results as a `.txt` file.

Use `-o` to save output and include one of the following format flags:
- `-t` → Save as `.txt`
- `-j` → Save as `.json`
- `-m` → Save as `.md`

If no file is provided, the tool will prompt you to enter the path interactively.

```bash
Enter the file path:
```
