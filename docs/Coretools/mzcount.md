MZcount recursively scans a directory and counts the number of files that match key signatures like MZ (Windows executables), ZIP, PDF, and others. It uses lightweight YARA rules to classify files by type, giving a quick overview of the content breakdown within a dataset. Results can be displayed in either a detailed per-file view or a clean summary table, depending on your analysis needs.

![MZCount Table View](../images/mzcount_table.png)

<p align="center"><strong>Figure 5.12.1:</strong> MZCount Table View</p>

![MZCount Detail View](../images/mzcount_detail.png)

<p align="center"><strong>Figure 5.12.2:</strong> MZCount Detail View</p>



---

### 🔧 CLI Syntax

```bash
# Example 1: Scan a directory and view results in terminal
cargo run -p mzcount -- /path_to_scan/

# Example 2: Enable table mode
MZCOUNT_TABLE_DISPLAY=1 cargo run -p mzcount -- /path_to_scan/

# Example 3: Save results as .txt
cargo run -p mzcount -- /path_to_scan/ -- -o -t

# Example 4: Save results to a case folder
cargo run -p mzcount -- /path_to_scan/ -- -o -t --case CaseName
```

If no path is provided, the tool will prompt you to enter it interactively.

Use `-o` to save output and `-t` to specify plain text format.

When `--case` is used, output is saved under:

```
saved_output/cases/CaseName/mzcount/
```

Otherwise, output is saved under:

```
saved_output/mzcount/
```
