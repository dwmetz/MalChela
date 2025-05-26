Hash It generates cryptographic hashes (MD5, SHA1, and SHA256) for a given file. It’s useful for file integrity checks, hash-based lookups, or comparing suspected duplicates across datasets.

![HashIt](../images/hashit.png)

<p align="center"><strong>Figure 11:</strong> HashIt</p>

---

### 🔧 CLI Syntax

```bash
cargo run -p hashit -- /path_to_file/
```

Displays the hash values in the terminal without saving a report.

```bash
cargo run -p hashit -- /path_to_file/ -o -t
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