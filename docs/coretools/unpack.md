Unpack detects packers, protectors, installers, and bundlers in PE, ELF, and Mach-O files, and statically recovers the payload wherever that's possible without running the sample. Every detection is reported with the evidence behind it (section names, magic offsets, structural anomalies), so the call can be checked rather than trusted, and every recovered payload is fed back through Unpack again — a dropper inside an installer inside a UPX stub comes out as a layer tree, not just the outermost layer.

**Static only.** Unpack never executes or emulates the sample. Where a packer can only be removed by running its stub (Themida, VMProtect, Enigma, custom crypters), Unpack identifies it, shows the evidence, and says so.

---

### What It Handles

| Detection | Formats | Recovery | Needs |
|---|---|---|---|
| UPX | PE, ELF, Mach-O | Decompressed with `upx -d` on a working copy | `upx` |
| UPX, tampered | ELF, PE | Headers repaired first, then `upx -d` — see below | `upx` |
| Mach-O universal (fat) | Mach-O | Split into one thin binary per architecture | — |
| PyInstaller | PE, ELF, Mach-O | CArchive extracted natively; entry scripts rebuilt as `.pyc` with the correct header | — |
| Python bytecode (`.pyc`), including obfuscated | `.pyc` (CPython 3.7–3.14) | Parsed natively; common obfuscation layers peeled; names, function names, and string constants written to `<name>_pyc_strings.txt` for mStrings — see below | — |
| .NET embedded resources / Costura.Fody | .NET PE | ManifestResources extracted natively; `costura.*.compressed` assemblies deflate-decompressed | — |
| NSIS installer | PE | Extracted with 7-Zip | `7zz` / `7z` |
| Inno Setup installer | PE | Extracted with innoextract | `innoextract` |
| Overlay | PE, ELF, Mach-O | Appended data carved out (archives, executables, or high-entropy blobs) | — |
| Embedded executable | any | Structurally validated PE/ELF/Mach-O images carved out of the file | — |
| Named packers / protectors | PE | Identified only: ASPack, MPRESS, PECompact, Petite, NsPack, RLPack, MEW, kkrunchy, Themida, WinLicense, VMProtect, Enigma, and others | — |
| .NET obfuscators | .NET PE | Identified only: ConfuserEx, SmartAssembly, Dotfuscator, Babel, and others | — |
| shc-compiled shell script | ELF, Mach-O | Identified only | — |
| Unknown packer (heuristic) | PE, ELF, Mach-O | Identified only: high-entropy code, minimal imports, W+X sections, entry point outside the first code section | — |
| Go binary | PE, ELF, Mach-O | Informational — not packing, but a hint to use GoReSym | — |

The three external helpers are optional. Everything else is native Rust and works the same on macOS, Linux, and Windows. Check what's available with:

```bash
./target/release/unpack --check
```

| Helper | macOS | Linux | Windows | Override |
|---|---|---|---|---|
| UPX | `brew install upx` | `apt install upx-ucl` | `choco install upx` | `MALCHELA_UPX` |
| 7-Zip | `brew install sevenzip` | `apt install 7zip` | `choco install 7zip` | `MALCHELA_7Z` |
| innoextract | `brew install innoextract` | `apt install innoextract` | `choco install innoextract` | `MALCHELA_INNOEXTRACT` |

None of the helpers execute the sample — they only parse and decompress it.

---

### Tampered UPX

Commodity malware — Mirai and its descendants especially — routinely damages UPX headers so that `upx -d` refuses the file while the stub still runs. Unpack detects and reverses the common tricks on a working copy (the original is never modified), and records every byte it changed in the report:

- **ELF:** the `UPX!` magic replaced with another four-byte value everywhere it appears (in `l_info` and the trailing pack header), and/or `p_info.p_filesize` / `p_blocksize` zeroed. Unpack restores the magic and rebuilds `p_info` from the trailing pack header's original file size — including big-endian targets (MIPS, PowerPC), whose pack header is itself big-endian.
- **PE:** the `UPX0` / `UPX1` sections renamed, and the pack header magic wiped. Unpack recognises UPX's section layout (an empty first section with a large virtual size, followed by a high-entropy section holding the entry point), renames the sections back, and restores the pack header magic after UPX's version string.

If the repair isn't enough, the report shows the repairs attempted and `upx`'s own error.

---

### CLI Syntax

```bash
# Unpack next to the input, into <name>_unpacked/
./target/release/unpack /path/to/sample

# Choose the output directory
./target/release/unpack /path/to/sample --out /path/to/output

# Save under a case (payloads go to saved_output/cases/Case123/unpack/<name>_unpacked/)
./target/release/unpack /path/to/sample --case Case123 -o -m

# Machine-readable summary on stdout (used by Analyze, the web interface, and MCP)
./target/release/unpack /path/to/sample --json

# Detection and native handlers only — never call upx / 7-Zip / innoextract
./target/release/unpack /path/to/sample --no-external
```

| Option | Default | Purpose |
|---|---|---|
| `--out DIR` | `<input>_unpacked` | Where recovered payloads are written |
| `--case NAME` | — | Route payloads and the saved report into a case |
| `--json` | — | JSON summary on stdout (verdict, payloads, MITRE IDs, full layer tree) |
| `-o` with `-m` / `-t` / `-j` | Markdown | Save the report (`saved_output/unpack/` or the case's `unpack/` folder) |
| `--max-depth N` | 3 | Maximum number of layers to unpack |
| `--max-output-mb MB` | 512 | Cap on total bytes written across the run (zip-bomb guard) |
| `--no-external` | — | Skip external helpers |
| `--only-if-found` | — | With `-o`, only save a report when something was detected |
| `--check` | — | List the external helpers that were found |

Recovered payloads are deduplicated by SHA256, archive-supplied names are sanitised (no absolute paths or `..`), and an empty output directory is removed when nothing was recovered.

---

### The Report

The Markdown report contains:

- **Packer verdict** — one line naming what was found and how many payloads were recovered (Analyze's rollup surfaces this line in its Sample Snapshot).
- **Detections** — every verdict at every layer, with type, confidence, and evidence, plus a note on what to do next where no static path exists.
- **Actions** — which handler ran, its status (`ok`, `partial`, `failed`, or `skipped`), and exactly what it did, including any header repairs.
- **Recovered Payloads** — path, format, size, SHA256, and how each one was produced.
- **Layer Tree** — the full parent → child chain, for example:

```text
dropper.exe [PE32 (x86)] — NSIS installer
└── payload.exe [PE32+ (x86_64)] — UPX (tampered)
    └── payload_upx.exe [PE32+ (x86_64)]
```

- **Section Entropy** for the input, with high-entropy sections marked.
- **MITRE ATT&CK** — `T1027.002` (Software Packing) when a packer, protector, or crypter is detected, and `T1027.009` (Embedded Payloads) when an installer, bundler, overlay, or embedded executable is found.

---

### Analyze Integration

[Analyze](analyze.md) runs Unpack automatically on every executable File Miner finds. When Unpack recovers payloads, each one is classified by File Miner and analysed with its own suggested tools — so File Analyzer, mStrings, and Threat Intel Query see the real payload, not just the packer stub. In the MalChela Summary, the packed file's section includes the Unpack report, the Sample Snapshot lists it under **Packing / Obfuscation**, the Component Inventory lists every recovered payload, and each payload's section is marked **Unpacked from** its parent. Clean executables add nothing to the rollup or the case.

File Analyzer's **Packed** field uses the same detector, and names the packer when one is found.

---

### Python Bytecode and Obfuscators

Python stealers (Luna Grabber, Blank Grabber, and many others) ship as PyInstaller bundles, and the real program is the entry script, a `.pyc`.  It's usually obfuscated, so a strings pass over it shows almost nothing.  BlankOBF-style builds wrap the code in layers: an xz or zlib blob in the module's constants, Python source holding base64 split into pieces (one rot13'd, some reversed), and finally a marshalled code object.

Unpack parses CPython's marshal format itself and follows those layers to the innermost code object.  It never imports, compiles, unmarshals, or runs anything in a Python interpreter.  Peeled layers handled: xz, zlib, gzip, and LZMA blobs; base64 (as is, reversed, or rot13'd); BlankOBF's split-and-reverse concatenation; and nested `.pyc` or marshal data.

It writes:

- `<name>_pyc_strings.txt`: every code object's function name, the names it uses, and its string constants (byte-tuple names decoded), innermost layer first.  This is the payload Analyze runs mStrings on, so the matrix and IOCs come from the stealer's own code.
- `<name>_layerN_source.py.txt` and `<name>_layerN.marshal`: each intermediate layer, for manual review.  The source layers are saved as `.txt` so they can't be run by double-clicking.

An obfuscated `.pyc` is reported as **Obfuscated Python bytecode** (Crypter) and tagged T1027.013 Encrypted/Encoded File, not Software Packing.  A plain `.pyc` is informational, and its strings file is still written.

Point Analyze at a standalone `.pyc` and File Miner routes it to Unpack and mStrings the same way.

---

### Limits

- Static only: protectors and custom crypters that decrypt in memory are identified, not unpacked. For those, use emulation (e.g. unipacker, Speakeasy) or a sandbox / memory dump — MalChela's [Volatility 3](../tools/vol3.md) integration can take it from there.
- UPX on Mach-O relies on `upx` supporting that particular binary; tampered-header repair is implemented for ELF and PE.
- PyInstaller's `PYZ` archive is extracted as a single `.pyz` file; individual library modules inside it are not unpacked. The author's entry script(s) — what you usually want — are recovered as standalone `.pyc` files.
- `.pyc` parsing covers CPython 3.7–3.14.  Bytecode is not decompiled: you get names and constants, not control flow.  PyArmor and other obfuscators that encrypt code objects with a runtime key are not peeled.
- shc-compiled scripts are detected, but not yet decrypted.
