dpp Extract unwraps Apple disk image (`.dmg`) and installer package (`.pkg`) containers — formats none of the other Core Tools can see through directly. A raw `.dmg` reads as `Unknown or unrecognized file type` to File Analyzer; a `.pkg` is a XAR archive wrapping a PBZX-compressed CPIO payload, not a Mach-O binary. dpp Extract walks the whole chain — **UDIF → HFS+/APFS → XAR → PBZX/CPIO** — and hands back the real files inside, so the rest of the suite (File Analyzer, mStrings, Mach-O Info, Code Sign Check) can analyze them normally.

It's built on the [`dpp`](https://github.com/Dil4rd/dpp) Rust crate.

---

### How It Works

1. Opens the `.dmg` (or `.pkg` directly) and mounts its filesystem — auto-detecting HFS+ vs. APFS, and all four DMG compression schemes Apple uses (Zlib, Bzip2, LZFSE, XZ).
2. If the filesystem contains one or more `.pkg` installers, extracts each component's **Payload** (the actual files the installer drops) and **Scripts** (preinstall/postinstall) archives — both are decoded whether they're the modern PBZX-wrapped format or the classic gzip-compressed CPIO format older installers use.
3. If there's no `.pkg` inside — just a bare app or binary sitting directly on the disk image — extracts the raw filesystem tree instead, since that already **is** the payload.
4. Extraction is entry-by-entry rather than all-or-nothing: a single unreadable or malformed entry (a handful of real-world DMGs trip a decoding quirk in the underlying HFS+/APFS crate) is skipped and reported, not treated as a fatal error for the whole volume.

**Why Scripts matters:** some installers (seen in both objective-see's oRAT and Shlayer samples) ship an empty or near-empty Payload and put their actual malicious behavior entirely in the postinstall script instead — a curl-and-execute one-liner, or a fingerprint-and-callback sequence. Extracting Payload alone would silently miss that; dpp Extract always pulls both.

---

### CLI Syntax

```bash
# Extract a DMG or PKG next to itself, in <name>_extracted/
cargo run -p dpp_extract /path/to/sample.dmg

# Extract to a specific output directory
cargo run -p dpp_extract /path/to/sample.pkg -o /path/to/output

# Save under a case
cargo run -p dpp_extract /path/to/sample.dmg --case Case123

# Machine-readable summary (used internally by Analyze and the web interface)
cargo run -p dpp_extract /path/to/sample.dmg --json
```

When `--case` is provided without `-o`, output is saved under:

```
saved_output/cases/Case123/dpp_extract/
```

---

### Analyze Integration

[Analyze](../coretools/analyze.md) auto-detects a `.dmg`/`.pkg` target and runs dpp Extract before handing the result to File Miner — there's no need to run dpp Extract by hand first. Because a trojanized installer's payload commonly bundles the full legitimate app it trojanized alongside the injected malicious file(s), the extracted tree is often well over Analyze's 25-file auto-run cap (EvilQuest: 624 files for one Mach-O of actual interest); when that happens, Analyze hands off to File Miner's interactive table instead of erroring out or auto-running everything. See [Analyze](../coretools/analyze.md) and [File Miner](../coretools/fileminer.md) for that flow.

---

### Known Limitations

dpp Extract inherits the maturity of the underlying `dpp` crate. Two failure modes have been observed against real-world samples and are not currently recoverable:

- A `.dmg` that isn't a standard UDIF file (missing the expected `koly` trailer) fails to open at all.
- A small number of DMGs have hit what looks like a broken by-name catalog lookup in the HFS+ decoder — the volume opens and walks fine, but every file read fails, extracting zero files.

Both fail safely (a clear error, or a zero-file result with every skipped entry listed) rather than crashing or silently corrupting output.
