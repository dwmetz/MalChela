# MalChela Tool Instructions for AI Assistants

MalChela is installed at: /home/remnux/Tools/MalChela
(Adjust this path if MalChela is installed elsewhere on the system.)

All tools are Rust binaries built with Cargo. You must `cd` to the MalChela
root before running any tool. The execution pattern is:

```
cd /home/remnux/Tools/MalChela
cargo run -p <toolname> -- <arguments>
```

Example:
```
cd /home/remnux/Tools/MalChela
cargo run -p fileanalyzer -- /path/to/sample.exe
```

## Primary Static Analysis Tools

| Tool | Binary | Description |
|------|--------|-------------|
| File Analyzer | `fileanalyzer` | Hash, entropy, packing detection, PE info, YARA scan, VirusTotal lookup |
| Unpack | `unpack` | Static packer detection + unpacking for PE/ELF/Mach-O: UPX (incl. tampered), PyInstaller, .NET/Costura, NSIS, Inno Setup, fat Mach-O, overlays, embedded executables. Never executes the sample |
| mStrings | `mstrings` | String extraction, Sigma rule matching, Regex, MITRE ATT&CK mapping |
| NSRL Hash Lookup | `nsrlquery` | Query MD5/SHA1 against the NIST NSRL known-good database |
| Threat Intel Query | `tiquery` | Multi-source hash lookup: VirusTotal, MalwareBazaar, OTX, and more |

## Mac Analysis Tools

| Tool | Binary | Description |
|------|--------|-------------|
| Plist Analyzer | `plist_analyzer` | Parse .plist / .app Info.plist for malware indicators (hidden agent, ATS disabled, custom URL schemes, env injection) |
| Mach-O Info | `macho_info` | Architecture, linked libs, section entropy, RPATH, stripped symbols, deprecated crypto libs |
| Code Sign Check | `codesign_check` | Code signature inspection: Developer-signed vs. ad-hoc vs. unsigned, Team ID, Bundle ID, entitlements |

## Additional Tools

| Tool | Binary | Description |
|------|--------|-------------|
| File Miner | `fileminer` | Scan directories for file type mismatches and metadata anomalies; suggests follow-up tools per file |
| Hash It | `hashit` | Generate MD5, SHA1, and SHA256 for a single file |
| mzHash | `mzhash` | Recursively hash all files with MZ headers (Windows PE corpus) |
| xmzHash | `xmzhash` | Recursively hash files without MZ/ZIP/PDF headers (Mac, Linux, scripts) |
| mzCount | `mzcount` | Count and summarize file types within a directory |
| Extract Samples | `extract_samples` | Extract files from password-protected malware archives |
| Hash Check | `hashcheck` | Check a hash against a local known-hash lookup file |
| Strings to YARA | `strings_to_yara` | Convert a string list into a formatted YARA rule |
| Combine YARA | `combine_yara` | Merge multiple YARA rule files into a single ruleset |

## Recommended Workflows

### Windows malware triage
1. `fileanalyzer` — establish baseline: hashes, entropy, PE headers
2. `unpack` — if File Analyzer reports packing (or entropy is high), recover the payload; repeat the triage on each recovered file
3. `mstrings` — extract strings, look for IOCs and ATT&CK technique indicators
4. `tiquery` — check community threat intelligence
5. `nsrlquery` — confirm or rule out known-good status

### macOS malware triage
1. `fileminer` — scan the sample directory; note Mach-O files and .plist files
2. `plist_analyzer` — check Info.plist for stealth/persistence indicators
3. `macho_info` — examine the binary: architecture, linked libs, entropy, crypto
4. `codesign_check` — verify signature type, Team ID, and entitlements
5. `mstrings` — extract strings with Mac-specific MITRE rule coverage
6. `tiquery` — hash lookup across threat intel sources

### Unknown directory or sample set
1. `fileminer` — entry point for any unknown folder; classifies all files and suggests tools
2. Follow fileminer's per-file suggestions for deeper analysis

### Malware analysis report
1. Finish the analysis first (`analyze`, or the triage steps above) with a case active
2. `report_template` — Lenny Zeltser's Malware Analysis Report template (CC BY 4.0, bundled in
   `assets/report_templates/`) and a guide to which MalChela output fills each section
3. Write the report from the case's findings: corroborate rule hits rather than listing them, mark
   behavioral and memory analysis as not performed (MalChela is static only), and resolve the
   template's (Optional) sections
4. `save_report` — saves it to `saved_output/cases/<case>/report/` and registers it in the case

## Environment Notes

- mStrings includes 12 Mac-specific MITRE ATT&CK detection rules (launch agents, dylib injection, shell execution, keychain access, sandbox evasion, and more)
- MalChela integrates with REMnux tools; use REMnux CLI tools in conjunction as needed
- Case management is available via the MalChela GUI if a graphical session is active