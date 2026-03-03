# MalChela Tool Instructions for AI Assistants

MalChela is installed at: /home/remnux/Tools/MalChela

All tools are Rust binaries. The execution pattern is:
cd /home/remnux/Tools/MalChela
./target/release/<toolname> <arguments>

## Primary Static Analysis Tools

| Tool | Binary | Description |
|------|--------|-------------|
| File Analyzer | `fileanalyzer` | Hash, entropy, packing detection, PE info, YARA scan, VirusTotal lookup |
| mStrings | `mstrings` | String extraction, Sigma rule matching, Regex, MITRE ATT&CK mapping |
| NSRL Hash Lookup | `nsrlquery` | Query MD5/SHA1 against the NIST NSRL known-good database |
| Malware Hash Lookup | `malhash` | Query a hash against VirusTotal and MalwareBazaar |

## Additional Tools

| Tool | Binary | Description |
|------|--------|-------------|
| File Miner | `fileminer` | Scan directories for file type mismatches and metadata anomalies |
| Hash It | `hashit` | Generate MD5, SHA1, and SHA256 for a single file |
| mzHash | `mzhash` | Recursively hash all files in a directory |
| Extract Samples | `extract_samples` | Extract files from password-protected malware archives |

## Recommended Workflow

For initial triage of an unknown file:
1. `fileanalyzer` — establish baseline: hashes, entropy, PE headers
2. `mstrings` — extract strings, look for IOCs and ATT&CK technique indicators
3. `malhash` — check community threat intelligence
4. `nsrlquery` — confirm or rule out known-good status

## Environment Notes

- MalChela integrates with REMnux tools; use REMnux CLI tools in conjunction as needed
- Case management is available via the MalChela GUI if a graphical session is active