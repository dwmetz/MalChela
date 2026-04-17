Threat Intel Query (`tiquery`) is a multi-source threat intelligence hash lookup tool. It queries multiple threat intelligence platforms in parallel and presents results in a unified table — giving analysts a fast, consolidated view of whether a hash is known, what family it belongs to, and how widely it has been detected.

---

### Supported Sources

| ID  | Source           | Tier | Key Required |
|-----|------------------|------|--------------|
| mb  | MalwareBazaar    | 1    | Optional     |
| vt  | VirusTotal       | 1    | Yes          |
| otx | AlienVault OTX   | 1    | Yes          |
| iq  | InQuest Labs     | 1    | No           |
| ha  | Hybrid Analysis  | 2    | Yes          |
| fs  | FileScan.IO      | 2    | Yes          |
| ms  | Malshare         | 2    | Yes          |
| os  | Objective-See    | 2    | No (SHA256 only) |

All sources with a configured API key are queried automatically. No flag is needed to enable Tier 2 sources — if the key file exists, the source is included. Pass `--sources` to restrict the query to specific sources.

---

### 🔧 CLI Syntax

```bash
# Basic lookup — queries all sources with a configured API key automatically
tiquery <hash>

# Restrict to specific sources
tiquery <hash> --sources mb,vt,ha,fs

# Include per-engine VirusTotal detections
tiquery <hash> --verbose-vt

# Output as JSON
tiquery <hash> --json

# Output as CSV
tiquery <hash> --csv

# Save text report
tiquery <hash> -o -t

# Save report to a case folder
tiquery <hash> -o -t --case Case123

# Download sample from MalwareBazaar (SHA256 only)
tiquery <hash> -d
```

Accepts MD5, SHA1, and SHA256 hashes. If no hash is provided, the tool will prompt interactively.

---

### Output

Results are presented in a matrix showing source, status, malware family/tags, detection summary, and a reference link:

```
  tiquery <hash> (SHA256)
  ────────  ────────────  ──────────────────────  ─────────────  ────────────────────────────────────────
  Source    Status        Family / Tags           Detections     Reference
  ────────  ────────────  ──────────────────────  ─────────────  ────────────────────────────────────────
  MB        FOUND         Emotet                  ...            https://bazaar.abuse.ch/sample/...
  VT        FOUND         Trojan.Emotet           58/72          https://virustotal.com/gui/file/...
  OTX       FOUND                                 4 pulses       https://otx.alienvault.com/...
  IQ        NOT FOUND                                            -
```

---

### Saving Output

Use `-o` to save output and include one of the following format flags:

- `-t` → Save as `.txt`

When `--case` is used, output is saved to:

```
saved_output/cases/Case123/tiquery/
```

Otherwise, reports are saved to:

```
saved_output/tiquery/
```

---

### API Keys

`tiquery` uses the same `api/` key file convention as other MalChela tools. Each source reads from its own file:

```
api/vt-api.txt
api/mb-api.txt
api/otx-api.txt
api/ha-api.txt
api/fs-api.txt
api/ms-api.txt
```

Keys can be managed via the **API Keys** panel in the MalChela GUI (Configuration menu → API Keys) or by placing the key directly in the appropriate file.

See [API Configuration](/Configuration/api-configuration.md) for details.

---

### Bulk Lookup

The MalChela GUI includes a **Bulk Lookup** mode in the TiQuery panel. Point it at a `.txt` or `.csv` file containing hashes (one per line, or mixed with other content — the tool extracts valid MD5/SHA1/SHA256 values automatically) and run all lookups in a single operation. Results are displayed in a consolidated grid.
