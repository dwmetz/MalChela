# Privacy Policy

**MalChela** is an open-source malware analysis toolkit. This policy describes how MalChela handles data when used as a standalone tool or as a Claude Code plugin via its MCP server integration.

## Data Collection

MalChela does not collect, transmit, or store any personal data. No telemetry, usage analytics, or crash reporting is sent to the developer or any third party.

## Local Storage

API keys are stored in plain text files in the `api/` subdirectory of the MalChela project directory on the user's local machine. These files are excluded from version control via `.gitignore` and are never transmitted anywhere other than to their respective API services during lookups.

## Third-Party Services

Some MalChela tools submit data to external services as part of their function. All submissions are initiated explicitly by the user running a tool — MalChela makes no background requests.

**Hash lookups (file hashes submitted):**

- **VirusTotal** — File hashes and, in some cases, file content may be submitted for analysis. [Terms of Service](https://www.virustotal.com/gui/terms-of-service)
- **MalwareBazaar** — File hashes queried against the MalwareBazaar database. [Terms of Use](https://bazaar.abuse.ch/terms/)
- **AlienVault OTX** — File hashes queried for threat intelligence pulses. [Privacy Policy](https://otx.alienvault.com/about/privacy-policy)
- **MetaDefender Cloud** — File hashes queried for multi-engine scan results. [Privacy Policy](https://www.opswat.com/legal/privacy-policy)
- **Hybrid Analysis** — File hashes queried for sandbox analysis results. [Terms](https://hybrid-analysis.com/terms)
- **Triage** — File hashes queried for sandbox reports. [Privacy Policy](https://tria.ge/privacy)
- **FileScan.IO** — File hashes queried for scan results. [Terms](https://www.filescan.io/pages/terms)
- **Malshare** — File hashes queried against the Malshare repository. [About](https://malshare.com/about.php)

**URL lookups (URLs submitted):**

- **urlscan.io** — *opt-in.* Searches urlscan.io's archive for existing scans of the URL. The full URL (including any query string) is sent; nothing is submitted for a new scan. It works without a key (lookups tied to your public IP) or with an optional key from a urlscan.io account (higher rate limits; lookups also tied to that account). [Privacy Policy](https://urlscan.io/about/)
- **Google Safe Browsing** — URLs checked against Google's Safe Browsing list. [Privacy Policy](https://policies.google.com/privacy)

**Local only (no external transmission):**

- **NIST NSRL** — File hashes queried against a local copy of the NSRL database. No data leaves the user's machine for this function.

Users should review the privacy policies and terms of service of these third-party providers before submitting sensitive or confidential files. Keyed services are contacted only when the user has configured an API key for them. Keyless services that send the looked-up value to a third party (currently urlscan.io) are **off until the user opts in**, in the web interface (Configuration → Keyless threat-intel sources, or the source checkbox) or with `tiquery --enable-keyless <id>`. The choice is saved in `api/keyless_sources.txt` and shared by the web interface, the CLI, and the Claude plugin; configuring an optional key for such a source also counts as opting in unless the user has opted out. Objective-See needs no key and sends nothing about the sample: its public catalogue is downloaded and matched locally. [Offline Mode](docs/configuration/offline-mode.md) turns off every external lookup.

## Claude / MCP Integration

When MalChela is used as a Claude Code plugin via the MCP server, tool inputs and outputs are passed between MalChela and Claude running locally on the user's machine. No additional data is collected or transmitted by MalChela beyond what is described above.

## Changes

This policy may be updated as MalChela's functionality evolves. Changes will be reflected in this file in the MalChela GitHub repository.

## Contact

For questions or concerns, contact the author via [Baker Street Forensics](https://bakerstreetforensics.com) or open an issue on the [MalChela GitHub repository](https://github.com/dwmetz/MalChela).
