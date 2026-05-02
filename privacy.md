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
- **InQuest Labs** — File hashes queried for malware intelligence. [Terms](https://labs.inquest.net)
- **MetaDefender Cloud** — File hashes queried for multi-engine scan results. [Privacy Policy](https://www.opswat.com/legal/privacy-policy)
- **Malpedia** — File hashes queried for malware family attribution. [About](https://malpedia.caad.fkie.fraunhofer.de/about)
- **Hybrid Analysis** — File hashes queried for sandbox analysis results. [Terms](https://hybrid-analysis.com/terms)
- **MWDB** — File hashes queried against the CERT.pl malware database. [About](https://mwdb.cert.pl)
- **Triage** — File hashes queried for sandbox reports. [Privacy Policy](https://tria.ge/privacy)
- **FileScan.IO** — File hashes queried for scan results. [Terms](https://www.filescan.io/pages/terms)
- **Malshare** — File hashes queried against the Malshare repository. [About](https://malshare.com/about.php)

**URL lookups (URLs submitted):**

- **urlscan.io** — URLs submitted for scanning and analysis. [Privacy Policy](https://urlscan.io/about/)
- **Google Safe Browsing** — URLs checked against Google's Safe Browsing list. [Privacy Policy](https://policies.google.com/privacy)

**Local only (no external transmission):**

- **NIST NSRL** — File hashes queried against a local copy of the NSRL database. No data leaves the user's machine for this function.

Users should review the privacy policies and terms of service of these third-party providers before submitting sensitive or confidential files. All external lookups require an API key configured by the user — no key, no submission.

## Claude / MCP Integration

When MalChela is used as a Claude Code plugin via the MCP server, tool inputs and outputs are passed between MalChela and Claude running locally on the user's machine. No additional data is collected or transmitted by MalChela beyond what is described above.

## Changes

This policy may be updated as MalChela's functionality evolves. Changes will be reflected in this file in the MalChela GitHub repository.

## Contact

For questions or concerns, contact the author via [Baker Street Forensics](https://bakerstreetforensics.com) or open an issue on the [MalChela GitHub repository](https://github.com/dwmetz/MalChela).
