# Privacy Policy

**MalChela** is an open-source malware analysis toolkit. This policy describes how MalChela handles data when used as a standalone tool or as a Claude Code plugin via its MCP server integration.

## Data Collection

MalChela does not collect, transmit, or store any personal data. No telemetry, usage analytics, or crash reporting is sent to the developer or any third party.

## Local Storage

API keys for VirusTotal and MalwareBazaar are stored in plain text files (`vt-api.txt`, `mb-api.txt`) in the MalChela project directory on the user's local machine. These files are excluded from version control via `.gitignore` and are never transmitted anywhere other than to the respective API services during lookups.

## Third-Party Services

Some MalChela tools submit data to external services as part of their function:

- **VirusTotal** — File hashes and, in some cases, file content may be submitted for analysis. Use is subject to the [VirusTotal Terms of Service](https://www.virustotal.com/gui/terms-of-service).
- **MalwareBazaar** — File hashes may be queried against the MalwareBazaar database. Use is subject to the [MalwareBazaar Terms of Use](https://bazaar.abuse.ch/terms/).
- **NIST NSRL** — File hashes may be queried against a local copy of the NSRL database. No data is transmitted externally for this function.

Users should review the privacy policies and terms of service of these third-party providers before submitting sensitive or confidential files.

## Claude / MCP Integration

When MalChela is used as a Claude Code plugin via the MCP server, tool inputs and outputs are passed between MalChela and Claude running locally on the user's machine. No additional data is collected or transmitted by MalChela beyond what is described above.

## Changes

This policy may be updated as MalChela's functionality evolves. Changes will be reflected in this file in the MalChela GitHub repository.

## Contact

For questions or concerns, contact the author via [Baker Street Forensics](https://bakerstreetforensics.com) or open an issue on the [MalChela GitHub repository](https://github.com/dwmetz/MalChela).
