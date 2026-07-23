# Navigation

A quick reference for getting around the MalChela web interface: what greets you on first launch, and what each button in the top toolbar does.

---

## Home & At a Glance

Home is the PWA's default/startup screen — it displays the MalChela ASCII art, a rotating koan, and an **At a Glance** stats card summarizing the current workspace at a glance:

| Field | Shows |
|---|---|
| Cases | Open vs. closed case counts |
| Detections | Number of rules currently loaded from `detections.yaml` |
| API Keys | How many of the supported API key files are configured (e.g. `4/12`) |
| MalChela Tools | How many cargo-built MalChela binaries are present in `target/release/`, out of the total `tools.yaml` expects (e.g. `17/17`) — this is the count referenced in [Installation](install.md) and troubleshooting build issues |
| Integrations | How many configured third-party tools (from `tools.yaml`) are actually found on `PATH` |
| Update Check | Whether a newer commit is available on the tracked branch — skipped automatically when [Offline Mode](configuration/offline-mode.md) is enabled |

The Home screen reloads automatically whenever you click the <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/home.svg" width="16" height="16"></span> **Home** button in the toolbar, refreshing all of the above.

---

## Top Toolbar

Left to right:

| Icon | Button | Opens |
|---|---|---|
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/home.svg" width="16" height="16"></span> | Home | The landing screen — ASCII art, koan, and the **At a Glance** card described above. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/analyze.png" width="16" height="16"></span> | Analyze | The [Analyze](coretools/analyze.md) target picker — point it at a file, folder, `.app` bundle, `.dmg`, or `.pkg` and it auto-runs every tool File Miner suggests. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/cases.png" width="16" height="16"></span> | Cases | The [case management](cases.md) browser. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/hide.png" width="16" height="16"></span> | Hide Tools Panel | Collapses/expands the left tool sidebar, so the console can use the full width. Persists across reloads. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/about.svg" width="16" height="16"></span> | About | Version and feature summary. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/config.svg" width="16" height="16"></span> | Configuration | Dropdown with three items (see below). |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/upload.svg" width="16" height="16"></span> | Upload Files | Upload a local file to the server for analysis — useful when the browser and the MalChela server aren't on the same machine. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/mitre.svg" width="16" height="16"></span> | MITRE Lookup | The standalone [MITRE ATT&CK lookup panel](coretools/mitre_lookup.md) — no internet required. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/notebook.svg" width="16" height="16"></span> | Notebook | A scratchpad for recording strings/IOCs/notes across a session. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/reports.svg" width="16" height="16"></span> | View Reports | Browse and open any previously saved report directly. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/guide.svg" width="16" height="16"></span> | User Guide | Opens this documentation site in a new tab. |

On narrow screens, everything past the first divider collapses into a **⋯ More** overflow menu with the same items.

### Configuration Dropdown

| Icon | Item | Opens |
|---|---|---|
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/server.svg" width="16" height="16"></span> | Server Config | The server URL/connection settings, and the [Offline Mode](configuration/offline-mode.md) toggle. |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/api.svg" width="16" height="16"></span> | API Keys | See [API Configuration](configuration/api-configuration.md). |
| <span style="display:inline-block;background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:3px;vertical-align:middle;"><img src="../images/icons/tools.svg" width="16" height="16"></span> | tools.yaml | See the [tools.yaml reference](configuration/tools-yaml.md). |
