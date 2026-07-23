# Offline Mode

MalChela normally makes a handful of network calls on its own — some obvious (Threat Intel Query's API-key-gated lookups), some less so. Offline Mode is a single switch that skips **every** one of them at the source, before any connection is even attempted. It's built for air-gapped labs and malware analysis scenarios where an unexpected outbound connection attempt — even a harmless, timed-out one — isn't acceptable.

---

## What It Skips

| Tool | Call | Notes |
|------|------|-------|
| `nsrlquery` | `hashlookup.circl.lu` | Despite the name, this is a live lookup against CIRCL's public hash database — not a local NSRL file. No API key involved, so this one is easy to trigger by accident. |
| `tiquery` | Every configured source | Including Objective-See's malware catalogue (`os`), the one source with no API-key gate of its own — it normally attempts a fetch on any cache miss regardless of which keys you've configured. |
| `fileanalyzer` | VirusTotal | A separate embedded check from Threat Intel Query's own VirusTotal source — gated on a VT key being configured, but if one is, plain FileAnalyzer also phones home. |
| Home screen | Update check (`git remote update`) | Runs automatically every time the Home screen loads, since it's the app's default/startup screen. |

Each of these normally fails only after a DNS/connect attempt (and, on a truly air-gapped host, a real timeout). With Offline Mode on, they return a clean "skipped" result immediately instead.

**What it doesn't cover:** anything a *sample itself* might do if executed. Offline Mode only governs MalChela's own lookups — it's not a sandbox or network isolation layer for the malware you're analyzing. Static analysis is unaffected either way, since nothing in that path ever touches the network.

---

## Enabling It

**Web interface:** Configuration menu → **Offline / air-gapped mode** checkbox. Takes effect immediately — no server restart needed, and it stays on across restarts until you turn it off.

**CLI:** set the environment variable before running any tool directly:

```bash
export MALCHELA_OFFLINE=1
cargo run -p nsrlquery -- d41d8cd98f00b204e9800998ecf8427e
```

```
Offline mode (MALCHELA_OFFLINE) — skipped CIRCL Hash Lookup network request.
```

The web interface toggle and the environment variable both work through the same mechanism — enabling it in the Configuration panel sets `MALCHELA_OFFLINE=1` for every tool the server launches on your behalf, so the two are interchangeable depending on how you're driving MalChela.

---

## Where It's Stored

The toggle persists the same way an API key does — a plain file in the workspace's `api/` directory:

```
api/offline_mode.txt
```

Containing `1` (enabled) or `0` (disabled). This file is read fresh on every check, not cached, which is why the web toggle takes effect without a restart.

---

## Reducing Network Dependency Further

Two page-load resources the PWA previously fetched from the internet on every load — the app icon and its webfonts (JetBrains Mono, Share Tech Mono) — are now vendored locally (`server/icons/`, `server/fonts/`) rather than pulled from GitHub/Google Fonts. This isn't gated behind Offline Mode; it's just always local now, which also makes page load faster regardless of connectivity.
