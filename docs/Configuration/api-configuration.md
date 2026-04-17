# API Configuration

Some tools within MalChela rely on external services. In order to use these integrations, you must configure your API credentials.

## Tools That Use API Keys

| Tool          | Service          | Purpose                                       |
|---------------|------------------|-----------------------------------------------|
| `fileanalyzer`| VirusTotal       | Hash lookup                                   |
| `tiquery`     | VirusTotal       | Multi-source hash lookup (Tier 1)             |
| `tiquery`     | MalwareBazaar    | Multi-source hash lookup (Tier 1)             |
| `tiquery`     | AlienVault OTX   | Multi-source hash lookup (Tier 1)             |
| `tiquery`     | Hybrid Analysis  | Multi-source hash lookup (Tier 2)             |
| `tiquery`     | FileScan.IO      | Multi-source hash lookup (Tier 2)             |
| `tiquery`     | Malshare         | Multi-source hash lookup (Tier 2)             |
| `tiquery`     | MetaDefender     | Multi-source hash lookup (Tier 2)             |

---

## Where to Configure

MalChela uses two plain text files to store API keys for its third-party integrations:

```
vt-api.txt
mb-api.txt
```

These files should be placed in the **root of your MalChela workspace**, alongside `tools.yaml`. Each file should contain a single line with your API key.

These keys will be read at runtime by tools such as `tiquery` to enable external lookups.

---
![API Configuration Utility](../images/api_configuration.png)

**Figure 3.2:** API Configuration Utility

## Managing Your Keys with the Configuration Utility

The MalChela GUI includes a built-in Configuration Panel that lets you easily **Create or update API key files** without opening a text editor.

Look for the **API Key Management** section in the Configuration Panel. Changes take effect immediately and persist across sessions.

---

## Best Practices

- **Keep these files private.** Do not commit them to Git or share them publicly.

---

> If a tool requires an API key but none is found, it will log a warning and skip external requests.
