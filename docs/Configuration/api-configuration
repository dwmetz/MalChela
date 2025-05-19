# API Configuration

Some tools within MalChela rely on external services such as **VirusTotal**, **MalwareBazaar**, or other threat intelligence platforms. In order to use these integrations, you must configure your API credentials.

---

## Where to Configure

MalChela reads API keys from a local file named:

```
config/api_keys.yaml
```

This file should live in the root of your MalChela workspace (next to `tools.yaml`).

---

## File Format

The file should be written in standard YAML format. Here is an example:

```yaml
virustotal:
  key: "your-virustotal-api-key"

malwarebazaar:
  key: "your-malwarebazaar-api-key"
```

Each supported tool checks this file at runtime to determine whether it can perform external lookups.

---

## Managing Your Keys

- **Keep this file private.** It should never be committed to a public repo.
- **Use separate keys per environment** (e.g. REMnux vs development laptop) if needed.
- If you omit an API key, the corresponding functionality will be disabled gracefully.

---

## Tools That Use API Keys

| Tool         | Service         | Purpose                                |
|--------------|------------------|----------------------------------------|
| `malhash`    | VirusTotal       | Hash lookup and enrichment             |
| `malhash`    | MalwareBazaar    | Hash lookup and sample classification  |
| _(Planned)_  | Hybrid Analysis  | Future integration for sample scoring  |

> If a tool requires an API key but none is found, it will log a warning and skip external requests.

---

## Troubleshooting

- Ensure the file is named `api_keys.yaml`, not `.yml`
- Make sure there are no tabs — YAML requires spaces
- Watch for quotes around API keys if they contain special characters
