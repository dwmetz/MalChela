# Integrating Third-Party Tools

MalChela supports the integration of external tools such as Python-based utilities (`oletools`, `oledump`) and high-performance YARA engines (`yara-x`). These tools expand MalChela’s capabilities beyond its native Rust-based toolset.
> Tools now require `exec_type` (e.g., `cargo`, `binary`, `script`) to define how they are launched, and `file_position` to clarify argument order when needed.

To integrate a new tool into the GUI, ensure the tool:
- Accepts CLI arguments in the form `toolname [args] [input]`
- Outputs results to stdout
- Is installed and available in `$PATH`

```yaml
- name: toolname
  description: “Short summary of tool purpose”
  command: [“toolname”]
  input_type: file  # or folder or hash
  category: “File Analysis”  # or other GUI category
  optional_args: []
  exec_type: binary  # or cargo / script
  file_position: last  # or first, if required
```

> You can switch to a prebuilt `tools.yaml` for REMnux mode via the GUI configuration panel — useful for quick setup in forensic VMs.
