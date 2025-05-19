
## Tool Configuration

MalChela uses a central `tools.yaml` file to define which tools appear in the GUI, along with their launch method, input types, categories, and optional arguments. This YAML-driven approach allows full control without editing source code.

### Key Fields in Each Tool Entry

| Field         | Purpose                                                          |
|---------------|------------------------------------------------------------------|
| name          | Internal and display name of the tool                            |
| description   | Shown in GUI for clarity                                         |
| command       | How the tool is launched (binary path or interpreter)           |
| exec_type     | One of `cargo`, `binary`, or `script`                            |
| input_type    | One of `file`, `folder`, or `hash`                               |
| file_position | Controls argument ordering                                       |
| optional_args | Additional CLI arguments passed to the tool                      |
| category      | Grouping used in the GUI left panel                              |

> ⚠️ All fields except `optional_args` are required.


## Swapping Configs: REMnux Mode and Beyond

MalChela supports easy switching between tool configurations via the GUI.

To switch:

1. Open the **Configuration Panel**
2. Use **“Select tools.yaml”** to point to a different config
3. Restart the GUI or reload tools

This allows forensic VMs like REMnux to use a tailored toolset while keeping your default config untouched.

> A bundled `tools_remnux.yaml` is included in the repo for convenience.


#### Key Tips

- Always use `file_position: “last”` unless the tool expects input before the script
- For scripts requiring Python, keep the script path in `optional_args[0]`
- For tools installed via `pipx`, reference the binary path directly in `command`



## Backing Up and Restoring tool.yaml

The MalChela GUI provides built-in functionality to back up and restore your `tools.yaml` configuration file.

### Backup

To create a backup of your current `tools.yaml`:

1. Open the **Configuration Panel**
2. Click the **“Back Up Config”** button
3. A timestamped copy of `tools.yaml` will be saved to the default location

You’ll see a confirmation message when the operation completes successfully.

### Restore

To restore from a previous backup:

1. Click the **“Restore Config”** button in the Configuration Panel
2. Select a previously saved backup file
3. The selected file will overwrite the current configuration

> This feature makes it easy to experiment with custom tool setups while retaining a safety net for recovery.