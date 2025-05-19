
## ⚙️ Tool Configuration Mode (YAML)

MalChela uses a central `tools.yaml` file to define which tools appear in the GUI, along with their launch method, input types, categories, and optional arguments. This YAML-driven approach allows full control without editing source code.

### Key Fields in Each Tool Entry

| Field           | Purpose                                               |
|——————|-——————————————————|
| `name`          | Internal and display name of the tool                |
| `description`   | Shown in GUI for clarity                             |
| `command`       | How the tool is launched (binary path or interpreter)|
| `exec_type`     | One of `cargo`, `binary`, or `script`                |
| `input_type`    | One of `file`, `folder`, or `hash`                   |
| `file_position` | Controls argument ordering                           |
| `optional_args` | Additional CLI arguments passed to the tool          |
| `category`      | Grouping used in the GUI left panel                  |

> ⚠️ All fields except `optional_args` are required.


## Swapping Configs: REMnux Mode and Beyond

MalChela supports easy switching between tool configurations via the GUI.

To switch:

1. Open the **Configuration Panel**
2. Use **“Select tools.yaml”** to point to a different config
3. Restart the GUI or reload tools

This allows forensic VMs like REMnux to use a tailored toolset while keeping your default config untouched.

> A bundled `tools_remnux.yaml` is included in the repo for convenience.

#### ✅ Key Tips

- Always use `file_position: “last”` unless the tool expects input before the script
- For scripts requiring Python, keep the script path in `optional_args[0]`
- For tools installed via `pipx`, reference the binary path directly in `command`