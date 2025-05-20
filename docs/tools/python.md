
### Configuring Python-Based Tools (oletools & oledump)

MalChela supports Python-based tools as long as they are properly declared in `tools.yaml`. Below are detailed examples and installation instructions for two commonly used utilities:

#### 🔧 `olevba` (from `oletools`)

**Install via `pipx`:**

```bash
pipx install oletools
```

This installs `olevba` as a standalone CLI tool accessible in your user path.

**`tools.yaml` configuration example:**

```yaml
- name: olevba
  description: “OLE document macro utility”
  command: [“/Users/youruser/.local/bin/olevba”]
  input_type: “file”
  file_position: “last”
  category: “Office Document Analysis”
  optional_args: []
  exec_type: script
```

**Notes:**

- `olevba` is run directly (thanks to pipx)
- No need to specify a Python interpreter in `command`
- Ensure the path to `olevba` is correct and executable

—

#### `oledump` (standalone script)

**Manual installation:**

```bash
mkdir -p ~/Tools/oledump
cd ~/Tools/oledump
curl -O https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py
chmod +x oledump.py
```

> Make sure the script path in `optional_args` is absolute, and that the file is executable if it’s run directly (not through a Python interpreter in `command`).

**Dependencies:**

```bash
python3 -m pip install olefile
```

Alternatively, create a virtual environment to isolate dependencies:

```bash
python3 -m venv ~/venvs/oledump-env
source ~/venvs/oledump-env/bin/activate
pip install olefile
```

**`tools.yaml` configuration example:**

```yaml
- name: oledump
  description: “OLE Document Dump Utility”
  command: [“/usr/local/bin/python3”]
  input_type: “file”
  file_position: “last”
  category: “Office Document Analysis”
  optional_args: [“/Users/youruser/Tools/oledump/oledump.py”]
  exec_type: script
```

**Notes:**

- The GUI ensures correct argument order: `python oledump.py <input_file>`
- `command` points to the Python interpreter
- `optional_args` contains the path to the script
