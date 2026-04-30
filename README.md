<div align="center">
 <img style="padding:0;vertical-align:bottom;" height="400" width="400" src="images/malchela_steampunk.png"/>
 <p>
 <h1>
  MalChela v4.0
 </h1>
  <h4>
      A YARA &amp; Malware Analysis Toolkit written in Rust.
   </h4>
<p>

 Check out the new [MalChela instructional series](https://www.youtube.com/playlist?list=PL__KsCEzV6Ae5jA-YObTmvZEKuu-rkON6) on YouTube 
 
<p>
 </div>
<div align="center">
  <table>
    <tr>
      <td><img src="images/malchela_screenshot.png" style="height:280px; width:auto;"></td>
      <td><img src="images/malchela_cli_screenshot.png" style="height:280px; width:auto;"></td>
    </tr>
    <tr>
      <td align="center"><strong>GUI View</strong></td>
      <td align="center"><strong>CLI View</strong></td>
    </tr>
  </table>
</div>



<h3>Features:</h3>

| Program             | Function |
|---------------------|----------|
| Combine YARA        | Combines all `.yara`/`.yar` files in a directory into a single rule file |
| Extract Samples     | Recursively extracts password-protected malware archives (ZIP/RAR) using common passwords |
| File Analyzer       | Analyzes a file for hashes, entropy, PE structure, fuzzy hashes, YARA matches, NSRL lookup, and VirusTotal status |
| File Miner          | Scans a folder for file type mismatches and metadata |
| Hash It             | Generates MD5, SHA1, and SHA256 hashes for a single file |
| Hash Check          | Checks if a given hash exists in a provided hash set file |
| Threat Intel Query  | Multi-source hash **and URL** lookup. Hash sources: VirusTotal, MalwareBazaar, OTX, Hybrid Analysis, FileScan.IO, Malshare, MetaDefender, ObjectiveSee. URL sources: VirusTotal, urlscan.io, Google Safe Browsing. GUI adds file-to-hash and QR code decode → URL lookup. |
| mStrings            | Extracts strings from a file, applies regex and Sigma rules, maps to MITRE ATT&CK, identifies IOCs, and includes built-in MITRE Technique lookup |
| mzhash              | Recursively hashes files with MZ headers using MD5 — ideal for gold build or known-bad corpus generation |
| mzcount             | Recursively counts files by format (MZ, ZIP, PDF, etc.) using header/YARA detection |
| nsrlquery           | Queries an MD5 hash against the NSRL database to determine if it's known-good |
| strings_to_yara     | Prompts for metadata and a string list to generate a YARA rule |
| xmzhash             | Recursively hashes files that are *not* MZ, ZIP, or PDF — ideal for non-Windows malware corpus |

*Threat Intel Query supports optional API keys for VirusTotal, MalwareBazaar, OTX, and additional sources. Sources without configured keys are skipped automatically.*

<h3>About:</h3>

> **mal** — malware  
> **chela** — "crab hand"  
> A chela on a crab is the scientific term for a claw or pincer. It's a specialized appendage, typically found on the first pair of legs, used for grasping, defense, and manipulating things — just like these programs.

<h3>Dependencies:</h3>

Linux
```
sudo apt install openssl libssl-dev clang yara libyara-dev libjansson-dev pkg-config build-essential libglib2.0-dev libgtk-3-dev
```

Mac
```
brew install openssl yara pkg-config gtk+3 glib
```
Note: YARA 4.2> required.
Before building, point the build to to Homebrew's YARA prefix
```
export YARA_LIBRARY_PATH=$(brew --prefix yara)/lib
export BINDGEN_EXTRA_CLANG_ARGS="-I$(brew --prefix yara)/include"
```

<h3>Installation &amp; Usage:</h3>

Install Rust — https://rustup.rs/

For CLI only installations (WSL, Raspberry Pi, etc.):

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository and build:

```
git clone https://github.com/dwmetz/MalChela.git
cd MalChela
chmod +x release.sh
./release.sh  # Builds all programs in release mode (recommended)
```

If you cloned MalChela before 17-Apr-2026, you may see a diverging branches error when pulling. Run `git fetch origin && git reset --hard origin/main` to resync. This was a one-time history rewrite to remove a large file.

<h3>Run:</h3>

```
./target/release/malchela
```

or

```
./target/release/MalChelaGUI
```

ℹ️ It is recommended to build and run MalChela in `--release` mode to ensure GUI and subtools function optimally.

> ⚠️ **Important:** MalChela binaries must be invoked from the project root directory. Always use `cd /path/to/MalChela && ./target/release/<binary>` rather than calling the binary directly from another path. This is required for correct resolution of API key files (`vt-api.txt`, `mb-api.txt`), YARA rules, and Sigma rules — all of which are resolved relative to the project root. API keys are read exclusively from these files; environment variables are not supported.

---

### Case Management (v3.0)

MalChela v3.0 introduces a full-featured case system:

- Track files, tools run, and notes under a unified `case.yaml`
- Auto-save tool output under `saved_output/cases/<case-name>/`
- Integrated tagging, search, and scratchpad with VS Code support
- Seamless case loading and archiving in GUI mode

---

### 🤖 AI Integration &amp; MCP Support (v3.1.0)

MalChela v3.1.0 introduces support for AI-assisted malware analysis through the **Model Context Protocol (MCP)**, exposing all 13 MalChela tools to AI agents like Claude. Three deployment paths are supported depending on your environment:

---

#### Path 1: Native MCP Server (Claude Desktop on macOS)

A Node.js MCP server exposes all MalChela tools directly to Claude Desktop on macOS with no additional infrastructure required.

**Setup:**

```
cd mcp/
npm install
```

Configure Claude Desktop to load the server by adding it to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "malchela": {
      "command": "node",
      "args": ["/path/to/MalChela/mcp/server.js"]
    }
  }
}
```

See [`mcp/README.md`](mcp/README.md) for full configuration details.

---

#### Path 2: Kali MCP Server (Remote Linux host / Raspberry Pi)

A two-layer architecture for running MalChela on a remote Kali Linux system (e.g., a Raspberry Pi forensics toolkit) and exposing it to Claude Desktop via MCP.

- **`mcp_server.py`** — FastMCP frontend, receives tool calls and forwards them
- **`kali_server.py`** — Flask backend, executes MalChela binaries on the Kali host

**Setup on the Kali host:**

```
cd /usr/share/mcp-kali-server/
pip install -r requirements.txt
python3 kali_server.py
```

Configure `mcp_server.py` with the host's IP and start it. Then point Claude Desktop at `mcp_server.py` as the MCP server.

See [`mcp/README.md`](mcp/README.md) for full setup and configuration.

---

#### Path 3: OpenCode / AGENTS.md (REMnux / Agentic CLI)

For agentic coding environments and CLI-based AI tools, MalChela ships with an `AGENTS.md` file describing all available tools, their arguments, and usage patterns. This allows tools like OpenCode to discover and invoke MalChela automatically.

On REMnux, OpenCode can be pointed at the MalChela directory and will use `AGENTS.md` to drive analysis workflows autonomously.

---

For a detailed walkthrough of all three approaches, see the blog post: [**MalChela Meets AI: Three Paths to Smarter Malware Analysis**](https://bakerstreetforensics.com)

---

<h3>🔧 Adding Custom Tools:</h3>

You can extend MalChela by editing the `tools.yaml` file to add third-party or custom tools to the GUI. This flexible configuration supports binaries, Python scripts, and Rust-based programs.

Each entry defines the tool's name, category, execution type, how input is passed (file, folder, or hash), and any optional arguments. Here are a few sample entries:

```yaml
- name: capa
  description: "Detects capabilities in binaries via rules"
  command: ["capa"]
  input_type: "file"
  category: "File Analysis"
  exec_type: binary
  file_position: "last"
  optional_args: []

- name: strings
  description: "Extracts printable strings from binaries"
  command: ["strings"]
  input_type: "file"
  category: "Utilities"
  exec_type: binary
  file_position: "first"
  optional_args: []

- name: pdf-parser
  description: "Parses and analyzes suspicious PDF structures"
  command: ["python3"]
  input_type: "file"
  category: "PDF Analysis"
  exec_type: script
  file_position: "last"
  optional_args: ["tools/pdf-parser/pdf-parser.py"]
```
---
<h3> 🦀 **REMnux Mode:**  </h3>


When run on a REMnux system, MalChela can load a REMnux-specific `tools.yaml` file tailored for the built-in tools available in that distro. This ensures smoother setup with minimal configuration required.

📝 **Notes:**
- Tools must be in your system `PATH` or include a full/relative path.
- `exec_type` must be one of: `cargo`, `binary`, or `script`.
- `file_position` indicates where the input is placed in the command (`first` or `last`).
- See the [MalChela User Guide](https://dwmetz.github.io/MalChela/) for detailed configuration examples and workflows.

---

<h3>Enhanced Tool Support:</h3>

MalChela includes improved integration with the following third-party tools:

- **Volatility 3**: Dynamic plugin builder, argument templating, and output directory selection.
- **TShark**: Visual reference panel and support for capturing filtered traffic with custom syntax.
- **YARA-X**: Smart rule matching with improved argument handling and REMnux-compatible default configuration.

These enhancements make working with memory images, PCAPs, and YARA rules more streamlined for forensic workflows.

---

#### Platform Support:

Successfully tested on macOS (Apple Silicon), Ubuntu, and Raspberry Pi.  

YARA version 4.2 or greater is required.

**Windows:** As of October 2025, both MalChela CLI and GUI operate on Windows under WSL2. MalChelaGUI improvements for WSL included in v3.1.1.
