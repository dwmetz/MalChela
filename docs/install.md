### Prerequisites

- Rust and Cargo — [rustup.rs](https://rustup.rs/)
- Git
- Unix-like environment (Linux, macOS, or Windows with WSL2)

For CLI-only installations (WSL, Raspberry Pi, etc.), Rust can be installed with:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### System Dependencies

MalChela's YARA engine is [YARA-X](https://virustotal.github.io/yara-x/), compiled in as a Rust crate.  There is no system YARA library to install and no `YARA_LIBRARY_PATH` or `BINDGEN_EXTRA_CLANG_ARGS` to set, and HTTPS uses rustls, so OpenSSL isn't needed either.  The build only needs a C compiler and `make`, for the few bundled C libraries (ssdeep, bzip2, LZFSE, and xz).

**Linux**

```bash
sudo apt install build-essential pkg-config
```

**macOS**

```bash
xcode-select --install
```

> **Upgrading from v4.3 or earlier?**  The old `yara`, `libyara-dev`, `libjansson-dev`, `openssl`, `clang`, GTK, and GLib packages are no longer used by the build.  You can leave them installed, and you can drop the `YARA_LIBRARY_PATH` and `BINDGEN_EXTRA_CLANG_ARGS` exports from your shell profile.

Third-party integrations (TShark, Volatility 3, the YARA-X CLI, and others in `tools.yaml`) are optional and installed separately.  See [Integrating Third Party Tools](tools/index.md) for each one.

### Clone the Repository

```bash
git clone https://github.com/dwmetz/MalChela.git
cd MalChela
```

> If you cloned MalChela before 17-Apr-2026, you may see a diverging branches error when pulling. Run `git fetch origin && git reset --hard origin/main` to resync — this was a one-time history rewrite to remove a large file.

### Build Tools

To build **all tools** in release mode in one step, use the script in the workspace root:

```bash
chmod +x release.sh
./release.sh
```

This compiles every core tool and generates optimized release binaries under `target/release/`. This is required before first use of the web interface or case features, which rely on prebuilt binaries.

Individual tools can also be built on their own:

```bash
cargo build -p fileanalyzer --release
```

> ⚠️ Using `--release` is highly recommended to ensure optimal performance and avoid unexpected behavior when launching tools from the web interface.

### Run

**PWA (recommended)**

On first run, execute the setup script after building the binaries:

```bash
cd server
./setup_server.sh
```

Then start the server:

```bash
./start_server.sh
```

The PWA will be accessible from any browser on the local network.

**CLI**

```bash
./target/release/malchela
```

The CLI is retained for scripting and automation use cases.

> ⚠️ **Important:** MalChela binaries must be invoked from the project root directory. Always use `cd /path/to/MalChela && ./target/release/<binary>` rather than calling the binary directly from another path. This is required for correct resolution of API key files, YARA rules, and Sigma rules — all of which are resolved relative to the project root. API keys are read exclusively from files under `api/`; environment variables are not supported.

### Windows (native)

As of v4.5, MalChela builds and runs natively on Windows, with no WSL required. You need Rust with the MSVC toolchain (from [rustup.rs](https://rustup.rs), plus the Visual Studio C++ build tools it prompts for), Git, and Python 3 (from [python.org](https://www.python.org) with "Add python.exe to PATH" ticked, or `winget install Python.Python.3.12`).

Build, from the MalChela folder in PowerShell or cmd:

```powershell
.\release.ps1            # or: release.cmd   (add -Unattended to skip the prompt)
```

or build the whole workspace in one go with `cargo build --release --workspace`. Binaries land in `target\release\` as `.exe` files.

Start the PWA server:

```powershell
server\start_server.cmd  # or, in PowerShell: .\server\start_server.ps1
```

The first run creates `server\venv` and installs Flask, flask-cors, and PyYAML. No `server_config.yaml` is needed: the server finds the MalChela folder relative to itself and uses your user folder as the file-browser root. To change the port or browser root, create `server\server_config.yaml` (see the setup steps above for the fields) or set `MALCHELA_PORT` / `MALCHELA_BROWSER_ROOT`.

- The `.cmd` wrappers run the PowerShell scripts with `-ExecutionPolicy Bypass`, so they work even where `.ps1` scripts are blocked by policy.
- External tools (capa, YARA, tshark, and so on) are found through your `PATH`.
- macOS-specific tools (Code Sign Check, Mach-O Info) build on Windows but are of limited use there.
- WSL2 still works if you prefer a Linux environment.

### What's Next

- [Case Management](cases.md) — no need to start with a file or folder; any tool result can be saved to a case.
- [tools.yaml Configuration](configuration/tools-yaml.md) — add third-party or custom tools to the GUI.
- [REMnux Mode](remnux.md) — a REMnux-tailored `tools.yaml` is loaded automatically when MalChela runs on a REMnux system.
- [Offline Mode](configuration/offline-mode.md) — run fully air-gapped, with all network calls skipped at the source.
- [AI Integration & MCP Support](mcp.md) — expose the full tool suite to Claude and other AI agents.
