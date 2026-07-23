### Prerequisites

- Rust and Cargo — [rustup.rs](https://rustup.rs/)
- Git
- Unix-like environment (Linux, macOS, or Windows with WSL2)

For CLI-only installations (WSL, Raspberry Pi, etc.), Rust can be installed with:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### System Dependencies

**Linux**

```bash
sudo apt install openssl libssl-dev clang yara libyara-dev libjansson-dev pkg-config build-essential libglib2.0-dev libgtk-3-dev
```

**macOS**

```bash
brew install openssl yara pkg-config gtk+3 glib
```

> ⚠️ YARA 4.2 or greater is required. Before building, point the build at Homebrew's YARA prefix:
>
> ```bash
> export YARA_LIBRARY_PATH=$(brew --prefix yara)/lib
> export BINDGEN_EXTRA_CLANG_ARGS="-I$(brew --prefix yara)/include"
> ```

These packages cover YARA/YARA-X support, native libraries used by Rust crates that link against them (e.g. TShark/glib), and TShark integration.

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
./setup-server.sh
```

Then start the server:

```bash
./start-server.sh
```

The PWA will be accessible from any browser on the local network.

**CLI**

```bash
./target/release/malchela
```

The CLI is retained for scripting and automation use cases.

> ⚠️ **Important:** MalChela binaries must be invoked from the project root directory. Always use `cd /path/to/MalChela && ./target/release/<binary>` rather than calling the binary directly from another path. This is required for correct resolution of API key files, YARA rules, and Sigma rules — all of which are resolved relative to the project root. API keys are read exclusively from files under `api/`; environment variables are not supported.

### Windows Notes

- Best experience via WSL2.
- As of October 2025, both the MalChela CLI and PWA operate on Windows under WSL2.
- The web interface is accessible via any browser on Windows (WSL2 recommended for running the server).

### What's Next

- [Case Management](cases.md) — no need to start with a file or folder; any tool result can be saved to a case.
- [tools.yaml Configuration](configuration/tools-yaml.md) — add third-party or custom tools to the GUI.
- [REMnux Mode](remnux.md) — a REMnux-tailored `tools.yaml` is loaded automatically when MalChela runs on a REMnux system.
- [Offline Mode](configuration/offline-mode.md) — run fully air-gapped, with all network calls skipped at the source.
- [AI Integration & MCP Support](mcp.md) — expose the full tool suite to Claude and other AI agents.
