### Prerequisites

	•	Rust and Cargo
	•	Git
	•	Unix-like environment (Linux, macOS, or Windows with WSL)

### System Dependencies (Recommended)

To ensure all tools build and run correctly, install the following packages (especially for Linux/REMnux):

```bash
sudo apt install openssl libssl-dev clang yara libyara-dev pkg-config build-essential libglib2.0-dev libgtk-3-dev ssdeep
```

These are required for:
- YARA and YARA-X support
- Building Rust crates that link to native libraries (e.g., GUI dependencies)
- TShark integration (via GTK/glib)
- `ssdeep` is used for fuzzy hashing in tools like `fileanalyzer`. If not installed, fuzzy hash results may be unavailable.

### Clone the Repository
```
git clone https://github.com/dwmetz/MalChela.git

cd MalChela
```
### Build Tools

```
cargo build --release                  # Build all tools in release mode
cargo build -p fileanalyzer --release # Build an individual tool in release mode
```

### One-Click Release Build (Recommended)

To build **all tools** in release mode in one step, use the script in the workspace root:

```bash
chmod +x release.sh
./release.sh
```

This will compile every core tool and generate optimized release binaries under `target/release/`. This is especially useful before first use of the GUI or case features, which rely on prebuilt binaries.

> ⚠️ Using `--release` is highly recommended to ensure optimal performance and avoid unexpected behavior when launching tools from the GUI.
### Windows Notes

	•	Best experience via WSL2
	•	GUI is not supported natively on Windows
