## 🛠 Installation

### Prerequisites

	•	Rust and Cargo
	•	Git
	•	Unix-like environment (Linux, macOS, or Windows with WSL)

### 🔗 System Dependencies (Recommended)

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
cargo build                 # Build all tools
cargo build -p fileanalyzer # Build individual tool
```
### Windows Notes

	•	Best experience via WSL2
	•	GUI is not supported natively on Windows
