use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::error::Error;
use std::env;
use std::time::Duration;

#[derive(Debug, Deserialize, Default)]
pub struct CommonConfig {
    pub input_type: String,
    pub description: Option<String>,
}

impl CommonConfig {
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let config_content = fs::read_to_string(path)?;
        let config: CommonConfig = serde_yaml::from_str(&config_content)?;
        Ok(config)
    }
}

pub fn get_output_dir(tool_name: &str) -> PathBuf {
    let mut dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    dir.push("saved_output");
    dir.push(tool_name);
    dir
}

/// True when MalChela should make zero outbound network calls — set via the
/// MALCHELA_OFFLINE env var (checked, not just presence-tested, so
/// MALCHELA_OFFLINE=0 in an inherited environment doesn't accidentally
/// enable it). The Python server injects this into every subprocess it
/// launches based on the persisted Configuration screen toggle; set it
/// directly for CLI use (`export MALCHELA_OFFLINE=1`). Every call site that
/// checks this should skip the network attempt entirely — not attempt it
/// and let it time out — so an air-gapped host never even tries to resolve
/// a hostname, and a lab exercise never risks a sample's network access
/// getting confused with MalChela's own lookups.
pub fn is_offline_mode() -> bool {
    env::var("MALCHELA_OFFLINE").map(|v| v == "1").unwrap_or(false)
}

pub fn write_launch_script(script_name: &str, command: &str) -> Result<(), Box<dyn Error>> {
    let mut file = fs::File::create(script_name)?;
    writeln!(file, "#!/bin/bash")?;
    writeln!(file, "{}", command)?;
    Ok(())
}

/// Walk up from the running executable until we find a Cargo.toml containing [workspace].
pub fn find_workspace_root() -> Option<PathBuf> {
    let exe_path = env::current_exe().ok()?;
    let mut dir = exe_path.parent()?.to_path_buf();
    loop {
        let toml = dir.join("Cargo.toml");
        if toml.exists() {
            if let Ok(content) = fs::read_to_string(&toml) {
                if content.contains("[workspace]") {
                    return Some(dir);
                }
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Resolve an API key for `source` (e.g. "vt", "mb", "otx").
///
/// Priority:
///   1. `<workspace>/api/<source>-api.txt`
///   2. `<workspace>/<source>-api.txt`  (legacy — auto-migrated on first hit)
///
/// Returns `None` if no key file is found or the file is empty.
pub fn resolve_api_key(source: &str) -> Option<String> {
    let workspace = find_workspace_root()?;
    let api_dir = workspace.join("api");
    let new_path = api_dir.join(format!("{}-api.txt", source));

    if new_path.exists() {
        return fs::read_to_string(&new_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    // Check legacy location; migrate if found.
    let old_path = workspace.join(format!("{}-api.txt", source));
    if old_path.exists() {
        let key = fs::read_to_string(&old_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;

        let _ = fs::create_dir_all(&api_dir);
        match fs::rename(&old_path, &new_path) {
            Ok(_) => eprintln!(
                "[MalChela] Moved {src}-api.txt → api/{src}-api.txt",
                src = source
            ),
            Err(_) => {
                // rename across devices; fall back to copy + delete
                if fs::copy(&old_path, &new_path).is_ok() {
                    let _ = fs::remove_file(&old_path);
                    eprintln!(
                        "[MalChela] Moved {src}-api.txt → api/{src}-api.txt",
                        src = source
                    );
                }
            }
        }

        return Some(key);
    }

    None
}

/// Ensure a minimal `case.json` exists for `case_name` under
/// `<workspace>/saved_output/cases/<case_name>/case.json`.
///
/// If the file already exists it is left untouched. If it doesn't exist a
/// skeleton is written so the GUI case browser can open the case without error.
pub fn ensure_case_json(case_name: &str) {
    let workspace = match find_workspace_root() {
        Some(p) => p,
        None => return,
    };
    let case_dir = workspace
        .join("saved_output")
        .join("cases")
        .join(case_name);
    let _ = fs::create_dir_all(&case_dir);
    let json_path = case_dir.join("case.json");
    if json_path.exists() {
        return;
    }
    // Built by hand to avoid pulling serde_json into common_config.
    let escaped = case_name.replace('\\', "\\\\").replace('"', "\\\"");
    let skeleton = format!(
        "{{\n  \"name\": \"{}\",\n  \"input_path\": null,\n  \"sha256\": null,\n  \"notes\": \"\"\n}}\n",
        escaped
    );
    let _ = fs::write(&json_path, skeleton);
}

/// Write an API key for `source` into `<workspace>/api/<source>-api.txt`.
pub fn write_api_key(source: &str, key: &str) -> Result<(), Box<dyn Error>> {
    let workspace = find_workspace_root()
        .ok_or("Could not locate MalChela workspace root")?;
    let api_dir = workspace.join("api");
    fs::create_dir_all(&api_dir)?;
    fs::write(api_dir.join(format!("{}-api.txt", source)), key)?;
    Ok(())
}

/// Call at startup to proactively migrate any legacy key files sitting at the
/// workspace root. Silent if nothing needs moving.
pub fn migrate_api_keys() {
    for src in &["vt", "mb", "otx", "ha", "mp", "mw", "tr", "fs", "ms"] {
        let _ = resolve_api_key(src);
    }
}

// ── Case manifest (case.yaml) registration ──────────────────────────────────
//
// case.yaml historically was only ever updated by the web GUI's Python
// server (malchela_server.py::_register_cli_case_output), which scans a
// tool's output directory for recently-modified files after shelling out to
// it. That means any tool run outside the web server — terminal, MCP, shell
// scripts — writes its report correctly but never gets an entry in
// case.yaml's manifest.
//
// register_case_output() closes that gap from the Rust side: a case-aware
// tool calls it directly with the exact path it just wrote, right after
// saving. That sidesteps the web server's mtime-window scanning entirely.
// It's idempotent (dedupes by `path`) and lock-guarded, so it's safe to run
// even if the Python registrar also fires for the same file.

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CaseFileEntry {
    filename: String,
    path: String,
    target: String,
    timestamp: String,
    tool: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CaseManifest {
    created: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    files: Vec<CaseFileEntry>,
    modified: String,
    name: String,
    #[serde(default)]
    notes: String,
    #[serde(default = "default_case_status")]
    status: String,
    #[serde(default)]
    tags: Vec<String>,
}

fn default_case_status() -> String {
    "open".to_string()
}

impl CaseManifest {
    fn new(name: &str, created: &str) -> Self {
        CaseManifest {
            created: created.to_string(),
            description: String::new(),
            files: Vec::new(),
            modified: created.to_string(),
            name: name.to_string(),
            notes: String::new(),
            status: default_case_status(),
            tags: Vec::new(),
        }
    }
}

/// Simple advisory file lock, used so multiple case-aware tool invocations
/// (e.g. run back-to-back by a script) don't race on case.yaml's
/// read-modify-write. Uses `create_new` for an atomic "did I win the lock"
/// check with no extra crate dependency. Steals stale locks older than 10s
/// so a crashed process can't wedge future runs.
struct CaseLock {
    path: PathBuf,
}

impl CaseLock {
    fn acquire(case_dir: &Path) -> Result<Self, Box<dyn Error>> {
        let lock_path = case_dir.join("case.yaml.lock");
        let mut attempts = 0u32;
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(CaseLock { path: lock_path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(meta) = fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = modified.elapsed() {
                                if age.as_secs() > 10 {
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                    }
                    attempts += 1;
                    if attempts > 50 {
                        return Err("Timed out waiting for case.yaml lock".into());
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
    }
}

impl Drop for CaseLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Register a just-written report file into `<case>/case.yaml`'s manifest.
///
/// `tool` — the tool name (matches its output subdirectory, e.g. "macho_info").
/// `case_name` — the active case.
/// `target` — the original input path the tool analyzed (for the entry's context).
/// `output_path` — the exact report file path the tool just wrote.
///
/// Silently no-ops on any I/O error (workspace not found, lock timeout, etc.)
/// rather than failing the tool run — manifest tracking is a convenience,
/// not something that should block analysis output.
pub fn register_case_output(tool: &str, case_name: &str, target: &str, output_path: &Path) {
    let _ = register_case_output_inner(tool, case_name, target, output_path);
}

fn register_case_output_inner(
    tool: &str,
    case_name: &str,
    target: &str,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let workspace = find_workspace_root().ok_or("Could not locate MalChela workspace root")?;
    let case_dir = workspace.join("saved_output").join("cases").join(case_name);
    fs::create_dir_all(&case_dir)?;

    let filename = output_path
        .file_name()
        .ok_or("Output path has no filename")?
        .to_string_lossy()
        .to_string();
    let rel_path = format!("{}/{}", tool, filename);
    let timestamp = chrono::Local::now().to_rfc3339();

    let _lock = CaseLock::acquire(&case_dir)?;

    let yaml_path = case_dir.join("case.yaml");
    let mut manifest: CaseManifest = if yaml_path.exists() {
        let content = fs::read_to_string(&yaml_path)?;
        serde_yaml::from_str(&content).unwrap_or_else(|_| CaseManifest::new(case_name, &timestamp))
    } else {
        CaseManifest::new(case_name, &timestamp)
    };

    if manifest.files.iter().any(|f| f.path == rel_path) {
        return Ok(()); // already registered (idempotent)
    }

    manifest.files.push(CaseFileEntry {
        filename,
        path: rel_path,
        target: target.to_string(),
        timestamp: timestamp.clone(),
        tool: tool.to_string(),
    });
    manifest.modified = timestamp;

    let yaml_str = serde_yaml::to_string(&manifest)?;
    let tmp_path = case_dir.join("case.yaml.tmp");
    fs::write(&tmp_path, yaml_str)?;
    fs::rename(&tmp_path, &yaml_path)?;

    Ok(())
}