use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::error::Error;
use std::env;

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