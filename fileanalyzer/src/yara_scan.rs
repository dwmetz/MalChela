use yara::{Compiler, Rules};
use std::fs;
use walkdir::WalkDir;
use std::path::PathBuf;
use std::env;
use std::io;

pub fn scan_file_with_yara_rules(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let workspace_root = find_workspace_root()?;
    let rules_dir = workspace_root.join("yara_rules");

    let mut compiler = Compiler::new()?;

    for entry in WalkDir::new(rules_dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "yar") {
            let rule_content = fs::read_to_string(path)?;
            compiler = compiler.add_rules_str(&rule_content)?;
        }
    }

    let rules: Rules = compiler.compile_rules()?;

    let results = rules.scan_file(file_path, 5)?;
    let matches = results.iter().map(|m| m.identifier.to_string()).collect();

    Ok(matches)
}

fn find_workspace_root() -> io::Result<PathBuf> {
    let mut current_dir = env::current_dir()?;

    loop {
        let cargo_toml_path = current_dir.join("Cargo.toml");
        if cargo_toml_path.exists() {
            return Ok(current_dir);
        }

        match current_dir.parent() {
            Some(parent) => current_dir = parent.to_path_buf(),
            None => {
                eprintln!("Error: Workspace root not found.");
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Workspace root not found",
                ));
            }
        }
    }
}