use std::process::Command;
use std::path::Path;

pub fn calculate_fuzzy_hash(file_path: &str) -> Result<String, String> {
    if !Path::new(file_path).exists() {
        return Err("File not found.".to_string());
    }

    let output = Command::new("ssdeep")
        .arg(file_path)
        .output()
        .map_err(|e| {
            if let Some(2) = e.raw_os_error() {
                "ssdeep not found — please install it and ensure it's in your PATH.".to_string()
            } else {
                format!("Failed to execute ssdeep: {}", e)
            }
        })?;

    if !output.status.success() {
        return Err(format!(
            "ssdeep returned error: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();

    // Skip header
    lines.next(); // column names
    lines.next(); // separator

    // Grab actual fuzzy hash line
    if let Some(hash_line) = lines.next() {
        Ok(hash_line.to_string())
    } else {
        Err("ssdeep output was empty or malformed.".to_string())
    }
}