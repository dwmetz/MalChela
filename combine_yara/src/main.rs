use std::fs::{self, File};
use std::io::{self, Write, stdin};
use std::path::Path;
use walkdir::WalkDir;
use colored::*;

fn main() -> io::Result<()> {
    println!("{}", "Enter the directory path to scan for YARA rules:".blue());
    let mut search_dir = String::new();
    stdin().read_line(&mut search_dir)?;
    let search_dir = search_dir.trim();

    let output_dir = Path::new("Saved_Results");
    if !output_dir.exists() {
        fs::create_dir(output_dir)?;
    }

    let output_file_path = output_dir.join("combined_rules.yar");
    let mut combined_rules = String::new();

    for entry in WalkDir::new(search_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "yar" || extension == "yara" {
                    let content = fs::read_to_string(path)?;
                    combined_rules.push_str(&content);
                    combined_rules.push_str("\n\n");
                }
            }
        }
    }

    let mut output = File::create(output_file_path.clone())?; // Clone here!
    output.write_all(combined_rules.as_bytes())?;

    println!(
        "{} {}",
        "Combined YARA rules written to".green(),
        output_file_path.display().to_string().green()
    );
    Ok(())
}