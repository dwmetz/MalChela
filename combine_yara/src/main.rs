use std::fs::{self, File};
use std::io::{self, Write, stdin};
use walkdir::WalkDir;

fn main() -> io::Result<()> {
    println!("Enter the directory path to scan for YARA rules:");
    let mut search_dir = String::new();
    stdin().read_line(&mut search_dir)?;
    let search_dir = search_dir.trim();

    let output_file = "combined_rules.yar";
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

    let mut output = File::create(output_file)?;
    output.write_all(combined_rules.as_bytes())?;

    println!("Combined YARA rules written to {}", output_file);
    Ok(())
}