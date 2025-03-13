use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, exit};
use walkdir::WalkDir;

fn main() {
    // Check if 7z or 7zz exists in PATH
    let seven_zip = find_7zip();
    if seven_zip.is_none() {
        eprintln!("Error: 7zip not found in PATH.");
        exit(1);
    }
    let seven_zip = seven_zip.unwrap();

    // Prompt the user for a directory to scan
    let dir = prompt_for_directory();
    if !Path::new(&dir).is_dir() {
        eprintln!("Error: Provided path is not a directory.");
        exit(1);
    }

    // Recursively search for .zip files and extract them
    for entry in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
        let zip_file = entry.path();

        // Skip "dot underscore" files
        if let Some(file_name) = zip_file.file_name().and_then(|name| name.to_str()) {
            if file_name.starts_with("._") {
                println!("Skipping metadata file: {:?}", zip_file);
                continue;
            }
        }

        // Check if the file has a .zip extension
        if zip_file.extension().and_then(|ext| ext.to_str()) == Some("zip") {
            println!("Extracting: {:?}", zip_file);

            let output = Command::new(&seven_zip)
                .arg("x")
                .arg(zip_file)
                .arg(format!("-p{}", "infected")) // Password
                .arg(format!("-o{}", zip_file.parent().unwrap().display())) // Output directory
                .output();

            match output {
                Ok(output) => {
                    if !output.status.success() {
                        eprintln!(
                            "Failed to extract {:?}: {}",
                            zip_file,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    } else {
                        println!("Successfully extracted {:?}", zip_file);
                    }
                }
                Err(e) => eprintln!("Error running 7zip: {}", e),
            }
        }
    }
}

/// Finds the path to `7z` or `7zz` in the system's PATH.
fn find_7zip() -> Option<String> {
    if which::which("7z").is_ok() {
        Some("7z".to_string())
    } else if which::which("7zz").is_ok() {
        Some("7zz".to_string())
    } else {
        None
    }
}

/// Prompts the user to enter a directory path.
fn prompt_for_directory() -> String {
    print!("Enter the directory to scan: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    input.trim().to_string()
}
