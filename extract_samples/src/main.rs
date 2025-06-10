use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, exit};
use walkdir::WalkDir;
use std::env;

fn main() {
    // Check if 7z or 7zz exists in PATH
    let seven_zip = find_7zip();
    if seven_zip.is_none() {
        eprintln!("Error: 7zip not found in PATH.");
        exit(1);
    }
    let seven_zip = seven_zip.unwrap();

    // Accept input directory and password via args or prompt
    let args: Vec<String> = env::args().collect();

    let mut case_name: Option<String> = None;

    let (dir, password) = if args.len() >= 3 {
        let mut input_dir = String::new();
        let mut pwd = String::new();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--case" if i + 1 < args.len() => {
                    case_name = Some(args[i + 1].clone());
                    i += 1;
                }
                _ if input_dir.is_empty() => input_dir = args[i].clone(),
                _ if pwd.is_empty() => pwd = args[i].clone(),
                _ => {}
            }
            i += 1;
        }

        (input_dir.trim().trim_matches('"').to_string(), pwd.trim().to_string())
    } else {
        let dir = prompt_for_directory();
        let password = prompt_for_password();
        (dir, password)
    };

    if !Path::new(&dir).is_dir() {
        eprintln!("Error: Provided path is not a directory.");
        exit(1);
    }
    println!("Using directory: {:?}", dir);

    // Determine base output path
    let case_output_dir = if let Some(ref name) = case_name {
        let path = format!("saved_output/cases/{}", name);
        std::fs::create_dir_all(&path).expect("Failed to create case output directory");
        Some(path)
    } else {
        None
    };

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

        // Skip non-zip files explicitly
        if zip_file.extension().and_then(|ext| ext.to_str()) != Some("zip") {
            continue;
        }

        // Check if the file has a .zip extension
        if zip_file.extension().and_then(|ext| ext.to_str()) == Some("zip") {
            println!("Extracting: {:?}", zip_file);

            let output = Command::new(&seven_zip)
                .arg("x")
                .arg(zip_file)
                .arg(format!("-p{}", password)) // Password
                .arg(format!(
                    "-o{}",
                    case_output_dir
                        .as_deref()
                        .unwrap_or(&zip_file.parent().unwrap().to_string_lossy())
                )) // Output directory
                .output();

            match output {
                Ok(output) => {
                    let stdout_str = String::from_utf8_lossy(&output.stdout);
                    let stderr_str = String::from_utf8_lossy(&output.stderr);

                    let everything_ok = stdout_str.contains("Everything is Ok");
                    let subitem_warning = stderr_str.contains("Wrong password");

                    if everything_ok || (stdout_str.contains("Extracting archive") && subitem_warning) {
                        println!("Successfully extracted {:?}", zip_file);
                    } else {
                        eprintln!(
                            "Error extracting {:?}:\nSTDOUT: {}\nSTDERR: {}",
                            zip_file, stdout_str.trim(), stderr_str.trim()
                        );
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

    input.trim().trim_matches('"').to_string()
}

/// Prompts the user to enter a password.
fn prompt_for_password() -> String {
    print!("Enter the password for zip files: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    input.trim().to_string()
}
