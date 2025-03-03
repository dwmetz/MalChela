use std::fs;
use std::path::{Path, PathBuf};
use std::io::{self, Write};
use yara::{Compiler, Rules};
use std::time::Instant;

fn main() {
    println!("Choose an option:");
    println!("1. Run a single YARA rule file (.yar or .yara)");
    println!("2. Run all YARA rules in a folder (combined into one rule set)");
    println!("3. Run all YARA rules in a folder (individually)");
    print!("Enter your choice (1, 2, or 3): ");
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();
    let choice = choice.trim();

    match choice {
        "1" => {
            print!("Enter the path to the YARA rule file (.yar or .yara): ");
            io::stdout().flush().unwrap();
            let mut rule_path = String::new();
            io::stdin().read_line(&mut rule_path).unwrap();
            let rule_path = resolve_path(rule_path.trim(), false);

            print!("Enter the directory to scan: ");
            io::stdout().flush().unwrap();
            let mut target_dir = String::new();
            io::stdin().read_line(&mut target_dir).unwrap();
            let target_dir = resolve_path(target_dir.trim(), true);

            if let (Some(rule_path), Some(target_dir)) = (rule_path, target_dir) {
                run_single_rule(&rule_path, &target_dir);
            } else {
                eprintln!("Invalid file or directory path.");
            }
        }
        "2" => {
            print!("Enter the folder containing YARA rule files: ");
            io::stdout().flush().unwrap();
            let mut rules_folder = String::new();
            io::stdin().read_line(&mut rules_folder).unwrap();
            let rules_folder = resolve_path(rules_folder.trim(), true);

            print!("Enter the directory to scan: ");
            io::stdout().flush().unwrap();
            let mut target_dir = String::new();
            io::stdin().read_line(&mut target_dir).unwrap();
            let target_dir = resolve_path(target_dir.trim(), true);

            if let (Some(rules_folder), Some(target_dir)) = (rules_folder, target_dir) {
                run_combined_rules(&rules_folder, &target_dir);
            } else {
                eprintln!("Invalid folder or directory path.");
            }
        }
        "3" => {
            print!("Enter the folder containing YARA rule files: ");
            io::stdout().flush().unwrap();
            let mut rules_folder = String::new();
            io::stdin().read_line(&mut rules_folder).unwrap();
            let rules_folder = resolve_path(rules_folder.trim(), true);

            print!("Enter the directory to scan: ");
            io::stdout().flush().unwrap();
            let mut target_dir = String::new();
            io::stdin().read_line(&mut target_dir).unwrap();
            let target_dir = resolve_path(target_dir.trim(), true);

            if let (Some(rules_folder), Some(target_dir)) = (rules_folder, target_dir) {
                run_individual_rules(&rules_folder, &target_dir);
            } else {
                eprintln!("Invalid folder or directory path.");
            }
        }
        _ => eprintln!("Invalid choice. Please enter 1, 2, or 3."),
    }
}

fn run_single_rule(rule_path: &Path, target_dir: &Path) {
    let start_time = Instant::now();

    match Compiler::new()
        .expect("Failed to create compiler")
        .add_rules_file(rule_path)
    {
        Ok(compiler) => match compiler.compile_rules() {
            Ok(rules) => {
                let total_matches = scan_directory(&rules, target_dir);
                println!("Total matches found: {}", total_matches);
            }
            Err(err) => eprintln!("Error compiling YARA rules: {}", err),
        },
        Err(err) => eprintln!("Error adding YARA rule file {}: {}", rule_path.display(), err),
    }

    let duration = start_time.elapsed();
    println!("Execution time: {:.2?}", duration);
}

fn run_combined_rules(rules_folder: &Path, target_dir: &Path) {
    let start_time = Instant::now();

    // Collect all valid rule paths
    let rule_paths: Vec<PathBuf> = fs::read_dir(rules_folder)
        .expect("Failed to read folder")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension() == Some(std::ffi::OsStr::new("yar")))
        .map(|entry| entry.path())
        .collect();

    // Compile all valid rules together
    match rule_paths.iter().try_fold(
        Compiler::new().expect("Failed to create compiler"),
        |compiler, path| compiler.add_rules_file(path),
    ) {
        Ok(compiler) => match compiler.compile_rules() {
            Ok(rules) => {
                let total_matches = scan_directory(&rules, target_dir);
                println!("Total matches found: {}", total_matches);
            }
            Err(err) => eprintln!("Error compiling YARA rules: {}", err),
        },
        Err(err) => eprintln!("Error adding YARA rules: {}", err),
    }

    let duration = start_time.elapsed();
    println!("Execution time: {:.2?}", duration);
}

fn run_individual_rules(rules_folder: &Path, target_dir: &Path) {
    let start_time = Instant::now();

    // Collect all valid rule paths
    let rule_paths: Vec<PathBuf> = fs::read_dir(rules_folder)
        .expect("Failed to read folder")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension() == Some(std::ffi::OsStr::new("yar")))
        .map(|entry| entry.path())
        .collect();

    // Compile and run each rule individually
    for path in &rule_paths {
        match Compiler::new()
            .expect("Failed to create compiler")
            .add_rules_file(path)
        {
            Ok(compiler) => match compiler.compile_rules() {
                Ok(rules) => {
                    println!(
                        "Scanning with rule file: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    );
                    scan_directory(&rules, target_dir);
                    println!(); // Add spacing between results for readability
                }
                Err(err) => eprintln!(
                    "Error compiling YARA rule file {}: {}",
                    path.display(),
                    err
                ),
            },
            Err(err) => eprintln!(
                "Error adding YARA rule file {}: {}",
                path.display(),
                err
            ),
        }
    }

    let duration = start_time.elapsed();
    println!("Execution time: {:.2?}", duration);
}

fn scan_directory(rules: &Rules, dir: &Path) -> usize {
    let mut total_matches = 0;

    for entry in fs::read_dir(dir).expect("Failed to read directory") {
        if let Ok(entry) = entry {
            if entry.path().is_file() {
                match rules.scan_file(entry.path(), 10) { // Added timeout argument
                    Ok(matches) => {
                        for m in matches.iter() {
                            println!(
                                "Match found in file {}: {}",
                                entry.path().display(),
                                m.identifier
                            );
                        }
                        total_matches += matches.len(); // Count matches
                    }
                    Err(e) => eprintln!(
                        "Error scanning file {}: {}",
                        entry.path().display(),
                        e
                    ),
                }
            }
        }
    }

    total_matches
}

/// Resolves a path conditionally using canonicalization.
///
/// If `trusted` is true, it assumes the parent path is canonical and only resolves symlinks.
/// Otherwise, it fully canonicalizes the path.
///
/// Returns `None` if the path is invalid.
fn resolve_path<P: AsRef<Path>>(path: P, trusted: bool) -> Option<PathBuf> {
    let path = PathBuf::from(path.as_ref());

    if trusted && path.exists() {
        fs::canonicalize(&path).ok()
    } else if !trusted {
        Some(path)
    } else {
        None
    }
}
