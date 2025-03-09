use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use yara::{Compiler, Rules};
use clearscreen;
use colored::*;

#[derive(Debug)]
struct Counts {
    total_files: usize,
    mz_header: usize,
    pdf_header: usize,
    zip_header: usize,
    neither_header: usize,
}

fn compile_yara_rules() -> Result<Rules, io::Error> {
    let rules = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}  // MZ header in hex
    condition:
        $mz at 0  // Match if MZ header is at the start of the file
}

rule pdf_header {
    meta:
        description = "Matches files with PDF header"
    strings:
        $pdf = {25 50 44 46}  // PDF header in hex (%PDF)
    condition:
        $pdf at 0  // Match if PDF header is at the start of the file
}

rule zip_header {
    meta:
        description = "Matches files with ZIP header"
    strings:
        $zip = {50 4B 03 04}  // ZIP header in hex
    condition:
        $zip at 0  // Match if ZIP header is at the start of the file
}
"#;

    Compiler::new()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .add_rules_str(rules)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .compile_rules()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

fn display_table(counts: &Counts) {
    println!("\n+----------------------+---------+");

    println!(
        "{}",
        format!("| Total Files         | {:>7} |", counts.total_files)
            .cyan()
    );
    println!(
        "{}",
        format!("| MZ Header Files     | {:>7} |", counts.mz_header).red()
    );
    println!(
        "{}",
        format!("| PDF Header Files    | {:>7} |", counts.pdf_header).green()
    );
    println!(
        "{}",
        format!("| ZIP Header Files    | {:>7} |", counts.zip_header).yellow()
    );
    println!(
        "{}",
        format!("| Neither Header Files| {:>7} |", counts.neither_header).purple()
    );
    println!("+----------------------+---------+");
}

fn scan_and_count_files(
    directory: &PathBuf,
    rules: &Rules,
    use_table_display: bool,
    counts: &mut Counts,
) {
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let file_path = entry.path();

            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    counts.total_files += 1;
                    match scan_file(&file_path, rules) {
                        Ok(matches) => {
                            if matches.contains(&"mz_header".to_string()) {
                                counts.mz_header += 1;
                            }
                            if matches.contains(&"pdf_header".to_string()) {
                                counts.pdf_header += 1;
                            }
                            if matches.contains(&"zip_header".to_string()) {
                                counts.zip_header += 1;
                            }
                            if matches.is_empty() {
                                counts.neither_header += 1;
                            }
                        }
                        Err(e) => eprintln!("Error scanning {:?}: {}", file_path, e),
                    }

                    if use_table_display {
                        clearscreen::clear().expect("Failed to clear screen");
                        display_table(counts);
                    } else {
                        println!("Scanned: {:?}", file_path.to_string_lossy().blue());
                        println!("Current Counts: {:?}", counts);
                    }

                    sleep(Duration::from_millis(100));
                } else if file_type.is_dir() {
                    scan_and_count_files(&file_path, rules, use_table_display, counts);
                } else {
                    eprintln!("Skipping special file: {:?}", file_path);
                }
            } else {
                eprintln!("Skipping unreadable path: {:?}", file_path);
            }
        }
    } else {
        eprintln!("Error reading directory: {:?}", directory);
    }
}

fn scan_file(file_path: &Path, rules: &Rules) -> Result<Vec<String>, io::Error> {
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let matches = rules.scan_mem(&data, 5).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(matches.iter().map(|m| m.identifier.to_string()).collect())
}

fn main() {
    println!("Enter directory to scan:");

    let mut directory_to_scan = String::new();
    std::io::stdin().read_line(&mut directory_to_scan).unwrap();

    let directory_to_scan = directory_to_scan.trim();

    let directory_path = match fs::canonicalize(directory_to_scan) {
        Ok(path) => path,
        Err(_) => {
            eprintln!(
                "Error: The directory '{}' does not exist or cannot be accessed.",
                directory_to_scan
            );
            return;
        }
    };

    println!("Choose output format - (1) Detailed, (2) Table Display:");

    let mut display_choice = String::new();
    std::io::stdin().read_line(&mut display_choice).unwrap();

    let use_table_display = display_choice.trim() == "2";

    match compile_yara_rules() {
        Ok(rules) => {
            if use_table_display {
                clearscreen::clear().expect("Failed to clear screen");
            }

            let mut counts = Counts {
                total_files: 0,
                mz_header: 0,
                pdf_header: 0,
                zip_header: 0,
                neither_header: 0,
            };

            scan_and_count_files(&directory_path, &rules, use_table_display, &mut counts);

            if use_table_display {
                clearscreen::clear().expect("Failed to clear screen");
            }

            println!("\nFinal Results:");
            display_table(&counts);

            if counts.total_files == 0 {
                println!("No files were scanned. Please check your directory.");
            }
        }
        Err(e) => eprintln!("Error compiling YARA rules: {}", e),
    }
}