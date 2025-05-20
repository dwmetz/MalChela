use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use yara::{Compiler, Rules};
use clearscreen;


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
    println!("[TABLE_UPDATE]");
    println!("\n+----------------------+---------+");

    println!(
        "{}",
        format!("| Total Files         | {:>7} |", counts.total_files)
    );
    println!(
        "{}",
        format!("| MZ Header Files     | {:>7} |", counts.mz_header)
    );
    println!(
        "{}",
        format!("| PDF Header Files    | {:>7} |", counts.pdf_header)
    );
    println!(
        "{}",
        format!("| ZIP Header Files    | {:>7} |", counts.zip_header)
    );
    println!(
        "{}",
        format!("| Neither Header Files| {:>7} |", counts.neither_header)
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

                    if !use_table_display {
                        println!("Scanned: {:?}", file_path.to_string_lossy());
                        println!(
                            "Current Counts: Counts {{ total_files: {}, mz_header: {}, pdf_header: {}, zip_header: {}, neither_header: {} }}",
                            counts.total_files,
                            counts.mz_header,
                            counts.pdf_header,
                            counts.zip_header,
                            counts.neither_header
                        );
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
    let input = std::env::var("MALCHELA_INPUT").unwrap_or_else(|_| {
        println!("Enter directory to scan:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read input");
        input
    });

    let directory_path = match fs::canonicalize(input.trim()) {
        Ok(path) => path,
        Err(_) => {
            eprintln!(
                "Error: The directory '{}' does not exist or cannot be accessed.",
                input
            );
            return;
        }
    };

    let use_table_display = std::env::var("MZCOUNT_TABLE_DISPLAY")
        .map(|val| val == "1")
        .unwrap_or(false);

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

            // DEBUG line removed as requested.
            scan_and_count_files(&directory_path, &rules, use_table_display, &mut counts);

            if use_table_display {
                clearscreen::clear().expect("Failed to clear screen");
                display_table(&counts);
            } else {
                println!("\nFinal Results:");
                display_table(&counts);
            }

            if counts.total_files == 0 {
                println!("No files were scanned. Please check your directory.");
            }
        }
        Err(e) => eprintln!("Error compiling YARA rules: {}", e),
    }
}