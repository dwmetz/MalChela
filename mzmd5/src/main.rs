use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;
use md5::{Md5, Digest};
use yara::{Compiler, Rules};
use walkdir::WalkDir;

/// Compile YARA rules for detecting MZ headers.
fn compile_yara_rules() -> Result<Rules, yara::Error> {
    let rule = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}  // MZ header in hex
    condition:
        $mz at 0  // Match if MZ header is at the start of the file
}
"#;

    Compiler::new()
        .map_err(yara::Error::from)?
        .add_rules_str(rule)
        .map_err(yara::Error::from)?
        .compile_rules()
        .map_err(yara::Error::from)
}

/// Calculate the MD5 hash of a file.
fn calculate_md5(file_path: &Path) -> Option<String> {
    let mut file = File::open(file_path).ok()?;
    let mut hasher = Md5::new();
    let mut buffer = [0; 4096];

    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

/// Scan files in a directory using YARA rules and write results to an output file.
fn scan_and_hash_files(directory: &Path, rules: &Rules, output_file: &Path) -> usize {
    let mut hash_count = 0;
    let mut output = File::create(output_file).expect("Failed to create output file");

    for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        if path.is_file() {
            match rules.scan_file(path, 0) {
                Ok(matches) => {
                    if matches.iter().any(|m| m.identifier == "mz_header") {
                        if let Some(md5_hash) = calculate_md5(path) {
                            // Debug output for verification
                            println!("Writing hash to file: {}", md5_hash);

                            // Write hash to output file
                            writeln!(output, "{}", md5_hash).expect("Failed to write to output file");
                            hash_count += 1;
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    // Flush the buffer to ensure all data is written
    output.flush().expect("Failed to flush output file");

    hash_count
}

fn main() {
    println!("Enter the directory or volume you want to scan:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");

    let directory_to_scan = match fs::canonicalize(input.trim()) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Error: Failed to resolve path. Details: {}", err);
            process::exit(1);
        }
    };

    println!("Resolved path: {:?}", directory_to_scan);

    let metadata = match fs::metadata(&directory_to_scan) {
        Ok(meta) => meta,
        Err(err) => {
            eprintln!("Error: The specified path does not exist or cannot be accessed. Details: {}", err);
            process::exit(1);
        }
    };

    if !metadata.is_dir() {
        eprintln!("Error: The specified path is not a directory or volume.");
        process::exit(1);
    }

    let output_file_path = Path::new("MZMD5.txt");

    if output_file_path.exists() {
        println!(
            "The file '{}' already exists. Overwrite? (y/n):",
            output_file_path.display()
        );
        let mut overwrite_input = String::new();
        io::stdin().read_line(&mut overwrite_input).expect("Failed to read input");
        if overwrite_input.trim().to_lowercase() != "y" {
            println!("Operation canceled.");
            process::exit(0);
        }
    }

    let yara_rules = match compile_yara_rules() {
        Ok(rules) => rules,
        Err(err) => {
            eprintln!("Failed to compile YARA rules: {}", err);
            process::exit(1);
        }
    };

    let total_hashes = scan_and_hash_files(&directory_to_scan, &yara_rules, output_file_path);

    println!("\nScan completed.");
    println!("Total number of hashes written: {}", total_hashes);
    println!("Output file location: {}", output_file_path.display());
}
