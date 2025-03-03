use md5::{Digest, Md5};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use yara::{Compiler, Rules};

const YARA_RULES: &str = r#"
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

/// Compiles YARA rules from a string.
fn compile_yara_rules() -> Result<Rules, Box<dyn std::error::Error>> {
    let compiler = Compiler::new()?; 
    let compiler = compiler.add_rules_str(YARA_RULES)?; 
    let rules = compiler.compile_rules()?; 
    Ok(rules)
}

/// Calculates the MD5 hash of a file.
fn calculate_md5(file_path: &Path) -> Option<String> {
    let file = File::open(file_path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();
    let mut buffer = [0; 4096];

    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

/// Recursively scans a directory for files that do not match YARA rules and calculates their MD5 hashes.
fn scan_and_hash_files(directory: &Path, rules: &Rules, output_file: &Path) -> io::Result<()> {
    let mut hash_count = 0;
    let mut output = File::create(output_file)?;

    for entry in WalkDir::new(directory)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if path.is_file() {
            match rules.scan_file(path, 5) {
                Ok(matches) => {
                    // Only process files that do not match any YARA rule
                    if matches.is_empty() {
                        if let Some(md5_hash) = calculate_md5(path) {
                            println!("Writing hash for {}", path.display());
                            writeln!(output, "{}", md5_hash)?; // Write only the hash value
                            hash_count += 1;
                        }
                    }
                }
                Err(e) => eprintln!("[WARNING] YARA error scanning {:?}: {}", path, e),
            }
        }
    }

    println!("\nScan completed.");
    println!("Total number of hashes written: {}", hash_count);
    println!("Output file location: {:?}", output_file.canonicalize()?);

    Ok(())
}

fn main() {
    // Prompt user for directory to scan
    println!("Enter directory to scan:");
    let mut directory_to_scan = String::new();
    io::stdin().read_line(&mut directory_to_scan).unwrap();
    let directory_to_scan = PathBuf::from(directory_to_scan.trim());

    if !directory_to_scan.is_dir() {
        eprintln!("[ERROR] The provided path is not a valid directory: {:?}", directory_to_scan);
        return;
    }

    // Compile YARA rules
    let yara_rules = match compile_yara_rules() {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("[ERROR] Failed to compile YARA rules: {}", e);
            return;
        }
    };

    // Output filename for unmatched files' MD5 hashes
    let output_filename = PathBuf::from("XMZMD5.txt");

    // Check if the output file already exists and prompt user for action
    if output_filename.exists() {
        println!(
            "[WARNING] The file '{:?}' already exists. Do you want to overwrite it? (yes/no):",
            output_filename
        );
        let mut response = String::new();
        io::stdin().read_line(&mut response).unwrap();
        if !matches!(response.trim().to_lowercase().as_str(), "yes" | "y") {
            println!("[INFO] Operation canceled by user.");
            return;
        }
    }

    // Scan the directory recursively and write results to the output file
    if let Err(e) = scan_and_hash_files(&directory_to_scan, &yara_rules, &output_filename) {
        eprintln!("[ERROR] Failed to scan directory or write to output file: {}", e);
    }
}
