mod hashing;
mod yara_scan;
mod entropy;
mod pe_parser;
mod strings;
mod metadata;
mod packed;
mod vt_scan;

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tokio;

#[tokio::main]
async fn main() {
    println!("Enter file path: ");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    let file_path = input.trim();

    if !Path::new(file_path).exists() {
        println!("File not found!");
        return;
    }

    let file_content = fs::read(file_path).expect("Failed to read file");
    let hash = hashing::calculate_sha256(&file_content);

    println!("🔹 SHA-256 Hash: {:?}", hash);

    let entropy_value = entropy::calculate_entropy(&file_content);

    if entropy_value > 7.5 {
        println!("⚠️  Entropy: {:.4} (High)", entropy_value);
    } else {
        println!("🔹 Entropy: {:.4} (Normal)", entropy_value);
    }
    match packed::detect_packing(file_path) {
        Ok(true) => println!("⚠️  File may be packed"),
        Ok(false) => println!("🔹 File is not packed"),
        Err(e) => println!("Error during UPX detection: {}", e),
    }

    match pe_parser::parse_pe_header(&file_content) {
        Ok(pe_info) => println!("🔹 PE Header: {}", pe_info),
        Err(e) => println!("🔹 PE Header: Error parsing PE header: {}", e),
    }

    match metadata::get_metadata(file_path) {
        Ok(metadata) => println!("🔹 Metadata: {:?}", metadata),
        Err(e) => println!("⚠️ Error fetching metadata: {}", e),
    }

    match yara_scan::scan_file_with_yara_rules(file_path) {
        Ok(matches) => {
            if matches.is_empty() {
                println!("🔹 No YARA matches found.");
            } else {
                println!("⚠️  YARA Matches: {:?}", matches);
            }
        }
        Err(e) => println!("⚠️ Error scanning file with YARA: {}", e),
    }

    match vt_scan::check_virustotal(&hash).await {
        Ok(true) => println!("⚠️  VirusTotal (Hash): Malicious file detected!"),
        Ok(false) => println!("🔹  VirusTotal (Hash): No malicious detections."),
        Err(e) => println!("⚠️ VirusTotal (Hash) Error: {}", e),
    }

    print!("Run strings module? (y/n): ");
    io::stdout().flush().unwrap();
    let mut run_strings = String::new();
    io::stdin().read_line(&mut run_strings).expect("Failed to read input");
    let run_strings = run_strings.trim().to_lowercase();

    if run_strings == "y" {
        let extracted_strings: Vec<String> = strings::extract_strings(&file_content)
            .into_iter()
            .filter(|s| s.len() >= 8)
            .collect();
        println!("🔹 Extracted Strings:");
        for string in extracted_strings {
            println!("  {}", string);
        }
    } else {
        println!("Strings module skipped.");
    }
}