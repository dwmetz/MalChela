extern crate serde;
#[macro_use]
extern crate serde_derive;

use std::fs::File;
use std::io::Write;

use clap::Parser;
use common_config::get_output_dir;
use common_ui::styled_line;

#[derive(Parser)]
#[command(name = "fileanalyzer", about = "Analyzes binary files for static indicators.")]
struct Args {
    #[arg(help = "Path to file to analyze")]
    input: Option<String>,

    #[arg(short, long, help = "Save output to file")]
    output: bool,
}

#[derive(Serialize)]
struct FileAnalysisReport {
    file_type: String,
    sha256: String,
    entropy: f64,
    packed: String,
    compile_time: Option<String>,
    signed: bool,
    vt_result: String,
    yara_matches: Vec<String>,
    metadata: Option<String>,
    uncommon_sections: Vec<String>,
    suspicious_imports: Vec<String>,
    suspicious_compile_time: bool,
}
#[allow(dead_code)]

mod hashing;
mod yara_scan;
mod entropy;
mod pe_parser;
mod metadata;
mod packed;
mod vt_scan;
mod filetype;
mod signing;

use std::fs;
use std::path::Path;

use chrono::{Utc, Datelike};



#[tokio::main]
async fn main() {
    let args = Args::parse();
    let file_path = match args.input {
        Some(path) => path,
        None => {
            let line = styled_line("yellow", "Enter the path to the file you want to analyze:");
            println!("{}", line);
            let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
            let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");
            writeln!(temp_file, "{}", line).ok();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).expect("Failed to read input");
            input.trim_end_matches(&['\n', '\r'][..]).to_string()
        }
    };

    if !Path::new(&file_path).exists() {
        let line = styled_line("yellow", "File not found!");
        println!("{}", line);
        let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
        let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");
        writeln!(temp_file, "{}", line).ok();
        return;
    }

    let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
    let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");
    writeln!(temp_file).ok();

    let file_content = fs::read(file_path.clone()).expect("Failed to read file");
    let save_output = args.output;
    let mut compile_time_str = String::new();
    let mut suspicious_compile_time = false;
    let file_type = filetype::detect_file_type(&file_content);
    let line = styled_line("stone", &format!("File Type: {}", file_type));
    println!("{}", line);
    writeln!(temp_file, "{}", line).ok();
    let hash = hashing::calculate_sha256(&file_content);
    let line = styled_line("stone", &format!("SHA-256 Hash: {:?}", hash));
    println!("{}", line);
    writeln!(temp_file, "{}", line).ok();

    let vt_result = match vt_scan::check_virustotal(&hash).await {
        Ok(true) => {
            let line = styled_line("red", &format!("VirusTotal: Malicious"));
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
            Some(true)
        }
        Ok(false) => {
            let line = styled_line("yellow", "VirusTotal: Clean or Unknown");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
            Some(false)
        }
        Err(e) => {
            let line = styled_line("yellow", &format!("VirusTotal: Error - {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
            None
        }
    };


    let entropy_value = entropy::calculate_entropy(&file_content);
    if entropy_value > 7.5 {
        let line = styled_line("yellow", &format!("Entropy: {:.4} (High)", entropy_value));
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    } else {
        let line = styled_line("yellow", &format!("Entropy: {:.4} (Normal)", entropy_value));
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    }

    match packed::detect_packing(&file_path) {
        Ok(true) => {
            let line = styled_line("yellow", "File may be packed");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
        Ok(false) => {
            let line = styled_line("yellow", "File is not packed");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
        Err(e) => {
            let line = styled_line("yellow", &format!("Error during UPX detection: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
    }

    match pe_parser::parse_pe_header(&file_content) {
        Ok(pe_info) => {
            let mut pe_output = String::new();
            writeln!(temp_file).ok();
            println!();
            let heading = styled_line("NOTE", "--- PE Header Details ---");
            println!("{}", heading);
            writeln!(temp_file, "{}", heading).ok();
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  PE Header parsed: {} sections, {} imports, {} exports", pe_info.sections.len(), pe_info.imports.len(), pe_info.exports.len()))));
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Summary: {}", pe_info.summary))));

            compile_time_str = pe_info.compile_time.clone();
            if let Ok(dt) = chrono::DateTime::parse_from_str(&pe_info.compile_time, "%Y-%m-%d %H:%M:%S UTC") {
                let compile_time_utc = dt.with_timezone(&Utc);
                let current_time = Utc::now();
                if compile_time_utc.year() < 2000 || compile_time_utc > current_time {
                    suspicious_compile_time = true;
                    compile_time_str.push_str(" [SUSPICIOUS]");
                }
            }
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Compile Time: {}", compile_time_str))));

            if !pe_info.sections.is_empty() {
                pe_output.push_str(&format!("{}\n", styled_line("stone", "  Sections:")));
                for section in pe_info.sections {
                    pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("    - {}", section))));
                }
            }

            if !pe_info.imports.is_empty() {
                pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Imports ({}):", pe_info.imports.len()))));
                for imp in pe_info.imports.iter().take(10) {
                    pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("    - {}", imp))));
                }
                if pe_info.imports.len() > 10 {
                    pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("    ... and {} more", pe_info.imports.len() - 10))));
                }
            }

            if !pe_info.exports.is_empty() {
                pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Exports ({}):", pe_info.exports.len()))));
                for exp in &pe_info.exports {
                    pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("    - {}", exp))));
                }
            }

            let is_signed = signing::check_digital_signature(&file_content);
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Signed: {}", if is_signed { "Yes" } else { "No" }))));

            use std::io::{self, Write};
            print!("{}", pe_output);
            io::stdout().flush().unwrap();
            write!(temp_file, "{}", pe_output).ok();
        }
        Err(e) => {
            let line = styled_line("highlight", &format!("PE parse error: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
    }

    let mut bad_sections = vec![];
    let mut suspicious_imports = vec![];
    let known_sections = [".text", ".rdata", ".data", ".reloc", ".rsrc", ".idata"];

    let mut printed_warning_header = false;
    if let Ok(pe_info) = pe_parser::parse_pe_header(&file_content) {
        // Uncommon section names
        for s in &pe_info.sections {
            let name = s.split_whitespace().next().unwrap_or("");
            if !known_sections.contains(&name) {
                bad_sections.push(name.to_string());
            }
        }

        // Suspicious imports
        let suspect_terms = [
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
            "InternetOpen", "InternetConnect", "URLDownloadToFile", "HttpSendRequest",
            "WinHttpSendRequest", "LoadLibrary", "GetProcAddress", "ShellExecute", "WinExec"
        ];
        for imp in &pe_info.imports {
            if suspect_terms.iter().any(|s| imp.contains(s)) {
                suspicious_imports.push(imp.clone());
            }
        }

        if !bad_sections.is_empty() {
            let line = styled_line("NOTE", "--- Heuristic Warnings ---");
            println!("\n{}", line);
            writeln!(temp_file, "\n{}", line).ok();
            printed_warning_header = true;
            let line = styled_line("stone", "- Uncommon Section Names:");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
            for name in &bad_sections {
                let line = styled_line("stone", &format!("  - {}", name.clone()));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            }
        }

        if !suspicious_imports.is_empty() {
            if !printed_warning_header {
                let line = styled_line("NOTE", "--- Heuristic Warnings ---");
                println!("\n{}", line);
                writeln!(temp_file, "\n{}", line).ok();
                printed_warning_header = true;
            }
            let line = styled_line("stone", "- Suspicious Imports:");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
            for imp in &suspicious_imports {
                let line = styled_line("stone", &format!("  - {}", imp));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            }
        }
        // Add suspicious compile time warning if needed
        if suspicious_compile_time {
            if !printed_warning_header {
                let line = styled_line("NOTE", "--- Heuristic Warnings ---");
                println!("\n{}", line);
                writeln!(temp_file, "\n{}", line).ok();
            }
            let line = styled_line("stone", "- Suspicious Compile Timestamp");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
    } else if suspicious_compile_time {
        // If parse_pe_header failed above, but suspicious_compile_time is set, print warning header
        let line = styled_line("NOTE", "--- Heuristic Warnings ---");
        println!("\n{}", line);
        writeln!(temp_file, "\n{}", line).ok();
        let line = styled_line("stone", "- Suspicious Compile Timestamp");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    }

    match metadata::get_metadata(&file_path) {
        Ok(metadata) => {
            if let Some((size, modified)) = metadata.split_once(", Last Modified: ") {
                let line = styled_line("highlight", &format!("- File Size: {}", size.trim().strip_prefix("Size: ").unwrap_or(size.trim())));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
                let line = styled_line("highlight", &format!("- Last Modified: {}", modified.trim()));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            } else {
                let line = styled_line("highlight", &format!("Metadata: {}", metadata));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            }
        },
        Err(e) => {
            let line = styled_line("highlight", &format!("Error fetching metadata: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        },
    }

    match yara_scan::scan_file_with_yara_rules(&file_path) {
        Ok(matches) => {
            if matches.is_empty() {
                let line = styled_line("stone", "No YARA matches found.");
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            } else {
                let line = styled_line("yellow", &format!("- YARA Matches: {:?}", matches));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            }
        }
        Err(e) => {
            let line = styled_line("yellow", &format!("Error scanning file with YARA: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        },
    }

    let line = styled_line("NOTE", "--- Heuristic Indicators ---");
    println!("\n{}", line);
    writeln!(temp_file, "\n{}", line).ok();
    match vt_result {
        Some(true) => {
            let line = styled_line("red", "- VirusTotal: Malicious");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
        Some(false) => {
            let line = styled_line("stone", "- VirusTotal: Clean or Unknown");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
        None => {
            let line = styled_line("stone", "- VirusTotal: Error");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
    }
    if entropy_value > 7.5 {
        let line = styled_line("yellow", "- Entropy: High");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    } else {
        let line = styled_line("stone", "- Entropy: Normal");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    }

    match packed::detect_packing(&file_path) {
        Ok(true) => {
            let line = styled_line("yellow", "- Packed: Possibly");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
        Ok(false) => {
            let line = styled_line("stone", "- Packed: Unlikely");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
        Err(_) => {
            let line = styled_line("stone", "- Packed: Unknown");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        }
    }

    if signing::check_digital_signature(&file_content) {
        let line = styled_line("stone", "- Signature: Present");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    } else {
        let line = styled_line("stone", "- Signature: Absent");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
    }

    match yara_scan::scan_file_with_yara_rules(&file_path) {
        Ok(matches) => {
            if matches.is_empty() {
                let line = styled_line("stone", "- YARA: No matches");
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            } else {
                let line = styled_line("yellow", &format!("- YARA: {} match(es)", matches.len()));
                println!("{}", line);
                writeln!(temp_file, "{}", line).ok();
            }
        }
        Err(_) => {
            let line = styled_line("stone", "- YARA: Error scanning");
            println!("{}", line);
            writeln!(temp_file, "{}", line).ok();
        },
    }
    if save_output {
        let output_dir = get_output_dir("fileanalyzer");

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let report_path = output_dir.join(format!("report_{}.json", timestamp));

        let report = FileAnalysisReport {
            file_type,
            sha256: hash.clone(),
            entropy: entropy_value,
            packed: match packed::detect_packing(&file_path) {
                Ok(true) => "Possibly".to_string(),
                Ok(false) => "Unlikely".to_string(),
                Err(_) => "Unknown".to_string(),
            },
            compile_time: Some(compile_time_str),
            signed: signing::check_digital_signature(&file_content),
            vt_result: match vt_result {
                Some(true) => "Malicious".to_string(),
                Some(false) => "Clean or Unknown".to_string(),
                None => "Error".to_string(),
            },
            yara_matches: match yara_scan::scan_file_with_yara_rules(&file_path) {
                Ok(m) => m,
                Err(_) => vec!["Error scanning".to_string()],
            },
            metadata: metadata::get_metadata(&file_path).ok(),
            uncommon_sections: bad_sections.clone(),
            suspicious_imports: suspicious_imports.clone(),
            suspicious_compile_time,
        };

        let mut file = File::create(&report_path).expect("Failed to create report file");
        let json = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
        file.write_all(json.as_bytes()).expect("Failed to write report");

        let text_path = output_dir.join(format!("report_{}.txt", timestamp));
        fs::copy(&temp_path, &text_path).expect("Failed to save text report");

        println!();
        writeln!(temp_file).ok();
        let line = styled_line("green", "Output successfully saved.");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
        writeln!(temp_file).ok();
        println!();
    } else {
        println!();
        writeln!(temp_file).ok();
        let line = styled_line("stone", "Output was not saved.");
        println!("{}", line);
        writeln!(temp_file, "{}", line).ok();
        writeln!(temp_file).ok();
        println!();
    }
}
