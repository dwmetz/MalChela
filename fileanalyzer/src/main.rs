fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok() && std::env::var("MALCHELA_WORKSPACE_MODE").is_err()
}

use std::fs::File;
use std::io::Write;

use clap::Parser;
use common_config::get_output_dir;
use common_ui::styled_line;
use serde::Serialize;

fn plain_text(s: &str) -> String {
    strip_ansi_escapes::strip_str(s)
}

#[derive(Parser)]
#[command(name = "fileanalyzer", about = "Analyzes binary files for static indicators.")]
struct Args {
    #[arg(help = "Path to file to analyze")]
    input: Option<String>,

    #[arg(short, long, help = "Save output to file")]
    output: bool,

    #[arg(short = 't', long, help = "Save as TXT format")]
    text: bool,

    #[arg(short = 'j', long, help = "Save as JSON format")]
    json: bool,

    #[arg(short = 'm', long, help = "Save as Markdown format")]
    markdown: bool,

    #[arg(long, help = "Optional case name for routing output")]
    case: Option<String>,

    #[arg(long, help = "Specify output file name")]
    output_file: Option<String>,
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
    imphash: Option<String>,
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
mod imphash;

use std::fs;
use std::path::Path;
use pelite::pe64::Pe;
use chrono::{Utc, Datelike};



#[tokio::main]
async fn main() {
    let args = Args::parse();
    let file_path = match args.input {
        Some(path) => path,
        None => {
            let line = styled_line("yellow", "\nEnter the path to the file you want to analyze:");
            println!("{}", line);
            let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
            let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");
            writeln!(temp_file, "{}", line).ok();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).expect("Failed to read input");
            input.trim_end_matches(&['\n', '\r'][..]).to_string()
        }
    };

    // Add blank line after file path is printed and before File Type section
    println!();
    let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
    let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");
    writeln!(temp_file).ok();

    if !Path::new(&file_path).exists() {
        let line = styled_line("yellow", "File not found!");
        println!("{}", line);
        let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
        let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");
        writeln!(temp_file, "{}", line).ok();
        return;
    }

    let file_content = fs::read(file_path.clone()).expect("Failed to read file");
    let save_output = args.output;
    // Removed compile_time_str declaration; will be scoped later.
    let mut suspicious_compile_time = false;
    let file_type = filetype::detect_file_type(&file_content);
    let line = styled_line("stone", &format!("File Type: {}", file_type));
    println!("{}", line);
    writeln!(temp_file, "{}", plain_text(&line)).ok();
    let hash = hashing::calculate_sha256(&file_content);
    let md5 = hashing::calculate_md5(&file_content);
    let line = styled_line("stone", &format!("SHA-256 Hash: {:?}", hash));
    println!("{}", line);
    writeln!(temp_file, "{}", plain_text(&line)).ok();

    let vt_result = match vt_scan::check_virustotal(&hash).await {
        Ok(true) => {
            let line = styled_line("red", &format!("VirusTotal: Malicious"));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            Some(true)
        }
        Ok(false) => {
            let line = styled_line("yellow", "VirusTotal: Clean or Unknown");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            Some(false)
        }
        Err(e) => {
            let line = styled_line("yellow", &format!("VirusTotal: Error - {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            None
        }
    };

    // NSRL hash lookup using precompiled nsrlquery binary for speed
    let nsrl_result = match std::process::Command::new("target/release/nsrlquery")
        .args(["--hash", &md5])
        .output()
    {
        Ok(output) if output.status.success() => {
            let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if output_str.contains("hash not found") || output_str.contains("not found in the database") {
                let line = styled_line("stone", "NSRL: Not found");
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
                Some(false)
            } else if output_str.contains("found in the database") {
                let line = styled_line("stone", "NSRL: Present in NSRL");
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
                Some(true)
            } else {
                let line = styled_line("stone", &format!("NSRL: Unknown response - {}", output_str.trim()));
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
                None
            }
        }
        Ok(_) => {
            let line = styled_line("stone", "NSRL: Not found");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            Some(false)
        }
        Err(e) => {
            let line = styled_line("stone", &format!("NSRL: Offline or Error - {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            None
        }
    };


    let entropy_value = entropy::calculate_entropy(&file_content);
    if entropy_value > 7.5 {
        let line = styled_line("yellow", &format!("Entropy: {:.4} (High)", entropy_value));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    } else {
        let line = styled_line("yellow", &format!("Entropy: {:.4} (Normal)", entropy_value));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    match packed::detect_packing(&file_path) {
        Ok(true) => {
            let line = styled_line("yellow", "File may be packed");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        Ok(false) => {
            let line = styled_line("yellow", "File is not packed");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        Err(e) => {
            let line = styled_line("yellow", &format!("Error during UPX detection: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    let mut imphash = None;
    let pe_info = match pe_parser::parse_pe_header(&file_content) {
        Ok(pe_info) => {
            let mut pe_output = String::new();
            writeln!(temp_file).ok();
            println!();
            let heading = styled_line("NOTE", "--- PE Header Details ---");
            println!("{}", heading);
            writeln!(temp_file, "{}", plain_text(&heading)).ok();
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  PE Header parsed: {} sections, {} imports, {} exports", pe_info.sections.len(), pe_info.imports.len(), pe_info.exports.len()))));
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Summary: {}", pe_info.summary))));

            let compile_time_str = {
                let mut s = pe_info.compile_time.clone();
                if let Ok(dt) = chrono::DateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S UTC") {
                    let compile_time_utc = dt.with_timezone(&Utc);
                    let current_time = Utc::now();
                    if compile_time_utc.year() < 2000 || compile_time_utc > current_time {
                        suspicious_compile_time = true;
                        s.push_str(" [SUSPICIOUS]");
                    }
                }
                s
            };
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Compile Time: {}", compile_time_str))));

            if !pe_info.sections.is_empty() {
                pe_output.push_str(&format!("{}\n", styled_line("stone", "  Sections:")));
                for section in pe_info.sections.iter() {
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
                imphash = match imphash::calculate_imphash(&pe_info.imports) {
                    Ok(hash) => {
                        let line = styled_line("stone", &format!("Import Hash (imphash): {}", hash));
                        println!("{}", line);
                        writeln!(temp_file, "{}", plain_text(&line)).ok();
                        Some(hash)
                    }
                    Err(e) => {
                        let line = styled_line("yellow", &format!("Imphash Error: {}", e));
                        println!("{}", line);
                        writeln!(temp_file, "{}", plain_text(&line)).ok();
                        None
                    }
                };
            }

            if !pe_info.exports.is_empty() {
                pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Exports ({}):", pe_info.exports.len()))));
                for exp in &pe_info.exports {
                    pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("    - {}", exp))));
                }
            }

            if let Ok(pe_file) = pelite::pe64::PeFile::from_bytes(&file_content[..]) {
                if let Ok(resources) = pe_file.resources() {
                    if let Ok(version_info) = resources.version_info() {
                        let mut version_lines = vec![];
                        let file_info = version_info.file_info();
                        let strings_map = &file_info.strings;
                        for (_lang, table) in strings_map {
                            for (key, value) in table {
                                match key.as_ref() {
                                    "ProductVersion" => version_lines.push(styled_line("stone", &format!("  Product Version: {}", value))),
                                    "FileVersion" => version_lines.push(styled_line("stone", &format!("  File Version: {}", value))),
                                    "ProductName" => version_lines.push(styled_line("stone", &format!("  Product Name: {}", value))),
                                    "CompanyName" => version_lines.push(styled_line("stone", &format!("  Company Name: {}", value))),
                                    "OriginalFilename" => version_lines.push(styled_line("stone", &format!("  Original Filename: {}", value))),
                                    _ => {}
                                }
                            }
                        }
                        for line in version_lines {
                            println!("{}", line);
                            writeln!(temp_file, "{}", line).ok();
                        }
                    }
                }
            }
            let is_signed = signing::check_digital_signature(&file_content);
            pe_output.push_str(&format!("{}\n", styled_line("stone", &format!("  Signature: {}", if is_signed { "Present" } else { "Absent" }))));

            use std::io::{self, Write};
            print!("{}", pe_output);
            io::stdout().flush().unwrap();
            write!(temp_file, "{}", plain_text(&pe_output)).ok();
            pe_info
        }
        Err(e) => {
            let line = styled_line("highlight", &format!("PE parse error: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            return;
        }
    };

    let mut bad_sections = vec![];
    let mut suspicious_imports = vec![];
    let known_sections = [".text", ".rdata", ".data", ".reloc", ".rsrc", ".idata"];

    let mut printed_warning_header = false;
    // already unwrapped above
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
        let heading = styled_line("NOTE", "--- Heuristic Warnings ---");
        println!("\n{}", heading);
        writeln!(temp_file, "{}", plain_text(&heading)).ok();
        printed_warning_header = true;
        let line = styled_line("stone", "- Uncommon Section Names:");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
        for name in &bad_sections {
            let line = styled_line("stone", &format!("  - {}", name.clone()));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    if !suspicious_imports.is_empty() {
        if !printed_warning_header {
            let heading = styled_line("NOTE", "--- Heuristic Warnings ---");
            println!("\n{}", heading);
            writeln!(temp_file, "{}", plain_text(&heading)).ok();
            printed_warning_header = true;
        }
        let line = styled_line("stone", "- Suspicious Imports:");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
        for imp in &suspicious_imports {
            let line = styled_line("stone", &format!("  - {}", imp));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
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
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    match metadata::get_metadata(&file_path) {
        Ok(metadata) => {
            if let Some((size, modified)) = metadata.split_once(", Last Modified: ") {
                let line = styled_line("highlight", &format!("- File Size: {}", size.trim().strip_prefix("Size: ").unwrap_or(size.trim())));
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
                let line = styled_line("highlight", &format!("- Last Modified: {}", modified.trim()));
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
            } else {
                let line = styled_line("highlight", &format!("Metadata: {}", metadata));
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
            }
        },
        Err(e) => {
            let line = styled_line("highlight", &format!("Error fetching metadata: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        },
    }


    let line = styled_line("NOTE", "--- Heuristic Indicators ---");
    println!("\n{}", line);
    writeln!(temp_file, "{}", plain_text(&line)).ok();
    match vt_result {
        Some(true) => {
            let line = styled_line("red", "- VirusTotal: Malicious");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        Some(false) => {
            let line = styled_line("stone", "- VirusTotal: Clean or Unknown");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        None => {
            let line = styled_line("stone", "- VirusTotal: Error");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }
    // NSRL result in heuristic indicators
    match nsrl_result {
        Some(true) => {
            let line = styled_line("stone", "- NSRL: Found");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        Some(false) => {
            let line = styled_line("stone", "- NSRL: Not Found");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        None => {
            let line = styled_line("stone", "- NSRL: Offline");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    };
    if entropy_value > 7.5 {
        let line = styled_line("yellow", "- Entropy: High");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    } else {
        let line = styled_line("stone", "- Entropy: Normal");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    match packed::detect_packing(&file_path) {
        Ok(true) => {
            let line = styled_line("yellow", "- Packed: Possibly");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        Ok(false) => {
            let line = styled_line("stone", "- Packed: Unlikely");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
        Err(_) => {
            let line = styled_line("stone", "- Packed: Unknown");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    if signing::check_digital_signature(&file_content) {
        let line = styled_line("stone", "- Signature: Present");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    } else {
        let line = styled_line("stone", "- Signature: Absent");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    if let Ok(matches) = yara_scan::scan_file_with_yara_rules(&file_path) {
        if !matches.is_empty() {
            let line = styled_line("yellow", &format!("- YARA Matches: [{}]", matches.join(", ")));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }
    if save_output {
        let output_dir = if let Some(ref case) = args.case {
            let path = format!("saved_output/cases/{}/fileanalyzer", case);
            std::fs::create_dir_all(&path).expect("Failed to create case output directory");
            std::path::PathBuf::from(path)
        } else {
            let path = get_output_dir("fileanalyzer");
            std::fs::create_dir_all(&path).expect("Failed to create default output directory");
            path
        };
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

        let format = if args.text {
            "txt"
        } else if args.json {
            "json"
        } else if args.markdown {
            "md"
        } else {
            let warn = styled_line("yellow", "Output format required. Use -t, -j, or -m with -o.");
            println!("\n{}", warn);
            writeln!(temp_file, "\n{}", warn).ok();
            return;
        };

        let report = FileAnalysisReport {
            file_type,
            sha256: hash.clone(),
            entropy: entropy_value,
            packed: match packed::detect_packing(&file_path) {
                Ok(true) => "Possibly".to_string(),
                Ok(false) => "Unlikely".to_string(),
                Err(_) => "Unknown".to_string(),
            },
            compile_time: Some(pe_info.compile_time.clone()),
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
            imphash: imphash.clone(),
        };

        // Determine output file path based on --output-file if provided
        let output_file_path = if let Some(ref file_name) = args.output_file {
            // If output_file is absolute, use as is, else join with output_dir
            let p = std::path::Path::new(file_name);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                output_dir.join(p)
            }
        } else {
            match format {
                "txt" => output_dir.join(format!("report_{}.txt", timestamp)),
                "md" => output_dir.join(format!("report_{}.md", timestamp)),
                "json" => output_dir.join(format!("report_{}.json", timestamp)),
                _ => output_dir.join(format!("report_{}.txt", timestamp)), // fallback
            }
        };

        // Ensure parent directories exist before creating the file
        if let Some(parent) = output_file_path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create output directories");
        }

        match format {
            "txt" => {
                use std::io::Write;
                temp_file.flush().expect("Failed to flush temp file before saving report");
                fs::copy(&temp_path, &output_file_path).expect("Failed to save text report");
                println!("\n{}", styled_line("green", &format!("Text report saved to: {}", output_file_path.display())));
            }
            "md" => {
                use std::io::Write;
                temp_file.flush().expect("Failed to flush temp file before saving report");
                fs::copy(&temp_path, &output_file_path).expect("Failed to save markdown report");
                println!("\n{}", styled_line("green", &format!("Markdown report saved to: {}", output_file_path.display())));
            }
            _ => {
                // Ensure parent directories exist before creating the file
                if let Some(parent) = output_file_path.parent() {
                    std::fs::create_dir_all(parent).expect("Failed to create output directories");
                }
                let mut file = File::create(&output_file_path).expect("Failed to create report file");
                let json = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
                file.write_all(json.as_bytes()).expect("Failed to write report");
                println!("\n{}", styled_line("green", &format!("JSON report saved to: {}", output_file_path.display())));
            }
        }
    } else {
        if !is_gui_mode() {
            println!();
            writeln!(temp_file).ok();
            let line = styled_line("stone", "Output was not saved. Use -o with -t, -j, or -m to export results.");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            writeln!(temp_file).ok();
            println!();
        }
    }
}
