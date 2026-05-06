// Helper to determine if we're in true GUI mode (not workspace panel)
fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok() && std::env::var("MALCHELA_WORKSPACE_MODE").is_err()
}
use std::fs::File;
use std::io::{self, BufReader, Write, Read};

use sha2::{Sha256, Digest};

use common_ui::styled_line;

use common_config::get_output_dir;

use clap::{Arg, Command};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use colored::*;
use tabled::{Table as TabledTable, Tabled};
use tabled::settings::{Style, Modify, Alignment, Width};



// Define a Rust Orange color helper for colored crate
const RUST_ORANGE: (u8, u8, u8) = (215, 100, 40); // Use this constant for color

// Function to handle printing IOCs (unified CLI/GUI logic and formatting)
fn print_iocs(title: &str, iocs: &std::collections::BTreeSet<String>) {
    if !iocs.is_empty() {
        println!("{}", title.truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));
        for ioc in iocs {
            println!("{}", ioc);
        }
    }
}

#[derive(Debug, serde::Serialize)]
enum Encoding {
    Ascii,
    Utf8,
}

#[derive(Debug, serde::Serialize)]
struct Match {
    offset: usize,
    encoding: Encoding,
    matched_str: String,
    rule_name: Option<String>,
    tactic: Option<String>,
    technique: Option<String>,
    technique_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Detection {
    title: String,
    detection: DetectionStrings,
    mitre: Vec<MitreMapping>,
}

#[derive(Debug, Deserialize)]
struct DetectionStrings {
    strings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MitreMapping {
    technique_id: String,
    technique_name: String,
    tactics: Vec<String>,
}

// Helper function to truncate strings over a given length
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

// Filter high-volume ObjC/Swift runtime noise that appears in every Mach-O binary.
// These strings are never meaningful IOCs and would swamp detection output.
fn is_objc_swift_noise(s: &str) -> bool {
    let t = s.trim();
    // ObjC runtime stubs and imported symbol stubs (appear hundreds of times per binary)
    if t.starts_with("_objc_") || t.starts_with("objc_") || t.starts_with("@_") {
        return true;
    }
    // Swift mangled symbol prefixes
    if t.starts_with("_$s") || t.starts_with("_$S") || t.starts_with("swift_") || t.starts_with("_T0") {
        return true;
    }
    // Apple system dylib paths — present in every Mac binary's import table
    if t.starts_with("/System/Library/Frameworks/")
        || t.starts_with("/System/Library/PrivateFrameworks/")
        || t.starts_with("/usr/lib/libobjc")
        || t.starts_with("/usr/lib/swift/")
        || t.starts_with("/usr/lib/libc++")
        || t.starts_with("/usr/lib/libSystem")
    {
        return true;
    }
    // ObjC type encoding strings (e.g. "v8@0:8", "@@:") — short, only ObjC type chars
    if t.len() < 16 && t.chars().all(|c| "@:^v#BiILlqQfdCSsDTtBrnoO*{}0123456789".contains(c)) {
        return true;
    }
    false
}

struct Mstrings {
    matches: Vec<Match>,
}

impl Mstrings {
    pub fn new() -> Self {
        Self { matches: Vec::new() }
    }

    pub fn process_line(&mut self, line: &str) {
        if !line.trim().is_empty() && !is_objc_swift_noise(line) {
            let encoding_type = if std::str::from_utf8(line.as_bytes()).is_ok() {
                Encoding::Utf8
            } else {
                Encoding::Ascii
            };

            self.matches.push(Match {
                offset: self.matches.len() * 16,
                encoding: encoding_type,
                matched_str: line.trim_start().to_string(),
                rule_name: None,
                tactic: None,
                technique: None,
                technique_id: None,
            });
        }
    }

    pub fn apply_yara_detections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let yaml_content = std::fs::read_to_string("detections.yaml")?;
        let raw_rules: HashMap<String, Detection> = serde_yaml::from_str(&yaml_content)?;

        let mut compiled_rules = Vec::new();
        for (_key, det) in &raw_rules {
            for pattern in &det.detection.strings {
                if let Ok(regex) = Regex::new(pattern) {
                    for mitre in &det.mitre {
                        compiled_rules.push((
                            regex.clone(),
                            det.title.clone(),
                            mitre.tactics.join(", "),
                            mitre.technique_name.clone(),
                            mitre.technique_id.clone(),
                        ));
                    }
                }
            }
        }

        for m in &mut self.matches {
            for (regex, rule_name, tactic, technique, technique_id) in &compiled_rules {
                if regex.is_match(&m.matched_str) {
                    m.rule_name = Some(rule_name.clone());
                    m.tactic = Some(tactic.clone());
                    m.technique = Some(technique.clone());
                    // Only store the T-number, not a URL
                    m.technique_id = Some(technique_id.clone());
                    break;
                }
            }
        }

        Ok(())
    }
}


#[derive(Tabled)]
struct DisplayMatch {
    #[tabled(rename = "Offset")]
    offset: String,
    #[tabled(rename = "Encoding")]
    encoding: String,
    #[tabled(rename = "Match")]
    matched_str: String,
    #[tabled(rename = "Rule")]
    rule_name: String,
    #[tabled(rename = "Tactic")]
    tactic: String,
    #[tabled(rename = "Technique")]
    technique: String, // now treated as Markdown in GUI
    #[tabled(rename = "ID")]
    technique_id: String, // e.g., "T1027"
}

// (No methods needed for DisplayMatch at this time)

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;

    let mut fs_iocs = BTreeSet::new();
    let mut net_iocs = BTreeSet::new();

    let matches = Command::new("mstrings")
        .version("0.1")
        .author("Author Name <dwmetz@gmail.com>")
        .about("Searches for strings in files with YARA-style detections")
        .allow_hyphen_values(true)
        .dont_collapse_args_in_usage(true)
        .args_conflicts_with_subcommands(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("file")
                .help("File to scan")
                .required(false)
                .index(1)
                .num_args(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .num_args(0)
                .help("Save output (must be paired with -t, -j, or -m)"),
        )
        .arg(
            Arg::new("text")
                .short('t')
                .long("text")
                .help("Save report as text")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(&["json", "markdown"]),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Save report as JSON")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(&["text", "markdown"]),
        )
        .arg(
            Arg::new("markdown")
                .short('m')
                .long("markdown")
                .help("Save report as Markdown")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(&["text", "json"]),
        )
        .arg(
            Arg::new("case")
                .long("case")
                .num_args(1)
                .help("Optional case name to group output"),
        )
        .arg(
            Arg::new("output-file")
                .long("output-file")
                .num_args(1)
                .help("Custom output file name (used with --output)"),
        )
        .get_matches();

    let file_path = match matches.get_one::<String>("file").map(String::as_str) {
        Some(path) => path.to_string(),
        None => {
            println!("Enter the file path:");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();  // Remove trailing newline and whitespace


            input.to_string()
        }
    };
    let file_path_copy = file_path.clone(); // clone once for later reuse

    // Ensure Path::new uses trimmed input (file_path is already trimmed at this point)
    let path = std::path::Path::new(&file_path);
    let file = File::open(path)?;
    let mut mstrings = Mstrings::new();
    let mut buffer = Vec::new();
    BufReader::new(file).read_to_end(&mut buffer)?;

    // Calculate SHA256 hash of the file buffer
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let sha256 = format!("{:x}", hasher.finalize());

    let mut current = Vec::new();
    for &byte in &buffer {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else if current.len() >= 4 {
            if let Ok(s) = String::from_utf8(current.clone()) {
                mstrings.process_line(&s);
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current.clone()) {
            mstrings.process_line(&s);
        }
    }

    mstrings.apply_yara_detections()?;

    let display_matches: Vec<DisplayMatch> = mstrings.matches.iter()
        .filter_map(|m| {
            if let Some(rule) = &m.rule_name {
                Some(DisplayMatch {
                    offset: format!("0x{:08X}", m.offset),
                    encoding: format!("{:?}", m.encoding),
                    matched_str: truncate_string(&m.matched_str, 80),
                    rule_name: rule.clone(),
                    tactic: m.tactic.clone().unwrap_or_default(),
                    technique: m.technique.clone().unwrap_or_default(),
                    technique_id: m.technique_id.clone().unwrap_or_default(),
                })
            } else {
                None
            }
        })
        .collect();

    if !is_gui_mode() {
        println!("{}", styled_line("stone", &format!("File: {}", file_path_copy)));
        println!("{}", styled_line("stone", &format!("SHA256: {}", sha256)));
        println!("\n{}\n", format!("{} unique detections matched.", display_matches.len()).truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));
    } else {
        println!("{}", styled_line("stone", &format!("File: {}", file_path_copy)));
        println!("{}", styled_line("stone", &format!("SHA256: {}", sha256)));
        println!("\n{} unique detections matched.\n", display_matches.len());
    }

    // Create the table using the `display_matches`
    use tabled::settings::object::Columns;
    let mut table = TabledTable::new(&display_matches);
    table
        .with(Style::modern())
        .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
        .with(Modify::new(Columns::single(4)).with(Width::wrap(15).keep_words(true)))
        .with(Modify::new(Columns::new(0..)).with(Width::wrap(25).keep_words(true)));

    // Stringify the table after applying formatting, for both display and output file
    let table_str = table.to_string();

    // Ensure the table is printed
    if !is_gui_mode() {
        let mut lines = table_str.lines();
        if let Some(top_border) = lines.next() {
            println!("{}", top_border);
            if let Some(header_row) = lines.next() {
                println!("{}", header_row);
            }
            if let Some(header_border) = lines.next() {
                println!("{}", header_border);
            }
            for line in lines {
                println!("{}", line);
            }
        } else {
            println!("{table_str}");
        }
    } else {
        // For GUI mode, print the table directly
        println!("{table_str}");
        // Handle clicking on "Open TXXXX" buttons (pseudo-code for illustration)
        // In actual GUI, you would have event/callback handling here.
        // For demonstration, if this were a GUI event loop, you might do:
        /*
        use open;
        // Suppose 'row_clicked' is the index of the clicked row
        if let Some(row_clicked) = get_clicked_row_index() {
            if let Some(dm) = display_matches.get(row_clicked) {
                if dm.mitre_button.starts_with("Open ") {
                    if let Some(url) = dm.mitre_url() {
                        let _ = open::that(url);
                    }
                }
            }
        }
        */
    }

    // Pre-compile IOC extraction regexes once, outside the loop.
    //
    // Go binaries store their entire runtime error-message table as one
    // continuous null-free UTF-8 blob in .rodata; the strings extractor
    // emits the whole thing as a single matched_str.  For blobs (len > 300)
    // we use targeted regexes to pull only well-formed patterns out of the
    // blob rather than classifying the whole string.
    // Short strings use the original logic unchanged.
    //
    // \x22 is used in char classes instead of \" to avoid raw-string issues.
    // The regex crate does not support lookarounds, so IP boundary validation
    // is done in Rust after matching.
    let re_url      = Regex::new(r"https?://[^\s\x22'<>]{8,}").unwrap();
    let re_ip       = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
    // Windows-style paths
    let re_fspath   = Regex::new(r"(?i)(?:%\w+%|\\|\$\{[^}]+\})[^\s\x22'<>]*\.(?:exe|bat|ps1|vbs|pdb|dll|txt|zip|lnk)").unwrap();
    // macOS-style paths: /Users/…, ~/Library/…, /Library/…, /private/var/…, /tmp/…
    let re_mac_path = Regex::new(r"(?:~|/Users/[^/\s]+|/Library|/private/var|/tmp)/[^\s\x22'<>]*\.(?:sh|py|dylib|plist|app|pkg|command)").unwrap();

    for m in &mstrings.matches {
        if let Some(rule) = &m.rule_name {
            let _s = m.matched_str.to_lowercase();

            if m.matched_str.len() > 300 {
                // Blob path: extract well-formed IOCs via regex
                for cap in re_url.find_iter(&m.matched_str) {
                    net_iocs.insert(cap.as_str().to_string());
                }
                // IP boundary check: regex crate has no lookarounds, so verify
                // surrounding bytes manually.  127.0.0.1 is omitted — it appears
                // in every Go net-stack binary and has no analytical value.
                // RFC 1918 ranges are kept: a private IP hardcoded in malware
                // strings is a meaningful tell (lateral movement target, lab
                // infrastructure leak, etc.).
                let blob = m.matched_str.as_bytes();
                for mat in re_ip.find_iter(&m.matched_str) {
                    let start = mat.start();
                    let end   = mat.end();
                    let before_ok = start == 0 || !matches!(blob[start - 1], b'0'..=b'9' | b'.');
                    let after_ok  = end == blob.len() || !matches!(blob[end], b'0'..=b'9' | b'.');
                    if before_ok && after_ok && mat.as_str() != "127.0.0.1" {
                        net_iocs.insert(mat.as_str().to_string());
                    }
                }
                for cap in re_fspath.find_iter(&m.matched_str) {
                    let extracted = cap.as_str();
                    // Skip template variables like ${EXTENSION}-FILES.txt
                    if !extracted.starts_with("${") && !extracted.starts_with('%') {
                        fs_iocs.insert(extracted.to_string());
                    }
                }
                for cap in re_mac_path.find_iter(&m.matched_str) {
                    fs_iocs.insert(cap.as_str().to_string());
                }
            } else {
                // Normal path: short discrete string.
                // Normalize key=value pairs — take only the value after '='.
                let candidate: &str = if let Some(pos) = m.matched_str.find('=') {
                    m.matched_str[pos + 1..].trim()
                } else {
                    m.matched_str.trim()
                };
                let sc = candidate.to_lowercase();

                // Quality filters: skip template vars, multi-word command strings,
                // and Rust/C++ namespace-polluted matches — none are usable file IOCs.
                let is_template  = candidate.starts_with("${") || candidate.starts_with('%');
                let has_spaces   = candidate.contains(' ') || candidate.contains('\t');
                let has_namespace = candidate.contains("::");

                if !is_template && !has_spaces && !has_namespace {
                    let rule_lc = rule.to_lowercase();
                    let is_mac_path = sc.starts_with("/users/")
                        || sc.starts_with("/library/")
                        || sc.starts_with("~/library/")
                        || sc.starts_with("/private/")
                        || sc.starts_with("/tmp/");
                    let is_mac_ext = sc.ends_with(".sh")
                        || sc.ends_with(".dylib")
                        || sc.ends_with(".pkg")
                        || sc.ends_with(".command")
                        || sc.ends_with(".plist");

                    if rule_lc.contains("filesystem")
                        || sc.ends_with(".exe")
                        || sc.ends_with(".bat")
                        || sc.ends_with(".ps1")
                        || sc.ends_with(".vbs")
                        || sc.ends_with(".pdb")
                        || is_mac_ext
                        || is_mac_path
                    {
                        fs_iocs.insert(candidate.to_string());
                    } else if rule_lc.contains("ip address")
                        || sc.contains("http:")
                        || sc.contains("https:")
                        || (sc.contains('.') && sc.split('.').count() == 4)
                    {
                        net_iocs.insert(candidate.to_string());
                    }
                }
            }
        }
    }

    // Use the print_iocs function for both headers, with color and proper handling for CLI/GUI
    println!("\n");
    print_iocs("POTENTIAL FILESYSTEM IOCs:", &fs_iocs);

    if !net_iocs.is_empty() {
        println!("\n");
        print_iocs("POTENTIAL NETWORK IOCs:", &net_iocs);
    }

    println!();

    let save_output = matches.get_flag("output") || matches.contains_id("case");
    let text = matches.get_flag("text");
    let json = matches.get_flag("json");
    let markdown = matches.get_flag("markdown");


    if save_output {
        let output_dir = match matches.get_one::<String>("case") {
            Some(case_name) => {
                common_config::ensure_case_json(case_name);
                get_output_dir("cases").join(case_name).join("mstrings")
            }
            None => get_output_dir("mstrings"),
        };
        std::fs::create_dir_all(&output_dir)?;
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

        let format = if text {
            "txt"
        } else if json {
            "json"
        } else if markdown {
            "md"
        } else {
            "md"
        };

        let custom_name = matches.get_one::<String>("output-file").map(|s| s.as_str());

        // Build the report content (reuse printed table and IOCs)
        let mut report_buffer = String::new();

        let detection_count = mstrings.matches.iter().filter(|m| m.rule_name.is_some()).count();

        // Add file and hash metadata at the top of the report
        if format == "md" {
            report_buffer.push_str("# mStrings Analysis Report\n\n");
            report_buffer.push_str(&format!("**File:** `{}`  \n", file_path_copy));
            report_buffer.push_str(&format!("**SHA256:** `{}`  \n", sha256));
            report_buffer.push_str(&format!("**Detections:** {}  \n\n", detection_count));
        } else {
            report_buffer.push_str(&format!("File: {}\n", file_path_copy));
            report_buffer.push_str(&format!("SHA256: {}\n\n", sha256));
        }

        // Add summary for non-md
        if format != "md" {
            report_buffer.push_str(&format!("{} unique detections matched.\n\n", detection_count));
        }

        // Add table content
        if format == "txt" {
            report_buffer.push_str(&format!("{}\n\n", table_str));
        } else if format == "md" {
            let mut md_table = TabledTable::new(&display_matches);
            md_table
                .with(Style::markdown())
                .with(Modify::new(Columns::new(0..)).with(Alignment::left()));
            report_buffer.push_str("## Detections\n\n");
            report_buffer.push_str(&format!("{}\n\n", md_table.to_string()));
        }

        // Add IOCs
        if !fs_iocs.is_empty() {
            if format == "md" {
                report_buffer.push_str("## Potential Filesystem IOCs\n\n");
                for ioc in &fs_iocs {
                    report_buffer.push_str(&format!("- `{}`\n", ioc));
                }
            } else {
                report_buffer.push_str("POTENTIAL FILESYSTEM IOCs:\n");
                for ioc in &fs_iocs {
                    report_buffer.push_str(&format!("{}\n", ioc));
                }
            }
            report_buffer.push('\n');
        }

        if !net_iocs.is_empty() {
            if format == "md" {
                report_buffer.push_str("## Potential Network IOCs\n\n");
                for ioc in &net_iocs {
                    report_buffer.push_str(&format!("- `{}`\n", ioc));
                }
            } else {
                report_buffer.push_str("POTENTIAL NETWORK IOCs:\n");
                for ioc in &net_iocs {
                    report_buffer.push_str(&format!("{}\n", ioc));
                }
            }
            report_buffer.push('\n');
        }

        match format {
            "txt" => {
                let text_path = output_dir.join(custom_name.unwrap_or(&format!("report_{}.txt", timestamp)));
                if let Some(parent) = text_path.parent() {
                    std::fs::create_dir_all(parent).expect("Failed to create output directory");
                }
                let mut file = File::create(&text_path).expect("Failed to save text report");
                file.write_all(report_buffer.as_bytes()).expect("Failed to write report");
                println!("\n{}\n", format!("Text report saved to: {}", text_path.display()).green());
            }
            "md" => {
                let md_path = output_dir.join(custom_name.unwrap_or(&format!("report_{}.md", timestamp)));
                if let Some(parent) = md_path.parent() {
                    std::fs::create_dir_all(parent).expect("Failed to create output directory");
                }
                let mut file = File::create(&md_path).expect("Failed to save markdown report");
                file.write_all(report_buffer.as_bytes()).expect("Failed to write report");
                println!("\n{}\n", format!("Markdown report saved to: {}", md_path.display()).green());
            }
            _ => {
                let json_path = output_dir.join(custom_name.unwrap_or(&format!("report_{}.json", timestamp)));
                if let Some(parent) = json_path.parent() {
                    std::fs::create_dir_all(parent).expect("Failed to create output directory");
                }
                let mut file = File::create(&json_path).expect("Failed to create JSON report file");
                let matched_only: Vec<_> = mstrings.matches.iter().filter(|m| m.rule_name.is_some()).collect();
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "file": file_path_copy,
                    "sha256": sha256,
                    "matches": matched_only
                })).expect("Failed to serialize report");
                file.write_all(json.as_bytes()).expect("Failed to write JSON report");
                println!("\n{}\n", format!("JSON report saved to: {}", json_path.display()).green());
            }
        }
    } else {
        if !is_gui_mode() {
            println!("\nOutput was not saved.\n");
        }
    }
    // End: Output saving logic
    // Optional CLI footer: MITRE reference note
    if !is_gui_mode() {
        println!("Note: MITRE Tactic IDs can be referenced with MITRE_lookup tool.");
    }
    Ok(())
}
