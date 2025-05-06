use std::fs::File;
use std::io::{self, BufReader, Write, Read};

use common_config::get_output_dir;

use clap::{Arg, Command};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use colored::*;
use tabled::{Table as TabledTable, Tabled};
use tabled::settings::{Style, Modify, Alignment, object::Columns, Width};



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

struct Mstrings {
    matches: Vec<Match>,
}

impl Mstrings {
    pub fn new() -> Self {
        Self { matches: Vec::new() }
    }

    pub fn process_line(&mut self, line: &str) {
        if !line.trim().is_empty() {
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
            });
        }
    }

    pub fn apply_yara_detections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let yaml_content = std::fs::read_to_string("detections.yaml")?;
        let raw_rules: HashMap<String, Detection> = serde_yaml::from_str(&yaml_content)?;

        let mut compiled_rules = Vec::new();
        for (_key, det) in raw_rules {
            for pattern in det.detection.strings {
                if let Ok(regex) = Regex::new(&pattern) {
                    for mitre in &det.mitre {
                        compiled_rules.push((regex.clone(), det.title.clone(), mitre.tactics.join(", "), format!("{} ({})", mitre.technique_name, mitre.technique_id)));
                    }
                }
            }
        }

        for m in &mut self.matches {
            for (regex, rule_name, tactic, technique) in &compiled_rules {
                if regex.is_match(&m.matched_str) {
                    m.rule_name = Some(rule_name.clone());
                    m.tactic = Some(tactic.clone());
                    m.technique = Some(technique.clone());
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
    technique: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;

    let mut fs_iocs = BTreeSet::new();
    let mut net_iocs = BTreeSet::new();

    let matches = Command::new("mstrings")
        .version("0.1")
        .author("Author Name <dwmetz@gmail.com>")
        .about("Searches for strings in files with YARA-style detections")
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
        .get_matches();

    let file_path = match matches.get_one::<String>("file").map(String::as_str) {
        Some(path) => path.to_string(),
        None => {
            println!("Enter the file path:");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    let file = File::open(file_path)?;
    let mut mstrings = Mstrings::new();
    let mut buffer = Vec::new();
    BufReader::new(file).read_to_end(&mut buffer)?;

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
                })
            } else {
                None
            }
        })
        .collect();

    if std::env::var("MALCHELA_GUI").is_err() {
        println!("\n{}\n", format!("{} unique detections matched.", display_matches.len()).truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));
    } else {
        println!("\n{} unique detections matched.\n", display_matches.len());
    }

    // Create the table using the `display_matches`
    let mut table = TabledTable::new(display_matches);

    // Apply the styles
    table
        .with(Style::modern())
        .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
        .with(Modify::new(Columns::new(0..)).with(Width::wrap(40).keep_words(true)));

    // Ensure the table is printed
    if std::env::var("MALCHELA_GUI").is_err() {
        let table_str = format!("{table}");
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
        println!("{table}");
    }

    for m in &mstrings.matches {
        if let Some(rule) = &m.rule_name {
            let s = m.matched_str.to_lowercase();

            if rule.to_lowercase().contains("filesystem")
                || s.contains(".exe")
                || s.contains(".bat")
                || s.contains(".ps1")
                || s.contains(".vbs")
                || s.contains(".pdb")
            {
                fs_iocs.insert(m.matched_str.clone());
            } else if rule.to_lowercase().contains("ip address")
                || s.contains("http:")
                || s.contains("https:")
                || (s.contains('.') && s.split('.').count() == 4)
            {
                net_iocs.insert(m.matched_str.clone());
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

    let save_output = matches.get_flag("output");
    let text = matches.get_flag("text");
    let json = matches.get_flag("json");
    let markdown = matches.get_flag("markdown");


    if save_output {
        let output_dir = get_output_dir("mstrings");
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

        let format = if text {
            "txt"
        } else if json {
            "json"
        } else if markdown {
            "md"
        } else {
            println!("\nOutput format required. Use -t, -j, or -m with -o.");
            println!();
            println!("Output was not saved.");
            return Ok(());
        };

        // Build the report content (reuse printed table and IOCs)
        let mut report_buffer = String::new();

        // Add summary
        report_buffer.push_str(&format!("{} unique detections matched.\n\n", mstrings.matches.iter().filter(|m| m.rule_name.is_some()).count()));

        // Add table content
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
                    })
                } else {
                    None
                }
            })
            .collect();

        let mut table = TabledTable::new(display_matches);
        table
            .with(Style::modern())
            .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
            .with(Modify::new(Columns::new(0..)).with(Width::wrap(40).keep_words(true)));

        report_buffer.push_str(&format!("{}\n\n", table.to_string()));

        // Add IOCs
        if !fs_iocs.is_empty() {
            report_buffer.push_str("POTENTIAL FILESYSTEM IOCs:\n");
            for ioc in &fs_iocs {
                report_buffer.push_str(&format!("{}\n", ioc));
            }
            report_buffer.push('\n');
        }

        if !net_iocs.is_empty() {
            report_buffer.push_str("POTENTIAL NETWORK IOCs:\n");
            for ioc in &net_iocs {
                report_buffer.push_str(&format!("{}\n", ioc));
            }
            report_buffer.push('\n');
        }

        match format {
            "txt" => {
                let text_path = output_dir.join(format!("report_{}.txt", timestamp));
                let mut file = File::create(&text_path).expect("Failed to save text report");
                file.write_all(report_buffer.as_bytes()).expect("Failed to write report");
                println!("\n{}", format!("Text report saved to: {}", text_path.display()).green());
            }
            "md" => {
                let md_path = output_dir.join(format!("report_{}.md", timestamp));
                let mut file = File::create(&md_path).expect("Failed to save markdown report");
                file.write_all(report_buffer.as_bytes()).expect("Failed to write report");
                println!("\n{}", format!("Markdown report saved to: {}", md_path.display()).green());
            }
            _ => {
                let json_path = output_dir.join(format!("report_{}.json", timestamp));
                let mut file = File::create(&json_path).expect("Failed to create JSON report file");
                let matched_only: Vec<_> = mstrings.matches.iter().filter(|m| m.rule_name.is_some()).collect();
                let json = serde_json::to_string_pretty(&matched_only).expect("Failed to serialize report");
                file.write_all(json.as_bytes()).expect("Failed to write JSON report");
                println!("\n{}", format!("JSON report saved to: {}", json_path.display()).green());
            }
        }
    } else {
        if std::env::var("MALCHELA_GUI_MODE").is_err() {
            println!("\nOutput was not saved.\n");
        }
    }
    // End: Output saving logic
    Ok(())
}
