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
use chrono::Utc;

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

struct Mstrings {
    matches: Vec<Match>,
}

impl Mstrings {
    pub fn new() -> Self {
        Self { matches: Vec::new() }
    }

    pub fn process_line(&mut self, line: &str) {
        // Simulate offset and encoding detection
        if !line.trim().is_empty() {
            self.matches.push(Match {
                offset: self.matches.len() * 16,
                encoding: if self.matches.len() % 3 == 0 {
                    Encoding::Utf8
                } else {
                    Encoding::Ascii
                },
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
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value("AUTO")
                .help("Save output to JSON file. If no file is provided, a default name will be used."),
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
    let output_path = matches
        .get_one::<String>("output")
        .map(|s| {
            if s == "AUTO" {
                format!("mstrings-{}-report.json", Utc::now().format("%Y%m%d%H%M%S"))
            } else {
                s.to_string()
            }
        });

    let file = File::open(file_path)?;
    let mut mstrings = Mstrings::new();
    let mut buffer = Vec::new();
    BufReader::new(file).read_to_end(&mut buffer)?;

    // Extract ASCII strings of length >= 4
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
    // Catch trailing string
    if current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current.clone()) {
            mstrings.process_line(&s);
        }
    }

    // Apply YARA-style detections
    mstrings.apply_yara_detections()?;

    if let Some(ref out) = output_path {
        let json_path = get_output_dir("mstrings").join(out);
        let mut output_file = File::create(json_path)?;
        let json = serde_json::to_string_pretty(&mstrings.matches)?;
        output_file.write_all(json.as_bytes())?;
    }

    let mut display_matches = Vec::new();

    for m in &mstrings.matches {
        if let Some(rule) = &m.rule_name {
            let offset = format!("0x{:06x}", m.offset);
            let encoding = format!("{:?}", m.encoding);
            let matched = m.matched_str.clone();
            let rule = rule.clone();
            let tactic = m.tactic.clone().unwrap_or_default();
            let technique = m.technique.clone().unwrap_or_default();

            display_matches.push(DisplayMatch {
                offset,
                encoding,
                matched_str: matched,
                rule_name: rule,
                tactic,
                technique,
            });
        }
    }

    if std::env::var("MALCHELA_GUI").is_err() {
        println!("\n{}\n", format!("{} unique detections matched.", display_matches.len()).truecolor(215, 100, 40));
    } else {
        println!("\n{} unique detections matched.\n", display_matches.len());
    }

    let mut table = TabledTable::new(display_matches);
    table
        .with(Style::modern())
        .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
        .with(Modify::new(Columns::new(0..)).with(Width::wrap(40).keep_words(true)));

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
        println!("{table}");
    }

    use std::collections::BTreeSet;

    let mut fs_iocs = BTreeSet::new();
    let mut net_iocs = BTreeSet::new();

    for m in &mstrings.matches {
        if let Some(rule) = &m.rule_name {
            let s = m.matched_str.to_lowercase();
            if rule.to_lowercase().contains("filesystem") || s.ends_with(".exe") || s.ends_with(".dll") || s.contains(".pdb") {
                fs_iocs.insert(m.matched_str.clone());
            } else if rule.to_lowercase().contains("ip address") || s.contains('.') && s.split('.').count() == 4 {
                net_iocs.insert(m.matched_str.clone());
            }
        }
    }

    if !fs_iocs.is_empty() {
        if std::env::var("MALCHELA_GUI").is_err() {
            println!("\n{}", "POTENTIAL FILESYSTEM IOC's".truecolor(215, 100, 40));
        } else {
            println!("\nPOTENTIAL FILESYSTEM IOC's");
        }
        for ioc in fs_iocs {
            println!("{}", ioc);
        }
    }

    if !net_iocs.is_empty() {
        if std::env::var("MALCHELA_GUI").is_err() {
            println!("\n{}", "POTENTIAL NETWORK IOC's".truecolor(215, 100, 40));
        } else {
            println!("\nPOTENTIAL NETWORK IOC's");
        }
        for ioc in net_iocs {
            println!("{}", ioc);
        }
    }

    if let Some(ref out) = output_path {
        println!(
            "\nThe results have been saved to: {}",
            get_output_dir("mstrings").join(out).display()
        );
    }
    Ok(())
}
