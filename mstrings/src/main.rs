use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path; // Add this import
use serde::Deserialize;
use serde_yaml;
use regex::Regex;
use std::io;
use std::process::Command;
use serde_json;
use colored::*;

#[derive(Debug, Deserialize, Clone, serde::Serialize)]
struct MitreTechnique {
    technique_id: String,
    technique_name: String,
    tactics: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, serde::Serialize)]
struct SigmaRule {
    title: String,
    id: String,
    detection: HashMap<String, Vec<String>>,
    mitre: Option<Vec<MitreTechnique>>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct EnhancedMatchResult {
    rule_title: String,
    matched_string: String,
    hex_offset: usize,
    mitre_techniques: Vec<MitreTechnique>,
    encoding: String,
    original_base64: Option<String>,
}

fn find_rule_matches(
    rule: &SigmaRule,
    content: &str,
    offset_base: usize,
    original_base64: Option<String>,
) -> Result<Vec<EnhancedMatchResult>, Box<dyn std::error::Error>> {
    let mut matches = Vec::new();

    if let Some(strings) = rule.detection.get("strings") {
        for pattern in strings {
            let regex = Regex::new(pattern)?;
            for match_obj in regex.find_iter(content) {
                let matched_string = match_obj.as_str().to_string();

                if matched_string.contains("microsoft.com") {
                    continue;
                }

                let hex_offset = offset_base + match_obj.start();
                let mitre_techniques = rule.mitre.clone().unwrap_or_else(Vec::new);

                let encoding = if matched_string.is_ascii() {
                    "A".to_string()
                } else {
                    "U".to_string()
                };

                matches.push(EnhancedMatchResult {
                    rule_title: rule.title.clone(),
                    matched_string: matched_string.clone(),
                    hex_offset,
                    mitre_techniques,
                    encoding: encoding.clone(),
                    original_base64: original_base64.clone(),
                });
            }
        }
    }
    Ok(matches)
}

fn call_strings_to_file(file_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("strings").arg(file_path).output()?;

    if !output.status.success() {
        return Err(format!("strings command failed: {:?}", output.status).into());
    }

    let stdout = output.stdout;
    fs::write(output_path, stdout)?;

    Ok(())
}

fn find_potential_interesting_strings(strings_content: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let pattern = r"\.(pdb|ps1|exe)$";
    let regex = Regex::new(pattern)?;
    let mut interesting_strings = HashSet::new();

    for line in strings_content.lines() {
        if regex.is_match(line) {
            interesting_strings.insert(line.to_string());
        }
    }
    Ok(interesting_strings)
}

fn find_potential_network_iocs(strings_content: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let mut network_iocs = HashSet::new();

    // HTTP regex
    let http_regex = Regex::new(r"^http")?;
    for line in strings_content.lines() {
        if http_regex.is_match(line) {
            network_iocs.insert(line.to_string());
        }
    }

    // IP address regex
    let ip_regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")?;
    for line in strings_content.lines() {
        for capture in ip_regex.captures_iter(line) {
            if let Some(match_obj) = capture.get(0) {
                network_iocs.insert(match_obj.as_str().to_string());
            }
        }
    }

    Ok(network_iocs)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    const DETECTIONS_YAML_PATH: &str = "detections.yaml";
    const SAVED_RESULTS_DIR: &str = "Saved_Results";

    let detections_yaml_content = fs::read_to_string(DETECTIONS_YAML_PATH)?;
    let sigma_rules: HashMap<String, SigmaRule> = serde_yaml::from_str(&detections_yaml_content)?;

    println!("Enter the file path to scan:");
    let mut file_path = String::new();
    io::stdin().read_line(&mut file_path)?;
    let file_path = file_path.trim();

    if !Path::new(SAVED_RESULTS_DIR).exists() {
        fs::create_dir(SAVED_RESULTS_DIR)?;
    }

    let file_name = Path::new(file_path).file_name().unwrap_or_default().to_string_lossy();
    let strings_output_path = format!("{}/{}.strings.txt", SAVED_RESULTS_DIR, file_name);
    let json_output_path = format!("{}/{}.detection.json", SAVED_RESULTS_DIR, file_name);

    call_strings_to_file(file_path, &strings_output_path)?;

    let strings_content = fs::read_to_string(&strings_output_path)?;

    let mut enhanced_matches: Vec<EnhancedMatchResult> = Vec::new();

    for (_rule_id, rule) in &sigma_rules {
        println!("Checking rule: {} (ID: {})", rule.title, rule.id);
        enhanced_matches.extend(find_rule_matches(rule, &strings_content, 0, None)?);
    }

    let mut grouped_matches: HashMap<String, Vec<EnhancedMatchResult>> = HashMap::new();
    for match_result in &enhanced_matches {
        grouped_matches
            .entry(match_result.rule_title.clone())
            .or_insert_with(Vec::new)
            .push(match_result.clone());
    }

    let mut grouped_mitre_matches: HashMap<String, Vec<EnhancedMatchResult>> = HashMap::new();

    for (_rule_title, rule_matches) in &grouped_matches {
        for match_result in rule_matches {
            for tech in &match_result.mitre_techniques {
                grouped_mitre_matches
                    .entry(tech.technique_id.clone())
                    .or_insert_with(Vec::new)
                    .push(match_result.clone());
            }
        }
    }

    let interesting_strings = find_potential_interesting_strings(&strings_content)?;
    let network_iocs = find_potential_network_iocs(&strings_content)?;

    let json_output_data = serde_json::json!({
        "enhanced_matches": enhanced_matches,
        "potential_iocs": interesting_strings.iter().cloned().collect::<Vec<String>>(),
        "network_iocs": network_iocs.iter().cloned().collect::<Vec<String>>(),
    });

    fs::write(&json_output_path, serde_json::to_string_pretty(&json_output_data)?)?;

    println!("\n--------------------------------------------------------------------------------\n");
    for (tech_id, matches) in &grouped_mitre_matches {
        if let Some(first_match) = matches.first() {
            if let Some(tech) = first_match.mitre_techniques.iter().find(|t| t.technique_id == *tech_id) {
                println!("\nMITRE Technique: {} ({})", tech.technique_name.green(), tech_id.green());
                let colored_tactics: Vec<String> = tech.tactics.iter().map(|tactic| tactic.green().to_string()).collect();
                println!("Tactics: {:?}", colored_tactics);
            }
        }

        for match_result in matches {
            let colored_output = format!(
                "0x{} :: {} :: {} :: Detected by {}",
                format!("{:08x}", match_result.hex_offset).blue(),
                match_result.encoding.yellow(),
                match_result.matched_string.red(),
                match_result.rule_title.cyan(),
            );
            println!("{}", colored_output);
        }
    }

    println!("\n--------------------------------------------------------------------------------\n");

    if !interesting_strings.is_empty() {
        let colored_header = "POTENTIAL FILESYSTEM IOC's".yellow();
        println!("\n{}", colored_header);
        for s in &interesting_strings {
            let trimmed = s.trim();
            if !trimmed.is_empty() && trimmed.chars().any(|c| !c.is_whitespace()) {
                println!("{}", s.red());
            }
        }
    }

    if !network_iocs.is_empty() {
        let colored_header = "POTENTIAL NETWORK IOC's".yellow();
        println!("\n{}", colored_header);
        for s in &network_iocs {
            let trimmed = s.trim();
            if !trimmed.is_empty() && trimmed.chars().any(|c| !c.is_whitespace()) {
                println!("{}", s.red());
            }
        }
    }

    println!(
        "\nSaved strings output to: {}\nSaved detection results to: {}\n",
        strings_output_path, json_output_path
    );

    println!("Do you want to review the raw strings output? (y/n)");
    let mut review_choice = String::new();
    io::stdin().read_line(&mut review_choice)?;
    let review_choice = review_choice.trim().to_lowercase();

    if review_choice == "y" {
        let output = Command::new("code")
            .arg(&strings_output_path)
            .output()
            .expect("Failed to execute VS Code command");

        if !output.status.success() {
            eprintln!(
                "Error opening VS Code: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    Ok(())
}