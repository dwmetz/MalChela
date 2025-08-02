use std::fs::File;
use std::io::{BufReader, stdin, BufRead};
use std::path::PathBuf;
use std::env;
use std::fs;

use clap::Parser;
use serde::Deserialize;
use regex::RegexBuilder;
use colored::*;

fn find_workspace_root() -> std::io::Result<PathBuf> {
    let exe_path = env::current_exe()?;
    let resolved_exe_path = fs::canonicalize(exe_path)?;

    if let Some(parent1) = resolved_exe_path.parent() {
        if let Some(parent2) = parent1.parent() {
            let workspace_root = parent2.to_path_buf();
            if workspace_root.exists() && workspace_root.is_dir() {
                return Ok(workspace_root);
            }
        }
    }
    eprintln!("{}", "Error: Workspace root not found.".red());
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Workspace root not found",
    ))
}

#[derive(Parser)]
#[command(name = "MITRE Lookup")]
#[command(about = "Search MITRE ATT&CK techniques locally", long_about = None)]
struct Args {
    /// Search term (ID, name, tactic, or keyword)
    #[arg()]
    query: Option<String>,

    /// Show full output without truncation
    #[arg(short, long)]
    full: bool,
}

#[derive(Deserialize)]
struct RelatedItem {
    name: String,
    description: String,
}

#[derive(Deserialize)]
struct Technique {
    id: String,
    name: String,
    tactic: String,
    description: String,
    platforms: Vec<String>,
    permissions_required: Vec<String>,
    detection: String,
    mitigations: Vec<String>,
    malware: Vec<RelatedItem>,
    tools: Vec<RelatedItem>,
    intrusion_sets: Vec<RelatedItem>,
}

fn main() {
    let args = Args::parse();

    let query = match args.query {
        Some(q) => q,
        None => {
            println!("Enter search query:");
            let mut input = String::new();
            stdin().lock().read_line(&mut input).expect("Failed to read input");
            input.trim().to_string()
        }
    };

    let workspace_root = find_workspace_root().expect("Unable to locate workspace root");
    let json_path = workspace_root
        .parent()
        .unwrap_or(&workspace_root)
        .join("assets")
        .join("mitre_techniques.json");



    let reader = BufReader::new(File::open(&json_path).unwrap_or_else(|e| panic!("Failed to open JSON: {}", e)));
    let techniques: Vec<Technique> =
        serde_json::from_reader(reader).expect("Failed to parse JSON");

    let query = query.to_lowercase();

    let highlight_re = RegexBuilder::new(&regex::escape(&query))
        .case_insensitive(true)
        .build()
        .unwrap();

    let matches: Vec<_> = techniques
        .into_iter()
        .filter(|tech| {
            tech.id.to_lowercase().contains(&query)
                || tech.name.to_lowercase().contains(&query)
                || tech.tactic.to_lowercase().contains(&query)
                || tech.description.to_lowercase().contains(&query)
                || tech.detection.to_lowercase().contains(&query)
                || tech.platforms.iter().any(|p| p.to_lowercase().contains(&query))
                || tech.permissions_required.iter().any(|p| p.to_lowercase().contains(&query))
                || tech.mitigations.iter().any(|m| m.to_lowercase().contains(&query))
                || tech.malware.iter().any(|m| m.name.to_lowercase().contains(&query) || m.description.to_lowercase().contains(&query))
                || tech.tools.iter().any(|t| t.name.to_lowercase().contains(&query) || t.description.to_lowercase().contains(&query))
                || tech.intrusion_sets.iter().any(|g| g.name.to_lowercase().contains(&query) || g.description.to_lowercase().contains(&query))
        })
        .collect();

    if matches.is_empty() {
        println!("No results found for query: {}", query);
    } else {
        let show_full = args.full;
        let max_items = if args.full { usize::MAX } else { 3 };
        println!();
        for t in matches {
            let id = highlight_re.replace_all(&t.id, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
            let name = highlight_re.replace_all(&t.name, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
            println!("{}", format!("{} - {}", id, name).bright_blue().bold());
            println!();
            let tactic = highlight_re.replace_all(&t.tactic, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
            println!("{} {}", "Tactic(s):".truecolor(255, 165, 0).bold(), tactic);
            println!();
            let platforms_joined = t.platforms.join(", ");
            let platforms = highlight_re.replace_all(&platforms_joined, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
            println!("{} {}", "Platforms:".truecolor(255, 165, 0).bold(), platforms);
            println!();

            let detection_output = t.detection.clone();
            let detection_output = highlight_re.replace_all(&detection_output, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();

            let description_output = t.description.clone();
            let description_output = highlight_re.replace_all(&description_output, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();

            println!("{} {}", "Detection:".truecolor(255, 165, 0).bold(), detection_output);
            println!();
            println!("{} {}", "Description:".truecolor(255, 165, 0).bold(), description_output);
            println!();

            if !t.mitigations.is_empty() {
                println!("{}", "Mitigations:".truecolor(255, 165, 0).bold());
                for m in &t.mitigations {
                    let mitigation = highlight_re.replace_all(m, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    println!("- {}", mitigation);
                }
            }

            if !t.malware.is_empty() {
                println!("\n{}", "Malware:".truecolor(255, 165, 0).bold());
                for (i, mw) in t.malware.iter().enumerate() {
                    if !show_full && i >= max_items {
                        break;
                    }
                    let mw_name = highlight_re.replace_all(&mw.name, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    let desc = mw.description.clone();
                    let desc = highlight_re.replace_all(&desc, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    println!("- {}: {}", mw_name.cyan().bold(), desc);
                }
                if !show_full && t.malware.len() > max_items {
                    println!("  ...and {} more", t.malware.len() - max_items);
                }
            }

            if !t.tools.is_empty() {
                println!("\n{}", "Tools:".truecolor(255, 165, 0).bold());
                for (i, tool) in t.tools.iter().enumerate() {
                    if !show_full && i >= max_items {
                        break;
                    }
                    let tool_name = highlight_re.replace_all(&tool.name, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    let desc = tool.description.clone();
                    let desc = highlight_re.replace_all(&desc, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    println!("- {}: {}", tool_name.cyan().bold(), desc);
                }
                if !show_full && t.tools.len() > max_items {
                    println!("  ...and {} more", t.tools.len() - max_items);
                }
            }

            if !t.intrusion_sets.is_empty() {
                println!("\n{}", "Intrusion Sets:".truecolor(255, 165, 0).bold());
                for (i, group) in t.intrusion_sets.iter().enumerate() {
                    if !show_full && i >= max_items {
                        break;
                    }
                    let group_name = highlight_re.replace_all(&group.name, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    let desc = group.description.clone();
                    let desc = highlight_re.replace_all(&desc, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
                    println!("- {}: {}", group_name.cyan().bold(), desc);
                }
                if !show_full && t.intrusion_sets.len() > max_items {
                    println!("  ...and {} more", t.intrusion_sets.len() - max_items);
                }
            }

            println!("\n{}", "-".repeat(60));
        }
    }
}