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
    // Added with the ATT&CK v20 dataset (scripts/build_mitre_techniques.py);
    // defaulted so an older mitre_techniques.json still loads.
    #[serde(default)]
    deprecated: bool,
    #[serde(default)]
    revoked_by: Option<String>,
    #[serde(default)]
    attack_version: Option<String>,
}

#[derive(Deserialize)]
struct TacticTechnique {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct Tactic {
    id: String,
    name: String,
    shortname: String,
    description: String,
    techniques: Vec<TacticTechnique>,
    #[serde(default)]
    attack_version: Option<String>,
}

/// Tactic entries (assets/mitre_tactics.json, written by
/// scripts/build_mitre_techniques.py). Optional: absent on older datasets.
fn load_tactics(assets: &std::path::Path) -> Vec<Tactic> {
    File::open(assets.join("mitre_tactics.json"))
        .ok()
        .and_then(|f| serde_json::from_reader(BufReader::new(f)).ok())
        .unwrap_or_default()
}

/// Which tactics a query names: a TA ID, a tactic name or shortname, the
/// retired "Defense Evasion", or "tactics" for the whole list.
fn tactic_hits<'a>(tactics: &'a [Tactic], query: &str, nquery: &str) -> (Vec<&'a Tactic>, bool) {
    if nquery == "tactics" || nquery == "tactic" {
        return (tactics.iter().collect(), true);
    }
    if nquery == "defense evasion" {
        return (tactics.iter().filter(|t| t.id == "TA0005" || t.id == "TA0112").collect(), false);
    }
    let hits: Vec<&Tactic> = tactics
        .iter()
        .filter(|t| t.id.to_lowercase() == query || norm(&t.name) == nquery || norm(&t.shortname) == nquery)
        .collect();
    // TA0005 was Defense Evasion before v20: show its successor alongside it.
    if query == "ta0005" {
        return (tactics.iter().filter(|t| t.id == "TA0005" || t.id == "TA0112").collect(), false);
    }
    (hits, false)
}

fn print_tactics(hits: &[&Tactic], list_only: bool, full: bool, nquery: &str, query: &str) {
    if let Some(v) = hits.iter().find_map(|t| t.attack_version.clone()) {
        println!("{}", format!("MITRE ATT&CK Enterprise v{}", v).truecolor(200, 200, 200));
    }
    if nquery == "defense evasion" || query == "ta0005" {
        println!(
            "{}",
            "Note: ATT&CK v20 retired the Defense Evasion tactic. TA0005 is now Stealth (hiding and obfuscation), and Defense Impairment (TA0112) is new (disabling or tampering with defenses)."
                .truecolor(255, 165, 0)
        );
    }
    println!();
    if list_only {
        println!("{}", "Enterprise tactics (matrix order):".truecolor(255, 165, 0).bold());
        for t in hits {
            let top = t.techniques.iter().filter(|x| !x.id.contains('.')).count();
            println!(
                "  {}  {:<22} {} techniques, {} sub-techniques",
                t.id.bright_blue().bold(),
                t.name,
                top,
                t.techniques.len() - top
            );
        }
        println!("\nLook up a tactic (e.g. TA0002 or \"execution\") for its description and techniques.");
        return;
    }
    for t in hits {
        println!("{}", format!("{} - {} (tactic)", t.id, t.name).bright_blue().bold());
        println!();
        println!("{} {}", "Shortname:".truecolor(255, 165, 0).bold(), t.shortname);
        println!();
        println!("{} {}", "Description:".truecolor(255, 165, 0).bold(), t.description);
        println!();
        let top: Vec<&TacticTechnique> = t.techniques.iter().filter(|x| !x.id.contains('.')).collect();
        println!(
            "{}",
            format!("Techniques ({} techniques, {} sub-techniques):", top.len(), t.techniques.len() - top.len())
                .truecolor(255, 165, 0)
                .bold()
        );
        for tech in &top {
            let subs: Vec<&TacticTechnique> =
                t.techniques.iter().filter(|x| x.id.starts_with(&format!("{}.", tech.id))).collect();
            if subs.is_empty() || full {
                println!("- {} {}", tech.id.cyan().bold(), tech.name);
            } else {
                println!("- {} {} {}", tech.id.cyan().bold(), tech.name, format!("(+{} sub-techniques)", subs.len()).truecolor(200, 200, 200));
            }
            if full {
                for sub in subs {
                    println!("    - {} {}", sub.id.cyan(), sub.name);
                }
            }
        }
        // Sub-techniques listed under a tactic whose parent belongs to a different one.
        let orphans: Vec<&TacticTechnique> = t
            .techniques
            .iter()
            .filter(|x| x.id.contains('.') && !top.iter().any(|p| x.id.starts_with(&format!("{}.", p.id))))
            .collect();
        if !orphans.is_empty() {
            println!("{}", "Sub-techniques (parent technique is under another tactic):".truecolor(200, 200, 200));
            for o in orphans {
                println!("- {} {}", o.id.cyan().bold(), o.name);
            }
        }
        if !full {
            println!("\n{}", "Use --full to list every sub-technique; look up any technique ID for details.".truecolor(200, 200, 200));
        }
        println!("\n{}", "-".repeat(60));
    }
}

/// Tactic shortnames are hyphenated ("defense-impairment"); let "defense
/// impairment" match too.
fn norm(s: &str) -> String {
    s.to_lowercase().replace('-', " ")
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

    let query = query.trim().to_lowercase();
    let nquery = norm(&query);

    // Tactics first: a TA ID or tactic name gets a tactic card (description
    // and its techniques) instead of a keyword match across techniques.
    let tactics = load_tactics(json_path.parent().unwrap_or(&workspace_root));
    let (tac_hits, list_only) = tactic_hits(&tactics, &query, &nquery);
    if !tac_hits.is_empty() {
        print_tactics(&tac_hits, list_only, args.full, &nquery, &query);
        return;
    }

    // ATT&CK v20 retired "Defense Evasion": TA0005 is now Stealth and the
    // new TA0112 Defense Impairment took the defense-tampering techniques.
    // Searching the old name returns both successors instead of nothing.
    let legacy_defense_evasion = nquery == "defense evasion" || query == "ta0005";
    if legacy_defense_evasion {
        println!(
            "{}",
            "Note: ATT&CK v20 retired the Defense Evasion tactic. TA0005 is now Stealth, and Defense Impairment (TA0112) is new — showing techniques from both."
                .truecolor(255, 165, 0)
        );
    }
    let attack_version = techniques.iter().find_map(|t| t.attack_version.clone());
    let names: std::collections::HashMap<String, String> =
        techniques.iter().map(|t| (t.id.clone(), t.name.clone())).collect();

    let highlight_re = RegexBuilder::new(&regex::escape(&query))
        .case_insensitive(true)
        .build()
        .unwrap();

    let mut matches: Vec<_> = techniques
        .into_iter()
        .filter(|tech| {
            (legacy_defense_evasion
                && (tech.tactic.contains("stealth") || tech.tactic.contains("defense-impairment") || tech.tactic.contains("defense-evasion")))
                || tech.id.to_lowercase().contains(&query)
                || norm(&tech.tactic).contains(&nquery)
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
    // Current techniques first; deprecated ones (kept so old IDs still
    // resolve) after them.
    matches.sort_by_key(|t| t.deprecated);

    if matches.is_empty() {
        println!("No results found for query: {}", query);
    } else {
        let show_full = args.full;
        let max_items = if args.full { usize::MAX } else { 3 };
        if let Some(v) = &attack_version {
            println!("{}", format!("MITRE ATT&CK Enterprise v{}", v).truecolor(200, 200, 200));
        }
        println!();
        for t in matches {
            let id = highlight_re.replace_all(&t.id, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
            let name = highlight_re.replace_all(&t.name, |caps: &regex::Captures| caps[0].yellow().bold().to_string()).to_string();
            println!("{}", format!("{} - {}", id, name).bright_blue().bold());
            if t.deprecated {
                let note = match &t.revoked_by {
                    Some(r) => format!(
                        "Deprecated in ATT&CK — superseded by {}{}",
                        r,
                        names.get(r).map(|n| format!(" ({})", n)).unwrap_or_default()
                    ),
                    None => "Deprecated in ATT&CK — no direct replacement".to_string(),
                };
                println!("{}", note.red().bold());
            }
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