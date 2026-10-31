use common_ui::styled_line;
use colored::*;

/// Every tool, alphabetically. tests::every_tool_is_listed fails the build's
/// tests when a tool in tools.yaml (or MITRE Lookup, which is not in it) is
/// missing here.
const FEATURES: &[(&str, &str)] = &[
    ("Analyze", "Point it at a file, folder, or bundle and it auto-runs every tool FileMiner suggests, plus a combined rollup report"),
    ("Code Sign Check", "Inspects macOS code signing: signature type, team ID, entitlements, ad-hoc detection"),
    ("Combine YARA", "Point it at a directory of YARA files and it will output one combined rule"),
    ("dpp Extract", "Unwraps .dmg and .pkg installers (and nested containers) so their contents can be analyzed"),
    ("Extract Samples", "Point it at a directory of password protected malware files to extract all"),
    ("File Analyzer", "Get the hash, entropy, packing, PE info, YARA and VT match status for a file"),
    ("File Miner", "Triages files based on magic byte mismatch and suggests follow-up tools for analysis"),
    ("Hash It", "Point it to a file and get the MD5, SHA1 and SHA256 hash"),
    ("HashCheck", "Check a hash table .txt or a .tsv lookup table for presence of a hash"),
    ("Mach-O Info", "Parses Mach-O binaries: architecture, linked libs, sections with entropy, symbols"),
    ("MITRE Lookup", "Look up an ATT&CK technique, sub-technique, or tactic (v20): description, detections, mitigations"),
    ("mStrings", "Analyzes files with Sigma rules (YAML), extracts strings, matches ReGex."),
    ("MZcount", "Recurse a directory, uses YARA to count MZ, Zip, PDF, other"),
    ("MZHash", "Recurse a directory, for files with MZ header, create hash list"),
    ("NSRL Hash Lookup", "Query an MD5 or SHA1 hash against NSRL"),
    ("Plist Analyzer", "Parses macOS .plist files and .app bundles for malware indicators"),
    ("Strings to YARA", "Prompts for metadata and strings (text file) to create a YARA rule"),
    ("Threat Intel Query", "Multi-source hash, IP, URL and QR code lookup (VT, MB, OTX, GreyNoise, urlscan.io, GSB, +more)"),
    ("Unpack", "Static packer detection and unpacking (UPX, PyInstaller, .NET, NSIS, Inno, fat Mach-O, obfuscated .pyc); never executes the sample"),
    ("XMZHash", "Recurse a directory, for files without MZ, Zip or PDF header, create hash list"),
    ("YARA Scan", "Scan a file or folder with YARA rules on the embedded YARA-X engine; flags follow yr scan"),
];

fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok()
}

fn main() {
    let crab_art = format!(
        "{}",
        r#"
                                                                                    
                                                                                        
                ▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒                                
              ▒▒▒▒▒▒                ▒▒▒▒▒▒                              
              ▒▒▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒▒▒▒▒▒▒            ▒▒▒▒▒▒▒▒▒▒                            
            ▒▒▒▒      ██        ██      ▒▒▒▒                            
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
            ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                            
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
                ▒▒▒▒    ▒▒▒▒▒▒▒▒    ▒▒▒▒                                                                                                                                                               
"#
    ).red();

    if is_gui_mode() {
        for line in crab_art.lines() {
            println!("[CRAB]{}", line);
        }
    } else {
        println!("{}", crab_art);
    }

    println!("{}", styled_line("gray", "            https://bakerstreetforensics.com"));
    println!();
    println!("{}", styled_line("rust", "MalChela - A YARA & Malware Analysis Toolkit written in Rust"));
    println!("{}", styled_line("gray", &format!("Version: {}", env!("CARGO_PKG_VERSION"))));
    println!();
    println!("{}", styled_line("ABOUT", "ABOUT:"));
    println!("{}", styled_line("yellow", "   mal — malware"));
    println!("{}", styled_line("yellow", "   chela — \"crab hand\""));
    println!();
    println!("A chela on a crab is the scientific term for a claw or pincer. It’s a specialized appendage,");
    println!("typically found on the first pair of legs, used for grasping, defense, and manipulating things; ");
    println!("just like these programs.\n");

    println!("{}", styled_line("FEATURES", "FEATURES:"));

    let feature_width = 20;
    let description_width = 70;
    let mut table_string = String::new();
    for (name, description) in FEATURES {
        table_string.push_str(&format!("  {:<feature_width$}|  {:<description_width$}\n", name, description));
    }
    println!("{}", table_string);

    println!("{}", styled_line("yellow", ""));
    println!("{}", styled_line("yellow", "* Threat Intel Query requires API keys for some sources."));
    println!("{}", styled_line("yellow", "  MalChela will prompt you to create them the first time you run the tool."));
    println!("{}", styled_line("white", ""));
}

#[cfg(test)]
mod tests {
    use super::FEATURES;

    fn norm(s: &str) -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
    }

    #[test]
    fn every_tool_is_listed() {
        let yaml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../tools.yaml")).expect("tools.yaml");
        let listed: Vec<String> = FEATURES.iter().map(|(n, _)| norm(n)).collect();
        let mut names: Vec<String> = yaml
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("- name:"))
            .map(|n| n.trim().trim_matches('"').trim_matches('\'').to_string())
            .collect();
        names.push("MITRE Lookup".into()); // a PWA panel and CLI, not in tools.yaml
        let missing: Vec<&String> = names.iter().filter(|n| !listed.contains(&norm(n))).collect();
        assert!(missing.is_empty(), "tools missing from About: {:?}", missing);
    }

    #[test]
    fn alphabetical() {
        let names: Vec<String> = FEATURES.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
