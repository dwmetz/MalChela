use common_ui::styled_line;
use colored::*;

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
    println!("{}", styled_line("gray", "Version: 3.0.0"));
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

    let table_string = format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}{}",
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Combine YARA", "Point it at a directory of YARA files and it will output one combined rule"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Extract Samples", "Point it at a directory of password protected malware files to extract all"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "File Analyzer", "Get the hash, entropy, packing, PE info, YARA and VT match status for a file"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "File Miner", "Triages files based on magic byte mismatch and suggests follow-up tools for analysis"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "HashCheck", "Check a  hash table .txt or a .tsv lookup table for presence of a hash"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Hash It", "Point it to a file and get the MD5, SHA1 and SHA256 hash"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "mStrings", "Analyzes files with Sigma rules (YAML), extracts strings, matches ReGex."),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "MZHash", "Recurse a directory, for files with MZ header, create hash list"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "MZcount", "Recurse a directory, uses YARA to count MZ, Zip, PDF, other"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "NSRL Hash Lookup", "Query an MD5 or SHA1 hash against NSRL"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Strings to YARA", "Prompts for metadata and strings (text file) to create a YARA rule"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Malware Hash Lookup", "Query a hash value against VirusTotal & Malware Bazaar*"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "XMZHash", "Recurse a directory, for files without MZ, Zip or PDF header, create hash list"),

    );

    println!("{}", table_string);

    println!("{}", styled_line("yellow", ""));
    println!("{}", styled_line("yellow", "* The Malware Hash Lookup requires an API key for VirusTotal and Malware Bazaar. If unidentified,"));
    println!("{}", styled_line("yellow", "  MalChela will prompt you to create them the first time you run the malware lookup function."));
    println!("{}", styled_line("white", ""));
}
