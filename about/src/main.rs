use colored::*;

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

            https://bakerstreetforensics.com                                                                                                                                  
"#
    ).red();

    println!("{}", crab_art);

    println!("{}", "MalChela - A YARA & Malware Analysis Toolkit written in Rust\n".yellow());
    println!("{}", "ABOUT:".green());
    println!("{}", "   mal — malware".white());
    println!("{}", "   chela — \"crab hand\"\n".white());
    println!("A chela on a crab is the scientific term for a claw or pincer. It’s a specialized appendage,");
    println!("typically found on the first pair of legs, used for grasping, defense, and manipulating things; ");
    println!("just like these programs.\n");

    println!("{}", "FEATURES:".green());

    let feature_width = 20; 
    let description_width = 70;

    let table_string = format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}{}",
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Combine YARA", "Point it at a directory of YARA files and it will output one combined rule"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Extract Samples", "Point it at a directory of password protected malware files to extract all"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "File Analyzer", "Get the hash, entropy, packing, PE info, YARA and VT match status for a file"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Hash It", "Point it to a file and get the MD5, SHA1 and SHA256 hash"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Mismatch Miner", "Analyzes a directory for exe files impersonating other file types (doc, png, etc)"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "MSTRINGS", "Analyzes files with Sigma rules (YAML), extracts strings, matches ReGex."),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "MZMD5", "Recurse a directory, for files with MZ header, create hash list"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "MZcount", "Recurse a directory, uses YARA to count MZ, Zip, PDF, other"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "NSRL MD5 Lookup", "Query an MD5 hash against NSRL"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "NSRL SHA1 Lookup", "Query a SHA1 hash against NSRL"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Strings to YARA", "Prompts for metadata and strings (text file) to create a YARA rule"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "Malware Hash Lookup", "Query a hash value against VirusTotal & Malware Bazaar*"),
        format!("  {:<feature_width$}|  {:<description_width$}\n", "XMZMD5", "Recurse a directory, for files without MZ, Zip or PDF header, create hash list"),
    );

    println!("{}", table_string);

    println!("{}", "\n".yellow());
    println!("{}", "* The Malware Hash Lookup requires an API key for VirusTotal and Malware Bazaar. If unidentified,".yellow());
    println!("{}", "  MalChela will prompt you to create them the first time you run the malware lookup function.".yellow());
    println!("{}", "\n".white());
}


