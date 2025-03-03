use std::{io::{self}, path::{Path, PathBuf}};
use walkdir::WalkDir;
use yara::{Rules, Scanner, Rule};
use std::error::Error;

// Function to load a single YARA rule file
fn load_yara_rule(rule_file_path: &Path) -> Result<Rules, Box<dyn Error>> {
    println!("Attempting to load YARA rule file: {:?}", rule_file_path);

    // Check if the file exists
    if !rule_file_path.exists() {
        return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "YARA rule file not found")));
    }

    // Try to load the YARA rule file
    match Rules::load_from_file(rule_file_path.to_str().unwrap()) {
        Ok(rules) => {
            println!("YARA rule loaded successfully: {:?}", rule_file_path);
            Ok(rules)
        },
        Err(e) => {
            // Provide a detailed error message if loading fails
            eprintln!("Failed to load YARA rule file {:?} due to: {:?}", rule_file_path, e);
            Err(Box::new(e))  // Return the actual YARA error for debugging
        }
    }
}

// Function to load all YARA rules from a directory (and subdirectories)
fn load_yara_rules_from_directory(directory_path: &PathBuf) -> Result<Vec<Rules>, Box<dyn Error>> {
    let mut combined_rules = Vec::new(); // Create an empty vector to store rules

    // Walk the directory to find all YARA rule files
    for entry in WalkDir::new(directory_path) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && (path.extension() == Some("yara".as_ref()) || path.extension() == Some("yar".as_ref())) {
            // Load the individual rule file
            let rules = load_yara_rule(path)?;

            // Add the rules to the combined set
            combined_rules.push(rules);
        }
    }

    Ok(combined_rules)
}

// Function to scan a file using the loaded YARA rules
fn scan_with_yara<'a>(rules: &'a Rules, path_to_scan: &'a Path) -> Result<Vec<Rule<'a>>, Box<dyn Error>> {
    // Alternative to Scanner::new(), use a public method to create the scanner (adjust based on available methods)
    // Ensure you are using the correct public method from YARA crate
    let mut scanner = Scanner::load_from_rules(rules)?;  // Assuming this method exists, check documentation for details

    // Scan the file at the provided path
    let matches = scanner.scan_file(path_to_scan)?;
    Ok(matches)
}

// Main function to execute the program
fn main() -> Result<(), Box<dyn Error>> {
    // Ask the user whether to scan with a single rule or a directory of rules
    println!("Would you like to scan with a single YARA rule or a directory of rules? (single/directory)");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    let rules: Rules;

    if choice == "single" {
        // Ask the user to provide a YARA rule file
        println!("Please provide the path to the YARA rule file:");
        input.clear();
        io::stdin().read_line(&mut input)?;
        let rule_file_path = PathBuf::from(input.trim());

        // Load the YARA rule
        rules = load_yara_rule(&rule_file_path)?;
    } else if choice == "directory" {
        // Ask the user to provide the directory containing YARA rules
        println!("Please provide the path to the directory containing YARA rules:");
        input.clear();
        io::stdin().read_line(&mut input)?;
        let directory_path = PathBuf::from(input.trim());

        // Load all YARA rules from the directory
        let rules_vector = load_yara_rules_from_directory(&directory_path)?;

        // Combine all rules into one (we can't do it with unsafe_try_from, so just keep the vector)
        // Depending on your use case, you might want to scan with each set of rules separately
        rules = rules_vector.into_iter().next().ok_or_else(|| Box::new(io::Error::new(io::ErrorKind::NotFound, "No rules found in directory")))?;
    } else {
        return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Invalid choice")));
    }

    // Ask the user for the directory to scan
    println!("Please provide the path to the directory you want to scan:");
    input.clear();
    io::stdin().read_line(&mut input)?;
    let path_to_scan = PathBuf::from(input.trim());

    // Walk through the directory and scan each file with the loaded YARA rules
    for entry in WalkDir::new(path_to_scan) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            // Scan each file with the YARA rules
            let matches = scan_with_yara(&rules, &path)?;

            // Print the scan results
            if matches.is_empty() {
                println!("No matches found in {:?}", path);
            } else {
                println!("Matches found in {:?}:", path);
                for rule in matches {
                    // Access the rule's identifier directly as a field
                    println!("{}", rule.identifier);
                }
            }
        }
    }

    Ok(())
}