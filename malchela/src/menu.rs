pub struct ToolEntry {
    pub shortcode: String,
    pub display_name: String,
    pub command_args: Vec<String>,
}

pub fn generate_tool_menu() -> Vec<ToolEntry> {
    use std::collections::HashMap;
    let mut tools = Vec::new();

    // Hardcoded map of display names to shortcodes
    let shortcode_map: HashMap<&str, &str> = [
        ("File Analyzer", "fa"),
        ("File Miner", "fm"),
        ("MStrings", "ms"),
        ("Hash It", "hi"),
        ("Hash Check", "hc"),
        ("MZCount", "mz"),
        ("MZHash", "mh"),
        ("XMZHash", "xh"),
        ("Combine YARA", "cy"),
        ("Strings to YARA", "sy"),
        ("Malware Hash Lookup", "mh"),
        ("NSRL Hash Lookup", "nh"),
        ("Extract Samples", "es"),
        ("About", "ab"),
    ].iter().cloned().collect();

    // Manually define the tools
    let entries = vec![
        ("File Analyzer", vec!["run", "--bin", "fileanalyzer"]),
        ("File Miner", vec!["run", "--bin", "fileminer"]),
        ("MStrings", vec!["run", "--bin", "mstrings"]),
        ("Hash It", vec!["run", "--bin", "hashit"]),
        ("Hash Check", vec!["run", "--bin", "hashcheck"]),
        ("MZCount", vec!["run", "--bin", "mzcount"]),
        ("MZHash", vec!["run", "--bin", "mzhash"]),
        ("XMZHash", vec!["run", "--bin", "xmzhash"]),
        ("Combine YARA", vec!["run", "--bin", "combine_yara"]),
        ("Strings to YARA", vec!["run", "--bin", "strings_to_yara"]),
        ("Malware Hash Lookup", vec!["run", "--bin", "malhash"]),
        ("NSRL Hash Lookup", vec!["run", "--bin", "nsrlquery"]),
        ("Extract Samples", vec!["run", "--bin", "extract_samples"]),
        ("About", vec!["run", "--bin", "about"]),
    ];

    for (display_name, command_args) in entries {
        let shortcode = shortcode_map
            .get(display_name)
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                display_name
                    .split_whitespace()
                    .filter_map(|word| word.chars().next())
                    .collect()
            });

        tools.push(ToolEntry {
            display_name: display_name.to_string(),
            shortcode,
            command_args: command_args.iter().map(|s| s.to_string()).collect(),
        });
    }

    tools
}
