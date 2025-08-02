pub struct ToolEntry {
    pub shortcode: String,
    pub display_name: String,
    pub binary_path: String,
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
        ("MITRE Lookup", "ml"),
    ].iter().cloned().collect();

    let entries = vec![
        ("About", "about"),
        ("Combine YARA", "combine_yara"),
        ("Extract Samples", "extract_samples"),
        ("File Analyzer", "fileanalyzer"),
        ("File Miner", "fileminer"),
        ("Hash Check", "hashcheck"),
        ("Hash It", "hashit"),
        ("Malware Hash Lookup", "malhash"),
        ("MITRE Lookup", "MITRE_lookup"),
        ("MStrings", "mstrings"),
        ("MZCount", "mzcount"),
        ("MZHash", "mzhash"),
        ("NSRL Hash Lookup", "nsrlquery"),
        ("Strings to YARA", "strings_to_yara"),
        ("XMZHash", "xmzhash"),
    ];

    for (display_name, binary_name) in entries {
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
            binary_path: format!("{}/../target/release/{}", env!("CARGO_MANIFEST_DIR"), binary_name),
        });


    }

    tools
}
