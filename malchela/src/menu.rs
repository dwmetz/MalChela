pub type MenuItem = (String, Vec<String>); // (Display Text, Command and Args)
pub type MenuGroup = (String, Vec<MenuItem>);

pub fn grouped_menu() -> Vec<MenuGroup> {
    vec![
        (
            "File Analysis".to_string(),
            vec![
                ("  File Analyzer".to_string(), vec!["run".to_string(), "--bin".to_string(), "fileanalyzer".to_string()]),
                ("  MStrings".to_string(), vec!["run".to_string(), "--bin".to_string(), "mstrings".to_string()]),
                ("  Mismatch Miner".to_string(), vec!["run".to_string(), "--bin".to_string(), "mismatchminer".to_string()]),
            ],
        ),
        (
            "Hashing Tools".to_string(),
            vec![
                ("  Hash It".to_string(), vec!["run".to_string(), "--bin".to_string(), "hashit".to_string()]),
                ("  MZCount".to_string(), vec!["run".to_string(), "--bin".to_string(), "mzcount".to_string()]),
                ("  MZMD5".to_string(), vec!["run".to_string(), "--bin".to_string(), "mzmd5".to_string()]),
                ("  XMZMD5".to_string(), vec!["run".to_string(), "--bin".to_string(), "xmzmd5".to_string()]),
            ],
        ),
        (
            "YARA Tools".to_string(),
            vec![
                ("  Combine YARA".to_string(), vec!["run".to_string(), "--bin".to_string(), "combine_yara".to_string()]),
                ("  Strings to YARA".to_string(), vec!["run".to_string(), "--bin".to_string(), "strings_to_yara".to_string()]),
            ],
        ),
        (
            "Threat Intel".to_string(),
            vec![
                ("  Malware Hash Lookup".to_string(), vec!["run".to_string(), "--bin".to_string(), "malhash".to_string()]),
                ("  NSRL Hash Lookup".to_string(), vec!["run".to_string(), "--bin".to_string(), "nsrlquery".to_string()]),
            ],
        ),
        (
            "Utilities".to_string(),
            vec![
                ("  Extract Samples".to_string(), vec!["run".to_string(), "--bin".to_string(), "extract_samples".to_string()]),
                ("  About".to_string(), vec!["run".to_string(), "--bin".to_string(), "about".to_string()]),
            ],
        ),
    ]
}
