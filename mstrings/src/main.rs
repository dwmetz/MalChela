// Helper to determine if we're in true GUI mode (not workspace panel)
fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok() && std::env::var("MALCHELA_WORKSPACE_MODE").is_err()
}
use std::fs::File;
use std::io::{self, BufReader, Write, Read};

use sha2::{Sha256, Digest};

use common_ui::styled_line;

use common_config::get_output_dir;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clap::{Arg, ArgMatches, Command};
use fancy_regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use colored::*;
use tabled::{Table as TabledTable, Tabled};
use tabled::settings::{Style, Modify, Alignment, Width};



// Define a Rust Orange color helper for colored crate
const RUST_ORANGE: (u8, u8, u8) = (215, 100, 40); // Use this constant for color

// Function to handle printing IOCs (unified CLI/GUI logic and formatting)
fn print_iocs(title: &str, iocs: &std::collections::BTreeSet<String>) {
    if !iocs.is_empty() {
        println!("{}", title.truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));
        for ioc in iocs {
            println!("{}", ioc);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
enum Encoding {
    Ascii,
    Utf8,
    Base64,
}

#[derive(Debug, serde::Serialize)]
struct Match {
    offset: usize,
    encoding: Encoding,
    matched_str: String,
    rule_name: Option<String>,
    tactic: Option<String>,
    technique: Option<String>,
    technique_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Detection {
    title: String,
    detection: DetectionStrings,
    mitre: Vec<MitreMapping>,
}

#[derive(Debug, Deserialize)]
struct DetectionStrings {
    strings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MitreMapping {
    technique_id: String,
    technique_name: String,
    tactics: Vec<String>,
}

// Helper function to truncate strings over a given length
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

// Neutralize characters that corrupt the report tables' structure before a
// matched string goes into a table cell. Two distinct failure modes, both
// from the same missing sanitization: an embedded newline (routine for a
// match pulled from base64-decoded multi-line content, e.g. a decoded
// script) renders as literal `\n` bytes inside the cell, which — parsed as
// markdown — starts what looks like a new table row with blank leading
// columns; an embedded `|` (routine in any matched shell command using a
// pipe, e.g. `curl ... | grep ...`) IS the markdown table's own column
// delimiter, so it splits the cell in two and shifts every column after it
// one to the right — the concrete symptom that surfaced this: a
// grep pattern showing up as if it were a MITRE tactic name.
fn sanitize_table_cell(s: &str) -> String {
    s.replace(['\r', '\n', '\t'], " ").replace('|', "\\|")
}

// Filter high-volume ObjC/Swift runtime noise that appears in every Mach-O binary.
// These strings are never meaningful IOCs and would swamp detection output.
fn is_objc_swift_noise(s: &str) -> bool {
    let t = s.trim();
    // ObjC runtime stubs and imported symbol stubs (appear hundreds of times per binary)
    if t.starts_with("_objc_") || t.starts_with("objc_") || t.starts_with("@_") {
        return true;
    }
    // Swift mangled symbol prefixes
    if t.starts_with("_$s") || t.starts_with("_$S") || t.starts_with("swift_") || t.starts_with("_T0") {
        return true;
    }
    // Apple system dylib paths — present in every Mac binary's import table
    if t.starts_with("/System/Library/Frameworks/")
        || t.starts_with("/System/Library/PrivateFrameworks/")
        || t.starts_with("/usr/lib/libobjc")
        || t.starts_with("/usr/lib/swift/")
        || t.starts_with("/usr/lib/libc++")
        || t.starts_with("/usr/lib/libSystem")
    {
        return true;
    }
    // ObjC type encoding strings (e.g. "v8@0:8", "@@:") — short, only ObjC type chars
    if t.len() < 16 && t.chars().all(|c| "@:^v#BiILlqQfdCSsDTtBrnoO*{}0123456789".contains(c)) {
        return true;
    }
    false
}

struct Mstrings {
    matches: Vec<Match>,
}

impl Mstrings {
    pub fn new() -> Self {
        Self { matches: Vec::new() }
    }

    pub fn process_line(&mut self, line: &str, offset: usize) {
        if !line.trim().is_empty() && !is_objc_swift_noise(line) {
            let encoding_type = if std::str::from_utf8(line.as_bytes()).is_ok() {
                Encoding::Utf8
            } else {
                Encoding::Ascii
            };

            self.matches.push(Match {
                offset,
                encoding: encoding_type,
                matched_str: line.trim_start().to_string(),
                rule_name: None,
                tactic: None,
                technique: None,
                technique_id: None,
            });
        }
    }

    /// Detect long base64-looking substrings anywhere within an extracted
    /// string, decode them, and add the decoded text as new matches
    /// (encoding: Base64) so the existing detection and IOC-extraction
    /// passes run against what's actually inside — not just the encoded
    /// blob itself. Malware embedding a full script/payload as base64 is
    /// otherwise invisible to every string-matching rule, since none of its
    /// real content exists as a literal substring anywhere in the binary
    /// pre-decode. Two shapes observed in the wild, both handled by
    /// searching for the base64 run rather than requiring the whole
    /// extracted string to be one: a blob as its own isolated string
    /// constant (a 2,514-line Python RAT decoded from one 149KB base64
    /// string in a Dok/Bella sample), and a blob embedded inline in a
    /// larger command line (`echo <blob> | base64 -d | python`, an EmPyre-
    /// style shell stager, where the whole line — not just the blob — is
    /// what gets extracted as one string).
    ///
    /// Decoding is recursive, up to MAX_LAYERS: an XCSSET shell-script
    /// dropper was found nesting the same encoding 8 times — a single
    /// decode pass just produces another base64-shaped string each time,
    /// so anything short of peeling every layer never reaches the real
    /// payload (in that sample: an AppleScript module with a hardcoded C2
    /// domain, a beacon format, and download-and-osascript-exec logic).
    /// Each layer is only accepted as the final result once decoding
    /// stops producing something that itself still looks like base64 —
    /// hitting MAX_LAYERS while still base64-shaped, or a failed decode
    /// partway through, discards the candidate rather than emitting a
    /// still-encoded intermediate layer as if it were the real payload.
    fn decode_base64_blobs(&mut self) {
        const MIN_LEN: usize = 60;
        const MIN_DECODED_LEN: usize = 20;
        const MIN_PRINTABLE_RATIO: f64 = 0.85;
        const MAX_LAYERS: usize = 12;

        fn is_base64_shaped(s: &str) -> bool {
            s.len() >= MIN_LEN
                && s.len() % 4 == 0
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                && s.chars().any(|c| c.is_ascii_alphabetic())
        }

        let base64_run = Regex::new(&format!(r"[A-Za-z0-9+/]{{{MIN_LEN},}}={{0,2}}")).unwrap();

        let candidates: Vec<(usize, String)> = self
            .matches
            .iter()
            .flat_map(|m| {
                base64_run
                    .find_iter(&m.matched_str)
                    .flatten()
                    .filter(|mat| is_base64_shaped(mat.as_str()))
                    .map(|mat| (m.offset, mat.as_str().to_string()))
                    .collect::<Vec<_>>()
            })
            .collect();

        let mut decoded_matches = Vec::new();
        for (offset, candidate) in candidates {
            let mut current = candidate;
            let mut terminal: Option<Vec<u8>> = None;

            for _ in 0..MAX_LAYERS {
                let decoded = match BASE64_STANDARD.decode(current.trim()) {
                    Ok(d) if d.len() >= MIN_DECODED_LEN => d,
                    _ => break, // invalid/too-short at this layer — abandon this candidate
                };
                match std::str::from_utf8(&decoded) {
                    Ok(s) if is_base64_shaped(s.trim()) => {
                        current = s.trim().to_string();
                        continue; // still encoded — peel another layer
                    }
                    _ => {
                        terminal = Some(decoded); // reached the real payload (text or binary)
                        break;
                    }
                }
            }

            let Some(decoded) = terminal else { continue };
            let printable = decoded
                .iter()
                .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
                .count();
            if (printable as f64 / decoded.len() as f64) < MIN_PRINTABLE_RATIO {
                continue;
            }
            decoded_matches.push(Match {
                offset,
                encoding: Encoding::Base64,
                matched_str: String::from_utf8_lossy(&decoded).to_string(),
                rule_name: None,
                tactic: None,
                technique: None,
                technique_id: None,
            });
        }
        self.matches.extend(decoded_matches);
    }

    pub fn apply_yara_detections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let yaml_content = std::fs::read_to_string("detections.yaml")?;
        let raw_rules: HashMap<String, Detection> = serde_yaml::from_str(&yaml_content)?;

        let mut compiled_rules = Vec::new();
        for (_key, det) in &raw_rules {
            for pattern in &det.detection.strings {
                if let Ok(regex) = Regex::new(pattern) {
                    for mitre in &det.mitre {
                        compiled_rules.push((
                            regex.clone(),
                            det.title.clone(),
                            mitre.tactics.join(", "),
                            mitre.technique_name.clone(),
                            mitre.technique_id.clone(),
                        ));
                    }
                }
            }
        }

        let mut new_matches: Vec<Match> = Vec::new();
        for m in &self.matches {
            let mut any_match = false;
            let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();
            for (regex, rule_name, tactic, technique, technique_id) in &compiled_rules {
                if regex.is_match(&m.matched_str).unwrap_or(false) && seen_rules.insert(rule_name.clone()) {
                    new_matches.push(Match {
                        offset: m.offset,
                        encoding: m.encoding.clone(),
                        matched_str: m.matched_str.clone(),
                        rule_name: Some(rule_name.clone()),
                        tactic: Some(tactic.clone()),
                        technique: Some(technique.clone()),
                        technique_id: Some(technique_id.clone()),
                    });
                    any_match = true;
                }
            }
            if !any_match {
                new_matches.push(Match {
                    offset: m.offset,
                    encoding: m.encoding.clone(),
                    matched_str: m.matched_str.clone(),
                    rule_name: None,
                    tactic: None,
                    technique: None,
                    technique_id: None,
                });
            }
        }
        self.matches = new_matches;

        Ok(())
    }
}


#[derive(Tabled)]
struct FlatMatch {
    #[tabled(rename = "Offset")]
    offset: String,
    #[tabled(rename = "Enc")]
    encoding: String,
    #[tabled(rename = "Match")]
    matched_str: String,
    #[tabled(rename = "Rule")]
    rule_name: String,
    #[tabled(rename = "Tactic")]
    tactic: String,
    #[tabled(rename = "Technique")]
    technique: String,
    #[tabled(rename = "ID")]
    technique_id: String,
}

#[derive(Tabled)]
struct DisplayMatch {
    #[tabled(rename = "Count")]
    count: String,
    #[tabled(rename = "Rule")]
    rule_name: String,
    #[tabled(rename = "Matched Strings")]
    matched_strings: String,
    #[tabled(rename = "Tactic")]
    tactic: String,
    #[tabled(rename = "Technique")]
    technique: String,
    #[tabled(rename = "ID")]
    technique_id: String,
}

fn tactic_priority(tactic: &str) -> u8 {
    let t = tactic.to_lowercase();
    if t.contains("impact")                { 0 }
    else if t.contains("collection")      { 1 }
    else if t.contains("command and control") { 2 }
    else if t.contains("exfiltration")    { 3 }
    else if t.contains("execution")       { 4 }
    else if t.contains("persistence")     { 5 }
    else if t.contains("privilege escalation") { 6 }
    else if t.contains("credential")      { 7 }
    else if t.contains("lateral movement") { 8 }
    else if t.contains("defense evasion") { 9 }
    else if t.contains("discovery")       { 10 }
    else if t.contains("resource development") { 11 }
    else { 12 }
}

// ── Per-file scan result ──────────────────────────────────────────────────────
struct FileScanResult {
    file_path: String,
    sha256: String,
    raw_match_count: usize,
    display_matches: Vec<DisplayMatch>,
    flat_matches: Vec<FlatMatch>,
    fs_iocs: BTreeSet<String>,
    net_iocs: BTreeSet<String>,
    matches: Vec<Match>,
}

// Scan a single file: read bytes, hash, extract strings, apply detections,
// build the grouped/flat match views and extract filesystem/network IOCs.
fn scan_file(path: &Path) -> Result<FileScanResult, Box<dyn std::error::Error>> {
    let mut fs_iocs = BTreeSet::new();
    let mut net_iocs = BTreeSet::new();

    let file = File::open(path)?;
    let mut mstrings = Mstrings::new();
    let mut buffer = Vec::new();
    BufReader::new(file).read_to_end(&mut buffer)?;

    // Calculate SHA256 hash of the file buffer
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let sha256 = format!("{:x}", hasher.finalize());

    let mut current = Vec::new();
    let mut string_start: usize = 0;
    for (i, &byte) in buffer.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            if current.is_empty() {
                string_start = i;
            }
            current.push(byte);
        } else if current.len() >= 4 {
            if let Ok(s) = String::from_utf8(current.clone()) {
                mstrings.process_line(&s, string_start);
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current.clone()) {
            mstrings.process_line(&s, string_start);
        }
    }

    mstrings.decode_base64_blobs();
    mstrings.apply_yara_detections()?;

    // Group matched strings by rule name; track tactic/technique for sort.
    // Use BTreeSet per group to deduplicate strings that appear at multiple offsets.
    let raw_match_count = mstrings.matches.iter().filter(|m| m.rule_name.is_some()).count();

    let mut rule_groups: std::collections::HashMap<
        String,
        (String, String, String, std::collections::BTreeSet<String>),
    > = std::collections::HashMap::new();

    for m in mstrings.matches.iter().filter(|m| m.rule_name.is_some()) {
        let rule = m.rule_name.as_ref().unwrap().clone();
        let entry = rule_groups.entry(rule).or_insert_with(|| (
            m.tactic.clone().unwrap_or_default(),
            m.technique.clone().unwrap_or_default(),
            m.technique_id.clone().unwrap_or_default(),
            std::collections::BTreeSet::new(),
        ));
        entry.3.insert(m.matched_str.clone());
    }

    // Sort groups: primary = tactic priority, secondary = rule name
    let mut sorted_groups: Vec<(String, String, String, String, Vec<String>)> = rule_groups
        .into_iter()
        .map(|(rule, (tactic, technique, id, strings))| {
            (rule, tactic, technique, id, strings.into_iter().collect())
        })
        .collect();
    sorted_groups.sort_by(|a, b| {
        tactic_priority(&a.1).cmp(&tactic_priority(&b.1)).then(a.0.cmp(&b.0))
    });

    let display_matches: Vec<DisplayMatch> = sorted_groups
        .iter()
        .map(|(rule, tactic, technique, id, strings)| {
            let count = strings.len();
            let matched_strings = {
                let cap = 8;
                let shown: Vec<String> = strings
                    .iter()
                    .take(cap)
                    .map(|s| truncate_string(&sanitize_table_cell(s), 50))
                    .collect();
                if count > cap {
                    format!("{} (+{} more)", shown.join(", "), count - cap)
                } else {
                    shown.join(", ")
                }
            };
            DisplayMatch {
                count: count.to_string(),
                rule_name: rule.clone(),
                matched_strings,
                tactic: tactic.clone(),
                technique: technique.clone(),
                technique_id: id.clone(),
            }
        })
        .collect();

    // Pre-compile IOC extraction regexes once, outside the loop.
    //
    // Go binaries store their entire runtime error-message table as one
    // continuous null-free UTF-8 blob in .rodata; the strings extractor
    // emits the whole thing as a single matched_str.  For blobs (len > 300)
    // we use targeted regexes to pull only well-formed patterns out of the
    // blob rather than classifying the whole string.
    // Short strings use the original logic unchanged.
    //
    // \x22 is used in char classes instead of \" to avoid raw-string issues.
    // IP boundary validation is done in Rust after matching (kept this way
    // even after the fancy-regex migration added lookaround support — a
    // manual byte check is simpler to read here than a lookaround, and
    // faster since it skips backtracking on every candidate match).
    let re_url      = Regex::new(r"https?://[^\s\x22'<>]{8,}").unwrap();
    let re_ip       = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
    // Windows-style paths
    let re_fspath   = Regex::new(r"(?i)(?:%\w+%|\\|\$\{[^}]+\})[^\s\x22'<>]*\.(?:exe|bat|ps1|vbs|pdb|dll|txt|zip|lnk)").unwrap();
    // macOS-style paths: /Users/…, ~/Library/…, /Library/…, /private/var/…, /tmp/…
    let re_mac_path = Regex::new(r"(?:~|/Users/[^/\s]+|/Library|/private/var|/tmp)/[^\s\x22'<>]*\.(?:sh|py|dylib|plist|app|pkg|command)").unwrap();

    for m in &mstrings.matches {
        if let Some(rule) = &m.rule_name {
            let _s = m.matched_str.to_lowercase();

            if m.matched_str.len() > 300 {
                // Blob path: extract well-formed IOCs via regex
                for cap in re_url.find_iter(&m.matched_str).flatten() {
                    net_iocs.insert(cap.as_str().to_string());
                }
                // IP boundary check: regex crate has no lookarounds, so verify
                // surrounding bytes manually.  127.0.0.1 is omitted — it appears
                // in every Go net-stack binary and has no analytical value.
                // RFC 1918 ranges are kept: a private IP hardcoded in malware
                // strings is a meaningful tell (lateral movement target, lab
                // infrastructure leak, etc.).
                let blob = m.matched_str.as_bytes();
                for mat in re_ip.find_iter(&m.matched_str).flatten() {
                    let start = mat.start();
                    let end   = mat.end();
                    let before_ok = start == 0 || !matches!(blob[start - 1], b'0'..=b'9' | b'.');
                    let after_ok  = end == blob.len() || !matches!(blob[end], b'0'..=b'9' | b'.');
                    if before_ok && after_ok && mat.as_str() != "127.0.0.1" {
                        net_iocs.insert(mat.as_str().to_string());
                    }
                }
                for cap in re_fspath.find_iter(&m.matched_str).flatten() {
                    let extracted = cap.as_str();
                    // Skip template variables like ${EXTENSION}-FILES.txt
                    if !extracted.starts_with("${") && !extracted.starts_with('%') {
                        fs_iocs.insert(extracted.to_string());
                    }
                }
                for cap in re_mac_path.find_iter(&m.matched_str).flatten() {
                    fs_iocs.insert(cap.as_str().to_string());
                }
            } else {
                // Normal path: short discrete string.
                // Normalize key=value pairs — take only the value after '='.
                let candidate: &str = if let Some(pos) = m.matched_str.find('=') {
                    m.matched_str[pos + 1..].trim()
                } else {
                    m.matched_str.trim()
                };
                let sc = candidate.to_lowercase();

                // Quality filters: skip template vars, multi-word command strings,
                // and Rust/C++ namespace-polluted matches — none are usable file IOCs.
                let is_template  = candidate.starts_with("${") || candidate.starts_with('%');
                let has_spaces   = candidate.contains(' ') || candidate.contains('\t');
                let has_namespace = candidate.contains("::");

                if !is_template && !has_spaces && !has_namespace {
                    let rule_lc = rule.to_lowercase();
                    let is_mac_path = sc.starts_with("/users/")
                        || sc.starts_with("/library/")
                        || sc.starts_with("~/library/")
                        || sc.starts_with("/private/")
                        || sc.starts_with("/tmp/");
                    let is_mac_ext = sc.ends_with(".sh")
                        || sc.ends_with(".dylib")
                        || sc.ends_with(".pkg")
                        || sc.ends_with(".command")
                        || sc.ends_with(".plist");

                    if rule_lc.contains("filesystem")
                        || sc.ends_with(".exe")
                        || sc.ends_with(".bat")
                        || sc.ends_with(".ps1")
                        || sc.ends_with(".vbs")
                        || sc.ends_with(".pdb")
                        || is_mac_ext
                        || is_mac_path
                    {
                        fs_iocs.insert(candidate.to_string());
                    } else if rule_lc.contains("ip address")
                        || sc.contains("http:")
                        || sc.contains("https:")
                        || (sc.contains('.') && sc.split('.').count() == 4)
                    {
                        net_iocs.insert(candidate.to_string());
                    }
                }
            }
        }
    }

    // Detail section: flat per-string table for drill-down (parsed by PWA toggle)
    let flat_matches: Vec<FlatMatch> = mstrings.matches.iter()
        .filter(|m| m.rule_name.is_some())
        .map(|m| FlatMatch {
            offset:       format!("0x{:08X}", m.offset),
            encoding:     format!("{:?}", m.encoding),
            matched_str:  truncate_string(&m.matched_str, 60),
            rule_name:    m.rule_name.clone().unwrap_or_default(),
            tactic:       m.tactic.clone().unwrap_or_default(),
            technique:    m.technique.clone().unwrap_or_default(),
            technique_id: m.technique_id.clone().unwrap_or_default(),
        })
        .collect();

    Ok(FileScanResult {
        file_path: path.display().to_string(),
        sha256,
        raw_match_count,
        display_matches,
        flat_matches,
        fs_iocs,
        net_iocs,
        matches: mstrings.matches,
    })
}

// ── Console printing helpers ──────────────────────────────────────────────────
fn print_summary(file_path: &str, sha256: &str, raw_match_count: usize, rule_count: usize) {
    if !is_gui_mode() {
        println!("{}", styled_line("stone", &format!("File: {}", file_path)));
        println!("{}", styled_line("stone", &format!("SHA256: {}", sha256)));
        println!("\n{}\n", format!("{} matches across {} rules.", raw_match_count, rule_count).truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));
    } else {
        println!("{}", styled_line("stone", &format!("File: {}", file_path)));
        println!("{}", styled_line("stone", &format!("SHA256: {}", sha256)));
        println!("\n{} matches across {} rules.\n", raw_match_count, rule_count);
    }
}

fn render_display_table(display_matches: &[DisplayMatch]) -> String {
    use tabled::settings::object::Columns;
    let mut table = TabledTable::new(display_matches);
    table
        .with(Style::modern())
        .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
        .with(Modify::new(Columns::single(0)).with(Width::wrap(5).keep_words(true)))   // Count
        .with(Modify::new(Columns::single(1)).with(Width::wrap(30).keep_words(true)))  // Rule
        .with(Modify::new(Columns::single(2)).with(Width::wrap(45).keep_words(true)))  // Matched Strings
        .with(Modify::new(Columns::single(3)).with(Width::wrap(18).keep_words(true)))  // Tactic
        .with(Modify::new(Columns::single(4)).with(Width::wrap(25).keep_words(true)))  // Technique
        .with(Modify::new(Columns::single(5)).with(Width::wrap(10).keep_words(true))); // ID
    table.to_string()
}

fn print_display_table(table_str: &str) {
    // Ensure the table is printed
    if !is_gui_mode() {
        let mut lines = table_str.lines();
        if let Some(top_border) = lines.next() {
            println!("{}", top_border);
            if let Some(header_row) = lines.next() {
                println!("{}", header_row);
            }
            if let Some(header_border) = lines.next() {
                println!("{}", header_border);
            }
            for line in lines {
                println!("{}", line);
            }
        } else {
            println!("{table_str}");
        }
    } else {
        // For GUI mode, print the table directly
        println!("{table_str}");
        // Handle clicking on "Open TXXXX" buttons (pseudo-code for illustration)
        // In actual GUI, you would have event/callback handling here.
        // For demonstration, if this were a GUI event loop, you might do:
        /*
        use open;
        // Suppose 'row_clicked' is the index of the clicked row
        if let Some(row_clicked) = get_clicked_row_index() {
            if let Some(dm) = display_matches.get(row_clicked) {
                if dm.mitre_button.starts_with("Open ") {
                    if let Some(url) = dm.mitre_url() {
                        let _ = open::that(url);
                    }
                }
            }
        }
        */
    }
}

fn print_detail(flat_matches: &[FlatMatch]) {
    use tabled::settings::object::Columns;
    if !flat_matches.is_empty() {
        println!("---DETAIL---");
        let mut flat_table = TabledTable::new(flat_matches);
        flat_table
            .with(Style::modern())
            .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
            .with(Modify::new(Columns::single(3)).with(Width::wrap(25).keep_words(true)))
            .with(Modify::new(Columns::single(4)).with(Width::wrap(18).keep_words(true)))
            .with(Modify::new(Columns::single(5)).with(Width::wrap(25).keep_words(true)))
            .with(Modify::new(Columns::single(2)).with(Width::wrap(30).keep_words(true)));
        println!("{}", flat_table.to_string());
    }
}

// ── Report-saving helpers ─────────────────────────────────────────────────────
fn resolve_output_dir(matches: &ArgMatches) -> std::path::PathBuf {
    match matches.get_one::<String>("case") {
        Some(case_name) => {
            common_config::ensure_case_json(case_name);
            get_output_dir("cases").join(case_name).join("mstrings")
        }
        None => get_output_dir("mstrings"),
    }
}

fn selected_format(matches: &ArgMatches) -> &'static str {
    if matches.get_flag("text") {
        "txt"
    } else if matches.get_flag("json") {
        "json"
    } else if matches.get_flag("markdown") {
        "md"
    } else {
        "md"
    }
}

fn write_report(
    output_dir: &std::path::Path,
    format: &str,
    custom_name: Option<&str>,
    contents: &str,
    matches: &ArgMatches,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let out_path = match format {
        "txt" => {
            let text_path = output_dir.join(custom_name.unwrap_or(&format!("report_{}.txt", timestamp)));
            if let Some(parent) = text_path.parent() {
                std::fs::create_dir_all(parent).expect("Failed to create output directory");
            }
            let mut file = File::create(&text_path).expect("Failed to save text report");
            file.write_all(contents.as_bytes()).expect("Failed to write report");
            println!("\n{}\n", format!("Text report saved to: {}", text_path.display()).green());
            text_path
        }
        "md" => {
            let md_path = output_dir.join(custom_name.unwrap_or(&format!("report_{}.md", timestamp)));
            if let Some(parent) = md_path.parent() {
                std::fs::create_dir_all(parent).expect("Failed to create output directory");
            }
            let mut file = File::create(&md_path).expect("Failed to save markdown report");
            file.write_all(contents.as_bytes()).expect("Failed to write report");
            println!("\n{}\n", format!("Markdown report saved to: {}", md_path.display()).green());
            md_path
        }
        _ => {
            let json_path = output_dir.join(custom_name.unwrap_or(&format!("report_{}.json", timestamp)));
            if let Some(parent) = json_path.parent() {
                std::fs::create_dir_all(parent).expect("Failed to create output directory");
            }
            let mut file = File::create(&json_path).expect("Failed to create JSON report file");
            file.write_all(contents.as_bytes()).expect("Failed to write JSON report");
            println!("\n{}\n", format!("JSON report saved to: {}", json_path.display()).green());
            json_path
        }
    };

    if let Some(case_name) = matches.get_one::<String>("case") {
        common_config::register_case_output("mstrings", case_name, target, &out_path);
    }

    Ok(())
}

// Build the txt/md report body for one scanned file (single-file layout).
// `with_title` controls the top-level markdown title — the bundle report emits
// its own title once and per-binary headings instead.
fn build_file_report_body(result: &FileScanResult, table_str: &str, format: &str, with_title: bool) -> String {
    let mut report_buffer = String::new();

    // Add file and hash metadata at the top of the report
    if format == "md" {
        if with_title {
            report_buffer.push_str("# mStrings Analysis Report\n\n");
        }
        report_buffer.push_str(&format!("**File:** `{}`  \n", result.file_path));
        report_buffer.push_str(&format!("**SHA256:** `{}`  \n", result.sha256));
        report_buffer.push_str(&format!(
            "**Detections:** {} matches across {} rules  \n\n",
            result.raw_match_count,
            result.display_matches.len()
        ));
    } else {
        report_buffer.push_str(&format!("File: {}\n", result.file_path));
        report_buffer.push_str(&format!("SHA256: {}\n\n", result.sha256));
    }

    // Add summary for non-md
    if format != "md" {
        report_buffer.push_str(&format!(
            "{} matches across {} rules.\n\n",
            result.raw_match_count,
            result.display_matches.len()
        ));
    }

    // Add table content
    if format == "txt" {
        report_buffer.push_str(&format!("{}\n\n", table_str));
    } else if format == "md" {
        use tabled::settings::object::Columns;
        let mut md_table = TabledTable::new(&result.display_matches);
        md_table
            .with(Style::markdown())
            .with(Modify::new(Columns::new(0..)).with(Alignment::left()));
        report_buffer.push_str(if with_title { "## Detections\n\n" } else { "### Detections\n\n" });
        report_buffer.push_str(&format!("{}\n\n", md_table.to_string()));
    }

    report_buffer
}

// Append IOC sections to a txt/md report buffer.
fn append_ioc_sections(
    report_buffer: &mut String,
    fs_iocs: &BTreeSet<String>,
    net_iocs: &BTreeSet<String>,
    format: &str,
) {
    if !fs_iocs.is_empty() {
        if format == "md" {
            report_buffer.push_str("## Potential Filesystem IOCs\n\n");
            for ioc in fs_iocs {
                report_buffer.push_str(&format!("- `{}`\n", ioc));
            }
        } else {
            report_buffer.push_str("POTENTIAL FILESYSTEM IOCs:\n");
            for ioc in fs_iocs {
                report_buffer.push_str(&format!("{}\n", ioc));
            }
        }
        report_buffer.push('\n');
    }

    if !net_iocs.is_empty() {
        if format == "md" {
            report_buffer.push_str("## Potential Network IOCs\n\n");
            for ioc in net_iocs {
                report_buffer.push_str(&format!("- `{}`\n", ioc));
            }
        } else {
            report_buffer.push_str("POTENTIAL NETWORK IOCs:\n");
            for ioc in net_iocs {
                report_buffer.push_str(&format!("{}\n", ioc));
            }
        }
        report_buffer.push('\n');
    }
}

// ── Single-file mode (original behavior, output unchanged) ────────────────────
fn run_single(
    path: &Path,
    file_path_copy: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = scan_file(path)?;

    print_summary(file_path_copy, &result.sha256, result.raw_match_count, result.display_matches.len());

    // Stringify the table after applying formatting, for both display and output file
    let table_str = render_display_table(&result.display_matches);
    print_display_table(&table_str);

    // Use the print_iocs function for both headers, with color and proper handling for CLI/GUI
    println!("\n");
    print_iocs("POTENTIAL FILESYSTEM IOCs:", &result.fs_iocs);

    if !result.net_iocs.is_empty() {
        println!("\n");
        print_iocs("POTENTIAL NETWORK IOCs:", &result.net_iocs);
    }

    print_detail(&result.flat_matches);

    println!();

    let save_output = matches.get_flag("output") || matches.contains_id("case");

    if save_output {
        let output_dir = resolve_output_dir(matches);
        std::fs::create_dir_all(&output_dir)?;

        let format = selected_format(matches);
        let custom_name = matches.get_one::<String>("output-file").map(|s| s.as_str());

        let contents = if format == "json" {
            let matched_only: Vec<_> = result.matches.iter().filter(|m| m.rule_name.is_some()).collect();
            serde_json::to_string_pretty(&serde_json::json!({
                "file": file_path_copy,
                "sha256": result.sha256,
                "matches": matched_only
            })).expect("Failed to serialize report")
        } else {
            // Build the report content (reuse printed table and IOCs)
            let mut report_buffer = build_file_report_body(&result, &table_str, format, true);
            append_ioc_sections(&mut report_buffer, &result.fs_iocs, &result.net_iocs, format);
            report_buffer
        };

        write_report(&output_dir, format, custom_name, &contents, matches, file_path_copy)?;
    } else {
        if !is_gui_mode() {
            println!("\nOutput was not saved.\n");
        }
    }
    // End: Output saving logic
    // Optional CLI footer: MITRE reference note
    if !is_gui_mode() {
        println!("Note: MITRE Tactic IDs can be referenced with MITRE_lookup tool.");
    }
    Ok(())
}

// ── Bundle mode: scan every embedded Mach-O binary in a .app bundle ───────────
fn run_bundle(
    bundle_path: &Path,
    file_path_copy: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let meta = common_macho::bundle_metadata(bundle_path);
    let targets = common_macho::resolve_scan_targets(bundle_path);

    // Bundle-level header
    println!("{}", styled_line("stone", &format!("Bundle: {}", file_path_copy)));
    if let Some(ref m) = meta {
        if let Some(ref id) = m.bundle_identifier {
            println!("{}", styled_line("stone", &format!("Bundle ID: {}", id)));
        }
        if let Some(ref exe) = m.bundle_executable {
            println!("{}", styled_line("stone", &format!("Executable: {}", exe)));
        }
        if let Some(ref ver) = m.bundle_version {
            println!("{}", styled_line("stone", &format!("Version: {}", ver)));
        }
    }
    println!("{}", styled_line("stone", &format!("Embedded Mach-O binaries: {}", targets.len())));

    if targets.is_empty() {
        println!("\n{}", "No Mach-O binaries found in bundle.".yellow());
        return Ok(());
    }

    let mut merged_fs_iocs: BTreeSet<String> = BTreeSet::new();
    let mut merged_net_iocs: BTreeSet<String> = BTreeSet::new();
    let mut scanned: Vec<(String, FileScanResult, String)> = Vec::new(); // (rel_path, result, table_str)

    for target in &targets {
        let rel_path = target
            .strip_prefix(bundle_path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| target.display().to_string());

        println!("\n{}", format!("=== {} ===", rel_path).truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));

        let result = match scan_file(target) {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("Failed to scan {}: {}", rel_path, e).yellow());
                continue;
            }
        };

        print_summary(&result.file_path, &result.sha256, result.raw_match_count, result.display_matches.len());

        let table_str = render_display_table(&result.display_matches);
        print_display_table(&table_str);
        print_detail(&result.flat_matches);

        merged_fs_iocs.extend(result.fs_iocs.iter().cloned());
        merged_net_iocs.extend(result.net_iocs.iter().cloned());
        scanned.push((rel_path, result, table_str));
    }

    // Combined IOC section across all binaries in the bundle
    println!("\n");
    print_iocs("POTENTIAL FILESYSTEM IOCs:", &merged_fs_iocs);

    if !merged_net_iocs.is_empty() {
        println!("\n");
        print_iocs("POTENTIAL NETWORK IOCs:", &merged_net_iocs);
    }

    println!();

    let save_output = matches.get_flag("output") || matches.contains_id("case");

    if save_output {
        let output_dir = resolve_output_dir(matches);
        std::fs::create_dir_all(&output_dir)?;

        let format = selected_format(matches);
        let custom_name = matches.get_one::<String>("output-file").map(|s| s.as_str());

        let contents = if format == "json" {
            let binaries: Vec<serde_json::Value> = scanned
                .iter()
                .map(|(rel_path, result, _)| {
                    let matched_only: Vec<_> = result.matches.iter().filter(|m| m.rule_name.is_some()).collect();
                    serde_json::json!({
                        "file": rel_path,
                        "sha256": result.sha256,
                        "matches": matched_only
                    })
                })
                .collect();
            serde_json::to_string_pretty(&serde_json::json!({
                "bundle": file_path_copy,
                "bundle_identifier": meta.as_ref().and_then(|m| m.bundle_identifier.clone()),
                "bundle_executable": meta.as_ref().and_then(|m| m.bundle_executable.clone()),
                "bundle_version": meta.as_ref().and_then(|m| m.bundle_version.clone()),
                "binaries": binaries
            })).expect("Failed to serialize report")
        } else {
            let mut report_buffer = String::new();
            if format == "md" {
                report_buffer.push_str("# mStrings Analysis Report\n\n");
                report_buffer.push_str(&format!("**Bundle:** `{}`  \n", file_path_copy));
                if let Some(ref m) = meta {
                    if let Some(ref id) = m.bundle_identifier {
                        report_buffer.push_str(&format!("**Bundle ID:** `{}`  \n", id));
                    }
                    if let Some(ref exe) = m.bundle_executable {
                        report_buffer.push_str(&format!("**Executable:** `{}`  \n", exe));
                    }
                    if let Some(ref ver) = m.bundle_version {
                        report_buffer.push_str(&format!("**Version:** `{}`  \n", ver));
                    }
                }
                report_buffer.push_str(&format!("**Embedded Mach-O binaries:** {}  \n\n", scanned.len()));
            } else {
                report_buffer.push_str(&format!("Bundle: {}\n", file_path_copy));
                if let Some(ref m) = meta {
                    if let Some(ref id) = m.bundle_identifier {
                        report_buffer.push_str(&format!("Bundle ID: {}\n", id));
                    }
                    if let Some(ref exe) = m.bundle_executable {
                        report_buffer.push_str(&format!("Executable: {}\n", exe));
                    }
                    if let Some(ref ver) = m.bundle_version {
                        report_buffer.push_str(&format!("Version: {}\n", ver));
                    }
                }
                report_buffer.push_str(&format!("Embedded Mach-O binaries: {}\n\n", scanned.len()));
            }

            for (rel_path, result, table_str) in &scanned {
                if format == "md" {
                    report_buffer.push_str(&format!("## Binary: {}\n\n", rel_path));
                } else {
                    report_buffer.push_str(&format!("=== {} ===\n\n", rel_path));
                }
                report_buffer.push_str(&build_file_report_body(result, table_str, format, false));
            }

            append_ioc_sections(&mut report_buffer, &merged_fs_iocs, &merged_net_iocs, format);
            report_buffer
        };

        write_report(&output_dir, format, custom_name, &contents, matches, file_path_copy)?;
    } else {
        if !is_gui_mode() {
            println!("\nOutput was not saved.\n");
        }
    }
    if !is_gui_mode() {
        println!("Note: MITRE Tactic IDs can be referenced with MITRE_lookup tool.");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("mstrings")
        .version("0.1")
        .author("Author Name <dwmetz@gmail.com>")
        .about("Searches for strings in files with YARA-style detections")
        .allow_hyphen_values(true)
        .dont_collapse_args_in_usage(true)
        .args_conflicts_with_subcommands(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("file")
                .help("File to scan")
                .required(false)
                .index(1)
                .num_args(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .num_args(0)
                .help("Save output (must be paired with -t, -j, or -m)"),
        )
        .arg(
            Arg::new("text")
                .short('t')
                .long("text")
                .help("Save report as text")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(&["json", "markdown"]),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Save report as JSON")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(&["text", "markdown"]),
        )
        .arg(
            Arg::new("markdown")
                .short('m')
                .long("markdown")
                .help("Save report as Markdown")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(&["text", "json"]),
        )
        .arg(
            Arg::new("case")
                .long("case")
                .num_args(1)
                .help("Optional case name to group output"),
        )
        .arg(
            Arg::new("output-file")
                .long("output-file")
                .num_args(1)
                .help("Custom output file name (used with --output)"),
        )
        .get_matches();

    let file_path = match matches.get_one::<String>("file").map(String::as_str) {
        Some(path) => path.to_string(),
        None => {
            println!("Enter the file path:");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();  // Remove trailing newline and whitespace


            input.to_string()
        }
    };
    let file_path_copy = file_path.clone(); // clone once for later reuse

    // Ensure Path::new uses trimmed input (file_path is already trimmed at this point)
    let path = std::path::Path::new(&file_path);

    if common_macho::is_app_bundle(path) {
        return run_bundle(path, &file_path_copy, &matches);
    }

    if path.is_dir() {
        eprintln!("{}", "Not a file or a recognized .app bundle (no Contents/Info.plist found).".red());
        std::process::exit(1);
    }

    run_single(path, &file_path_copy, &matches)
}
