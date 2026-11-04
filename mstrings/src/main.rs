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

// Function to handle printing IOCs (unified CLI/GUI logic and formatting).
// is_network gates defanging — filesystem IOCs are never defanged, only URLs/
// domains/IPs (see defang_network_ioc's doc comment for why).
/// Network IOCs, with public DNS resolvers listed separately (not C2).
fn print_net_iocs(iocs: &BTreeSet<String>) {
    let (net, resolvers) = split_resolvers(iocs);
    print_iocs("POTENTIAL NETWORK IOCs:", &net, true);
    if !resolvers.is_empty() {
        println!(
            "{} {}",
            "PUBLIC DNS RESOLVERS REFERENCED (not C2):".truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2),
            resolvers.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
}

fn print_iocs(title: &str, iocs: &std::collections::BTreeSet<String>, is_network: bool) {
    if !iocs.is_empty() {
        println!("{}", title.truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2));
        for ioc in iocs {
            if is_network {
                println!("{}", defang_network_ioc(ioc));
            } else {
                println!("{}", ioc);
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
enum Encoding {
    Ascii,
    Utf8,
    Utf16,
    Base64,
}

#[derive(Debug, serde::Serialize)]
struct Match {
    offset: usize,
    encoding: Encoding,
    // Full underlying string (can be a multi-hundred-byte decoded base64
    // blob) — IOC extraction below needs the whole thing, so this is never
    // truncated to a rule's specific hit. See `display_str` for that.
    matched_str: String,
    // The actual regex-matched substring for this rule, set in
    // apply_yara_detections(). Distinct from matched_str because several
    // unrelated rules can all match somewhere inside the same long decoded
    // blob — showing the shared blob prefix for every one of them made the
    // "Matched Strings" column look identical across different detections.
    // Defaults to matched_str for untagged matches, where it's unused.
    display_str: String,
    // How many base64 layers were peeled to reach this match (0 for
    // non-decoded matches). A rule firing only after several layers of
    // decoding is itself a signal — routine base64 use is one layer;
    // repeated re-encoding is a deliberate evasion tell.
    decode_layers: u8,
    rule_name: Option<String>,
    tactic: Option<String>,
    technique: Option<String>,
    technique_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Detection {
    title: String,
    detection: DetectionStrings,
    #[serde(default)]
    mitre: Vec<MitreMapping>,
    /// An IOC-only rule reports its matches (and feeds IOC extraction) but
    /// claims no ATT&CK technique: e.g. a private IP address, which is worth
    /// listing but is not evidence of C2 by itself. Without this flag a rule
    /// with no `mitre` entry never fires.
    #[serde(default)]
    ioc_only: bool,
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

// Reserved/documentation/network-address IPs that are never a real IOC —
// mirrors the exclusions in detections.yaml's HardcodedIPAddress rule, kept
// in sync so the blob-path extractor below (which has its own IP regex,
// since the regex crate used there has no lookaround for the boundary
// check) doesn't let through what the rule-based path already excludes.
// Found needed on IPStorm (TAOMM Ch1): 0.0.0.0 and 10.0.0.0 — both from
// libp2p's own bogon/CIDR-filter constant list — leaked through here even
// after the rule itself was fixed, since this is a separate code path.
/// Well-known public DNS resolvers. Malware hardcodes these for name
/// resolution or connectivity checks (Mirai-family bots use 8.8.8.8 to learn
/// their own local IP) — worth reporting, but they are not C2, so they get
/// their own report section instead of the Network IOC list.
const PUBLIC_DNS_RESOLVERS: &[&str] = &[
    "8.8.8.8", "8.8.4.4",                  // Google
    "1.1.1.1", "1.0.0.1",                  // Cloudflare
    "9.9.9.9", "149.112.112.112",          // Quad9
    "208.67.222.222", "208.67.220.220",    // OpenDNS
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6", // Level3
    "64.6.64.6", "64.6.65.6",              // Verisign
    "94.140.14.14", "94.140.15.15",        // AdGuard
    "114.114.114.114", "114.114.115.115",  // 114DNS
    "223.5.5.5", "223.6.6.6",              // AliDNS
    "119.29.29.29", "180.76.76.76",        // DNSPod, Baidu
    "77.88.8.8", "77.88.8.1",              // Yandex
];

/// Split resolver IPs out of a network IOC set: (iocs, resolvers).
fn split_resolvers(net_iocs: &BTreeSet<String>) -> (BTreeSet<String>, BTreeSet<String>) {
    net_iocs.iter().cloned().partition(|ioc| !PUBLIC_DNS_RESOLVERS.contains(&ioc.as_str()))
}

/// Pull well-formed URLs out of a string. Go (and some C) binaries store
/// strings back to back with no separator, so a URL can be glued to a comma
/// list, a closing parenthesis, or a following hex constant — the old
/// "everything up to whitespace or a quote" match swallowed all of that
/// (XorDDoS: four C2 config URLs reported as one IOC). Stop at characters
/// that don't occur in malware URLs in practice, trim trailing punctuation,
/// and drop Go toolchain documentation links present in every Go binary.
fn extract_urls(s: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)https?://[a-z0-9](?:[a-z0-9.\-]*[a-z0-9])?(?::\d{1,5})?(?:[/?#][a-z0-9._~%!$&*+=:@/?#\-]*)?").unwrap()
    });
    let mut out = Vec::new();
    for m in re.find_iter(s).flatten() {
        let url = m.as_str().trim_end_matches(['.', ':', '?', '#', '-']);
        let lower = url.to_ascii_lowercase();
        let host = lower.split("://").nth(1).unwrap_or("").split(['/', '?', '#', ':']).next().unwrap_or("");
        if !host.contains('.') || host.len() < 4 || url.len() > 300 {
            continue;
        }
        if matches!(host, "go.dev" | "golang.org" | "www.golang.org" | "pkg.go.dev") {
            continue;
        }
        out.push(url.to_string());
    }
    out
}

fn is_boring_ip(ip: &str) -> bool {
    if ip == "127.0.0.1" || ip == "239.255.255.250" {
        return true;
    }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    if octets[0] == "255" {
        return true; // 255.x.x.x — broadcast or a subnet mask (240.0.0.0/4 is reserved, never a host)
    }
    if octets[1] == "0" && octets[2] == "0" && octets[3] == "0" {
        return true; // X.0.0.0 — network/supernet address
    }
    if octets[2] == "0" && octets[3] == "0" {
        return true; // X.X.0.0 — network/supernet address
    }
    (octets[0] == "192" && octets[1] == "0" && (octets[2] == "0" || octets[2] == "2")) // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1)
        || (octets[0] == "198" && octets[1] == "51" && octets[2] == "100") // TEST-NET-2
        || (octets[0] == "203" && octets[1] == "0" && octets[2] == "113") // TEST-NET-3
}

// The Hardcoded Bitcoin address rule's regex only checks charset/length/case
// shape, which isn't enough: Itanium C++ mangled symbol names (ubiquitous in
// any Qt/C++ Mach-O binary, e.g. minergate-cli's "3connectToHostERK7QStringt")
// routinely fall inside the same 26-35-char Base58 envelope with mixed case,
// since the linker's string-suffix-sharing optimization leaves standalone
// null-terminated fragments that look exactly like address bodies. A real
// Base58Check address's last 4 bytes are a double-SHA256 checksum of the
// preceding 21 bytes — decode and verify that here so only cryptographically
// real addresses fire, instead of adding more probabilistic regex heuristics
// that the next mangled-symbol shape would just slip past again.
fn is_valid_base58check_address(s: &str) -> bool {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut leading_zeros = 0usize;
    let mut chars = s.chars().peekable();
    while chars.peek() == Some(&'1') {
        leading_zeros += 1;
        chars.next();
    }

    // Big-endian base58 -> base256 via repeated "multiply whole number by
    // 58, add next digit" on a little-endian byte accumulator.
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.chars() {
        let Some(digit) = ALPHABET.iter().position(|&a| a as char == c) else {
            return false; // not valid base58 charset at all
        };
        let mut carry = digit as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    bytes.resize(bytes.len() + leading_zeros, 0);
    bytes.reverse(); // was little-endian, address payload is big-endian

    // Standard legacy address payload: 1-byte version + 20-byte hash160 + 4-byte checksum.
    if bytes.len() != 25 {
        return false;
    }
    let (payload, checksum) = bytes.split_at(21);
    let round1 = Sha256::digest(payload);
    let round2 = Sha256::digest(round1);
    &round2[0..4] == checksum
}

// Defang a network IOC before display — standard analyst practice, and the
// same reasoning that already applies to the Analyze rollup: a rendered/
// displayed URL that reads exactly like a live clickable link is the wrong
// affordance for a malware report to put in front of an analyst. Idempotent
// (checks for "[.]"/"hxxp" already present) so re-processing already-
// defanged text — e.g. the Python/MCP rollup re-extracting this same value
// out of mstrings' own markdown — never double-defangs it into "[[.]]".
fn defang_network_ioc(ioc: &str) -> String {
    let lower = ioc.to_lowercase();
    if ioc.contains("[.]") || lower.contains("hxxp") {
        return ioc.to_string(); // already defanged
    }
    ioc.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace("ftp://", "fxxp://")
        .replace('.', "[.]")
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
        let encoding_type = if std::str::from_utf8(line.as_bytes()).is_ok() {
            Encoding::Utf8
        } else {
            Encoding::Ascii
        };
        self.push_line(line, offset, encoding_type);
    }

    // Same as process_line, but for a run recovered from the UTF-16LE
    // extraction pass in scan_file (see there for why that pass exists).
    pub fn process_line_utf16(&mut self, line: &str, offset: usize) {
        self.push_line(line, offset, Encoding::Utf16);
    }

    fn push_line(&mut self, line: &str, offset: usize, encoding: Encoding) {
        if !line.trim().is_empty() && !is_objc_swift_noise(line) {
            let trimmed = line.trim_start().to_string();
            self.matches.push(Match {
                offset,
                encoding,
                display_str: trimmed.clone(),
                matched_str: trimmed,
                decode_layers: 0,
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
            let mut layers: u8 = 0;

            for _ in 0..MAX_LAYERS {
                let decoded = match BASE64_STANDARD.decode(current.trim()) {
                    Ok(d) if d.len() >= MIN_DECODED_LEN => d,
                    _ => break, // invalid/too-short at this layer — abandon this candidate
                };
                layers += 1;
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
            let decoded_str = String::from_utf8_lossy(&decoded).to_string();
            decoded_matches.push(Match {
                offset,
                encoding: Encoding::Base64,
                display_str: decoded_str.clone(),
                matched_str: decoded_str,
                decode_layers: layers,
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
        self.apply_detections_from_yaml(&yaml_content)
    }

    // Split out from apply_yara_detections so tests can feed the real
    // detections.yaml by path instead of relying on the working directory.
    fn apply_detections_from_yaml(&mut self, yaml_content: &str) -> Result<(), Box<dyn std::error::Error>> {
        let raw_rules: HashMap<String, Detection> = serde_yaml::from_str(yaml_content)?;

        let mut compiled_rules = Vec::new();
        for (_key, det) in &raw_rules {
            for pattern in &det.detection.strings {
                if let Ok(regex) = Regex::new(pattern) {
                    if det.ioc_only && det.mitre.is_empty() {
                        compiled_rules.push((regex.clone(), det.title.clone(), String::new(), String::new(), String::new()));
                    }
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
            // Keyed by (rule_name, matched text) rather than rule_name alone: a
            // rule with multiple patterns (e.g. two distinct command strings
            // that are both meaningful evidence on their own) can have both
            // patterns match within the same single extracted string — most
            // often a large base64-decoded blob, which mstrings treats as one
            // whole matched_str rather than splitting it back into lines.
            // Deduping on rule_name alone silently dropped every pattern after
            // the first one that matched in that blob, even though each was a
            // genuine independent hit at a different offset within it.
            //
            // The technique ID is part of the key too: compiled_rules holds one
            // entry per (pattern, technique), so a rule mapped to several
            // techniques must produce one Match per technique. Keying on
            // (rule, text) alone kept only the first technique and silently
            // dropped the rest (WMISystemDiscovery reported T1047 but never
            // T1082). The report groups these back into one row per rule.
            let mut seen_rules: std::collections::HashSet<(String, String, String)> = std::collections::HashSet::new();
            for (regex, rule_name, tactic, technique, technique_id) in &compiled_rules {
                if let Ok(Some(found)) = regex.find(&m.matched_str) {
                    if rule_name == "Hardcoded Bitcoin address (P2PKH/P2SH)"
                        && !is_valid_base58check_address(found.as_str())
                    {
                        continue; // shape matched but checksum didn't — not a real address
                    }
                    if seen_rules.insert((rule_name.clone(), found.as_str().to_string(), technique_id.clone())) {
                        new_matches.push(Match {
                            offset: m.offset,
                            encoding: m.encoding.clone(),
                            matched_str: m.matched_str.clone(),
                            display_str: found.as_str().to_string(),
                            decode_layers: m.decode_layers,
                            rule_name: Some(rule_name.clone()),
                            tactic: Some(tactic.clone()).filter(|t| !t.is_empty()),
                            technique: Some(technique.clone()).filter(|t| !t.is_empty()),
                            technique_id: Some(technique_id.clone()).filter(|t| !t.is_empty()),
                        });
                        any_match = true;
                    }
                }
            }
            if !any_match {
                new_matches.push(Match {
                    offset: m.offset,
                    encoding: m.encoding.clone(),
                    matched_str: m.matched_str.clone(),
                    display_str: m.matched_str.clone(),
                    decode_layers: m.decode_layers,
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

/// One technique a match was attributed to: (tactics, technique name, ID).
/// `tactics` is already comma-joined, as it comes from detections.yaml.
type MitreCell = (String, String, String);

/// Record a match's technique on a report row, once, keeping first-seen
/// (detections.yaml) order. IOC-only matches carry no technique and add nothing.
fn push_mitre(cells: &mut Vec<MitreCell>, m: &Match) {
    let id = m.technique_id.clone().unwrap_or_default();
    if id.is_empty() || cells.iter().any(|c| c.2 == id) {
        return;
    }
    cells.push((
        m.tactic.clone().unwrap_or_default(),
        m.technique.clone().unwrap_or_default(),
        id,
    ));
}

/// Flatten a row's techniques into its Tactic / Technique / ID cells.
/// Tactics are de-duplicated and comma-joined (the PWA matrix parser splits
/// the Tactic cell on ","); technique names are joined with "; " because the
/// names themselves can contain commas; IDs are comma-joined (the matrix
/// parser pulls every T-number out of the ID cell). A single-technique rule
/// renders exactly as before.
fn join_mitre(cells: &[MitreCell]) -> (String, String, String) {
    let mut tactics: Vec<&str> = Vec::new();
    for (t, _, _) in cells {
        for part in t.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if !tactics.contains(&part) {
                tactics.push(part);
            }
        }
    }
    (
        tactics.join(", "),
        cells.iter().map(|c| c.1.as_str()).collect::<Vec<_>>().join("; "),
        cells.iter().map(|c| c.2.as_str()).collect::<Vec<_>>().join(", "),
    )
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
    // ATT&CK v20 split Defense Evasion into Defense Impairment (TA0112) and
    // Stealth (TA0005); "defense evasion" stays for custom/older rule files.
    else if t.contains("defense impairment") { 9 }
    else if t.contains("stealth")         { 9 }
    else if t.contains("defense evasion") { 9 }
    else if t.contains("discovery")       { 10 }
    else if t.contains("resource development") { 11 }
    else { 12 }
}

/// Title of the detections.yaml rule for long base64-alphabet strings.
const B64_BLOB_RULE: &str = "Large embedded base64 blob";
/// How many distinct blob strings it takes to call it a string table.
const ENCODED_TABLE_MIN: usize = 25;

/// One summary row for a binary whose payload is stored as a table of many
/// encoded strings (AMOS keeps its whole AppleScript stealer as ~2,000
/// encrypted, base64-alphabet C strings decoded at runtime). Per-string
/// matches say nothing useful at that scale; the shape itself is the finding,
/// and it explains why no other rule fires — the behavior isn't in plaintext.
fn encoded_string_table_row(matches: &[Match], file_len: usize) -> Option<DisplayMatch> {
    let mut seen = std::collections::BTreeSet::new();
    let (mut bytes, mut lo, mut hi) = (0usize, usize::MAX, 0usize);
    for m in matches.iter().filter(|m| m.rule_name.as_deref() == Some(B64_BLOB_RULE) && m.decode_layers == 0) {
        if seen.insert(m.offset) {
            bytes += m.matched_str.len();
            lo = lo.min(m.offset);
            hi = hi.max(m.offset + m.matched_str.len());
        }
    }
    let n = seen.len();
    if n < ENCODED_TABLE_MIN {
        return None;
    }
    let kb = bytes as f64 / 1024.0;
    let share = if file_len > 0 { bytes as f64 * 100.0 / file_len as f64 } else { 0.0 };
    Some(DisplayMatch {
        count: n.to_string(),
        rule_name: "Encoded string table (likely encrypted payload)".to_string(),
        matched_strings: format!(
            "{n} base64-alphabet strings, {kb:.0} KB ({share:.0}% of file) at 0x{lo:X}–0x{hi:X}; \
             decoded at runtime, so the real behavior isn't visible as plaintext strings"
        ),
        tactic: "Stealth".to_string(),
        technique: "Obfuscated Files or Information: Encrypted/Encoded File".to_string(),
        technique_id: "T1027.013".to_string(),
    })
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
    /// Runs of IPs stored together (see `split_ip_lists`), kept out of net_iocs.
    ip_lists: Vec<IpList>,
    matches: Vec<Match>,
    /// Every extracted string, before mStrings' noise filter, for the full
    /// strings dump saved alongside the report.
    raw_strings: Vec<RawString>,
}

/// One extracted string as it came off the file, unfiltered.
#[derive(Debug, Clone)]
struct RawString {
    offset: usize,
    encoding: &'static str,
    text: String,
}

/// Per-file cap on the full strings dump. Go and Electron binaries can yield
/// tens of MB of strings; a folder-wide Analyze run would otherwise fill the
/// case. The dump says plainly when and where it was cut.
const STRINGS_DUMP_CAP: usize = 10 * 1024 * 1024;

/// Ten or more IP addresses stored within a few hundred bytes of each other:
/// an embedded list, most often an anti-analysis blocklist of sandbox and
/// analysis-host IPs (Luna Grabber's blackListedIPS), sometimes a C2 pool.
/// Either way, not ten separate C2 indicators.
#[derive(Debug, Clone)]
struct IpList {
    start: usize,
    end: usize,
    ips: Vec<String>,
}

const IP_LIST_MIN: usize = 10;
const IP_LIST_GAP: usize = 256;

/// Move IPs that sit in a dense run (>= IP_LIST_MIN within IP_LIST_GAP bytes
/// of each other) out of `net_iocs` into lists. `ip_offsets` holds only IPs
/// stored as whole strings (or whole lines of a decoded blob), with each one's
/// first offset: an IP inside a command line ("curl http://1.2.3.4/x") is a
/// standalone indicator however close it sits to a list.
fn split_ip_lists(net_iocs: &mut BTreeSet<String>, ip_offsets: &HashMap<String, usize>) -> Vec<IpList> {
    let mut by_off: Vec<(usize, &String)> = ip_offsets
        .iter()
        .filter(|(ip, _)| net_iocs.contains(*ip))
        .map(|(ip, off)| (*off, ip))
        .collect();
    by_off.sort();
    let mut lists = Vec::new();
    let mut run: Vec<(usize, &String)> = Vec::new();
    let flush = |run: &mut Vec<(usize, &String)>, lists: &mut Vec<IpList>| {
        if run.len() >= IP_LIST_MIN {
            lists.push(IpList {
                start: run[0].0,
                end: run[run.len() - 1].0,
                ips: run.iter().map(|(_, ip)| (*ip).clone()).collect(),
            });
        }
        run.clear();
    };
    for (off, ip) in by_off {
        if let Some(&(last, _)) = run.last() {
            if off.saturating_sub(last) > IP_LIST_GAP {
                flush(&mut run, &mut lists);
            }
        }
        run.push((off, ip));
    }
    flush(&mut run, &mut lists);
    for l in &lists {
        for ip in &l.ips {
            net_iocs.remove(ip);
        }
    }
    lists
}

// Scan a single file: read bytes, hash, extract strings, apply detections,
// build the grouped/flat match views and extract filesystem/network IOCs.
fn scan_file(path: &Path) -> Result<FileScanResult, Box<dyn std::error::Error>> {
    let mut fs_iocs = BTreeSet::new();
    let mut net_iocs = BTreeSet::new();
    let mut ip_offsets: HashMap<String, usize> = HashMap::new();

    let file = File::open(path)?;
    let mut mstrings = Mstrings::new();
    let mut raw_strings: Vec<RawString> = Vec::new();
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
                raw_strings.push(RawString { offset: string_start, encoding: "ascii", text: s });
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current.clone()) {
            mstrings.process_line(&s, string_start);
            raw_strings.push(RawString { offset: string_start, encoding: "ascii", text: s });
        }
    }

    // UTF-16LE extraction pass — catches text stored as 16-bit little-endian
    // code units instead of UTF-8/ASCII bytes: Windows PE resources, and
    // macOS's compiled AppleScript (.scpt) format, which osacompile uses for
    // every text literal in a script. Confirmed necessary via a TAOMM
    // Bundlore sample: a 'do shell script' payload (domain, curl/tar
    // commands) was only recoverable by decoding the .scpt as UTF-16LE —
    // the ASCII/UTF-8 pass above never found it at all, since none of the
    // bytes form a valid run under that scan (every other byte is 0x00).
    // Restricted to the printable-ASCII/Latin-1 range (low byte only, high
    // byte must be 0x00) since that covers every case relevant to detection
    // rules; full BMP decoding would need String::from_utf16 and complicate
    // the noise filtering below for no practical benefit here. Naturally
    // low-noise: a plain ASCII/UTF-8 file has no null bytes to pair against,
    // so this pass only ever fires on genuinely UTF-16-encoded content.
    let mut current16: Vec<u8> = Vec::new();
    let mut string_start16: usize = 0;
    let mut i = 0usize;
    while i + 1 < buffer.len() {
        let lo = buffer[i];
        let hi = buffer[i + 1];
        if hi == 0 && (lo.is_ascii_graphic() || lo == b' ') {
            if current16.is_empty() {
                string_start16 = i;
            }
            current16.push(lo);
            i += 2;
        } else {
            if current16.len() >= 4 {
                if let Ok(s) = String::from_utf8(current16.clone()) {
                    mstrings.process_line_utf16(&s, string_start16);
                    raw_strings.push(RawString { offset: string_start16, encoding: "utf16le", text: s });
                }
            }
            current16.clear();
            i += 1;
        }
    }
    if current16.len() >= 4 {
        if let Ok(s) = String::from_utf8(current16.clone()) {
            mstrings.process_line_utf16(&s, string_start16);
            raw_strings.push(RawString { offset: string_start16, encoding: "utf16le", text: s });
        }
    }
    // Interleave the two passes by file offset so the dump reads top to bottom.
    raw_strings.sort_by_key(|r| r.offset);

    mstrings.decode_base64_blobs();
    mstrings.apply_yara_detections()?;

    // A rule mapped to several techniques yields one Match per technique for
    // the same string (see apply_detections_from_yaml), so count distinct
    // (offset, rule, string) hits rather than Match entries, or a
    // two-technique rule would double the reported match count.
    let raw_match_count = mstrings.matches.iter()
        .filter(|m| m.rule_name.is_some())
        .map(|m| (m.offset, m.rule_name.as_deref().unwrap_or(""), m.display_str.as_str()))
        .collect::<std::collections::HashSet<_>>()
        .len();

    // Group matched strings by rule name, collecting every technique the rule
    // maps to (in detections.yaml order). Use BTreeSet per group to
    // deduplicate strings that appear at multiple offsets.
    let mut rule_groups: std::collections::HashMap<
        String,
        (Vec<MitreCell>, std::collections::BTreeSet<String>, u8),
    > = std::collections::HashMap::new();

    for m in mstrings.matches.iter().filter(|m| m.rule_name.is_some()) {
        let rule = m.rule_name.as_ref().unwrap().clone();
        let entry = rule_groups.entry(rule).or_insert_with(|| (
            Vec::new(),
            std::collections::BTreeSet::new(),
            0u8,
        ));
        push_mitre(&mut entry.0, m);
        entry.1.insert(m.display_str.clone());
        entry.2 = entry.2.max(m.decode_layers);
    }

    // Sort groups: primary = tactic priority, secondary = rule name
    let mut sorted_groups: Vec<(String, String, String, String, Vec<String>, u8)> = rule_groups
        .into_iter()
        .map(|(rule, (mitre, strings, max_layers))| {
            let (tactic, technique, id) = join_mitre(&mitre);
            (rule, tactic, technique, id, strings.into_iter().collect(), max_layers)
        })
        .collect();
    sorted_groups.sort_by(|a, b| {
        tactic_priority(&a.1).cmp(&tactic_priority(&b.1)).then(a.0.cmp(&b.0))
    });

    let mut display_matches: Vec<DisplayMatch> = sorted_groups
        .iter()
        .map(|(rule, tactic, technique, id, strings, max_layers)| {
            let count = strings.len();
            let mut matched_strings = {
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
            // Only a rule firing after MULTIPLE re-encoding layers is a
            // meaningful evasion tell — a single base64 decode is routine
            // (e.g. `echo <blob> | base64 -d`) and not worth flagging.
            if *max_layers > 1 {
                matched_strings = format!("{matched_strings}  [\u{26A0} found after {max_layers} layers of base64 decoding]");
            }
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

    if let Some(row) = encoded_string_table_row(&mstrings.matches, buffer.len()) {
        display_matches.insert(0, row);
    }

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
                for url in extract_urls(&m.matched_str) {
                    net_iocs.insert(url);
                }
                // IP boundary check: regex crate has no lookarounds, so verify
                // surrounding bytes manually. is_boring_ip() filters loopback/
                // broadcast/reserved/network-address shapes — see its doc
                // comment. RFC 1918 host addresses are still kept (not boring):
                // a private IP hardcoded in malware strings is a meaningful
                // tell (lateral movement target, lab infrastructure leak,
                // etc.). Boundary excludes ASCII letters and underscore too,
                // not just digit/dot — a Go compiler closure symbol like
                // ...marshal.func1.4.10.1 has a letter ('c' in "func")
                // immediately before "4.10.1", which a digit/dot-only check
                // never caught, so IPStorm's symbol table produced dozens of
                // fake "IPs" shaped like func-name tail numbers.
                let blob = m.matched_str.as_bytes();
                let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.';
                for mat in re_ip.find_iter(&m.matched_str).flatten() {
                    let start = mat.start();
                    let end   = mat.end();
                    let before_ok = start == 0 || !is_word_byte(blob[start - 1]);
                    let after_ok  = end == blob.len() || !is_word_byte(blob[end]);
                    if before_ok && after_ok && !is_boring_ip(mat.as_str()) {
                        net_iocs.insert(mat.as_str().to_string());
                        // A whole line of a decoded blob counts as a list entry.
                        let line_start = start == 0 || matches!(blob[start - 1], b'\n' | b'\r');
                        let line_end = end == blob.len() || matches!(blob[end], b'\n' | b'\r');
                        if line_start && line_end {
                            ip_offsets.entry(mat.as_str().to_string()).or_insert(m.offset + start);
                        }
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
                let rule_lc = rule.to_lowercase();

                // Network indicators first, and regardless of spaces: the
                // filters below are for file IOCs. An IP or URL inside a
                // command line ("curl -s http://…", "beacon 1.2.3.4 443") is
                // still a precise indicator — the IP rule's own capture and
                // extract_urls() pull out just the indicator — and skipping
                // every string with a space dropped exactly those.
                let mut network_done = false;
                if rule_lc.contains("ip address") {
                    let ip = m.display_str.trim().to_string();
                    if !is_boring_ip(&ip) {
                        // Only an IP that is a whole string by itself can be a
                        // list entry (see split_ip_lists).
                        if m.matched_str.trim() == ip {
                            ip_offsets.entry(ip.clone()).or_insert(m.offset);
                        }
                        net_iocs.insert(ip);
                    }
                    network_done = true;
                } else if sc.contains("http:") || sc.contains("https:") {
                    let urls = extract_urls(candidate);
                    network_done = !urls.is_empty();
                    for url in urls {
                        net_iocs.insert(url);
                    }
                }

                if !network_done && !is_template && !has_spaces && !has_namespace {
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
                    } else if rule_lc.contains("ip address") {
                        // Use display_str (the rule's own precise capture) rather
                        // than the whole candidate/matched_str: a real IP is
                        // routinely embedded in a longer command line or query
                        // string (e.g. a Zyxel exploit's
                        // "wget+http://213.209.129.101/zyxel;chmod+777+..."),
                        // and inserting the whole thing produces an unreadable
                        // net_ioc entry when the clean, exact IP is already
                        // sitting right there in display_str.
                        net_iocs.insert(m.display_str.trim().to_string());
                        ip_offsets.entry(m.display_str.trim().to_string()).or_insert(m.offset);
                    } else if sc.contains("http:") || sc.contains("https:") {
                        for url in extract_urls(candidate) {
                            net_iocs.insert(url);
                        }
                    } else if sc.split('.').count() == 4
                            && sc.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                    {
                        net_iocs.insert(candidate.to_string());
                        if m.matched_str.trim() == candidate {
                            ip_offsets.entry(candidate.to_string()).or_insert(m.offset);
                        }
                    }
                }
            }

            // Bare-domain C2 indicators (e.g. "cdntor.ru", "usb.mine.nu") —
            // caught by a rule's own regex but with no "http://" scheme and
            // not a 4-part IPv4 shape, so neither branch above picks them up
            // (both require a scheme or an IPv4 shape). Use display_str, the
            // rule's own precise match, rather than re-deriving domain shape
            // from scratch — and gate on the Command and Control tactic so
            // dotted-but-not-network strings a C2-tactic rule might still
            // incidentally match (e.g. a version string) stay out, while
            // filesystem-flavored dotted strings (bundle IDs, LaunchDaemon
            // labels) picked up by non-C2 rules are never considered here.
            // Also require all-lowercase: a C2-tactic rule can legitimately
            // match a dotted Objective-C class/namespace string (e.g.
            // "com.pusher.libPusher", found by the libPusher C2 rule itself)
            // which is dotted but NOT a domain — real domains harvested from
            // binaries are lowercase, camelCase/PascalCase identifiers aren't.
            if let Some(tactic) = &m.tactic {
                if tactic.contains("Command and Control") {
                    let d = m.display_str.trim();
                    // Numeric dotted-quads (real or Go-symbol-tail-shaped
                    // fakes like "4.10.1") are deliberately left to the
                    // dedicated Hardcoded IP address rule/path instead of
                    // this heuristic — that path has real exclusions
                    // (reserved/documentation ranges, broadcast, network
                    // addresses) this generic shape check has no business
                    // re-deriving, and a second independent path applying
                    // its own weaker rules was exactly how those reserved
                    // ranges and Go-symbol tails leaked into net_iocs on
                    // IPStorm (TAOMM Ch1) despite the dedicated rule already
                    // excluding most of them.
                    let is_dotted_quad = d.split('.').count() == 4
                        && d.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
                    if !is_dotted_quad
                        && d.contains('.')
                        && !d.contains(' ')
                        && !d.contains('/')
                        && !d.contains('_')
                        && !d.contains('\\')
                        && d.len() < 100
                        && !d.chars().any(|c| c.is_ascii_uppercase())
                    {
                        net_iocs.insert(d.to_string());
                    }
                }
            }
        }
    }

    // Detail section: flat per-string table for drill-down (parsed by PWA toggle).
    // One row per (offset, rule, string): the per-technique Match copies of a
    // multi-technique rule are folded back together, in first-seen order.
    let mut flat_index: HashMap<(usize, &str, &str), usize> = HashMap::new();
    let mut flat_rows: Vec<(&Match, Vec<MitreCell>)> = Vec::new();
    for m in mstrings.matches.iter().filter(|m| m.rule_name.is_some()) {
        let key = (m.offset, m.rule_name.as_deref().unwrap_or(""), m.display_str.as_str());
        let i = *flat_index.entry(key).or_insert_with(|| {
            flat_rows.push((m, Vec::new()));
            flat_rows.len() - 1
        });
        push_mitre(&mut flat_rows[i].1, m);
    }
    let flat_matches: Vec<FlatMatch> = flat_rows.iter()
        .map(|(m, mitre)| {
            let (tactic, technique, technique_id) = join_mitre(mitre);
            FlatMatch {
                offset:       format!("0x{:08X}", m.offset),
                encoding:     if m.decode_layers > 1 {
                    format!("Base64\u{d7}{}", m.decode_layers)
                } else {
                    format!("{:?}", m.encoding)
                },
                matched_str:  truncate_string(&m.display_str, 60),
                rule_name:    m.rule_name.clone().unwrap_or_default(),
                tactic,
                technique,
                technique_id,
            }
        })
        .collect();

    Ok(FileScanResult {
        file_path: path.display().to_string(),
        sha256,
        raw_match_count,
        display_matches,
        flat_matches,
        ip_lists: split_ip_lists(&mut net_iocs, &ip_offsets),
        fs_iocs,
        net_iocs,
        matches: mstrings.matches,
        raw_strings,
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
        .with(Modify::new(Columns::one(0)).with(Width::wrap(5).keep_words(true)))   // Count
        .with(Modify::new(Columns::one(1)).with(Width::wrap(30).keep_words(true)))  // Rule
        .with(Modify::new(Columns::one(2)).with(Width::wrap(45).keep_words(true)))  // Matched Strings
        .with(Modify::new(Columns::one(3)).with(Width::wrap(18).keep_words(true)))  // Tactic
        .with(Modify::new(Columns::one(4)).with(Width::wrap(25).keep_words(true)))  // Technique
        .with(Modify::new(Columns::one(5)).with(Width::wrap(10).keep_words(true))); // ID
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
            .with(Modify::new(Columns::one(3)).with(Width::wrap(25).keep_words(true)))
            .with(Modify::new(Columns::one(4)).with(Width::wrap(18).keep_words(true)))
            .with(Modify::new(Columns::one(5)).with(Width::wrap(25).keep_words(true)))
            .with(Modify::new(Columns::one(2)).with(Width::wrap(30).keep_words(true)));
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

// ── Full strings dump ─────────────────────────────────────────────────────────
// Saved next to every report mStrings writes (-o, PWA, Analyze), so the case
// holds what the rules ran against and not just what they matched. Offsets
// are mStrings' own, so a detail-table hit (lsass.exe @ 0x000000F0) can be
// found in context by offset. Goes in its own full_strings/ folder, never in
// mstrings/: the server's Analyze path renames and registers "the newest file
// in <case>/mstrings/" as the report, so a dump there could be mistaken for it.

/// Render the dump body, stopping at `cap` bytes. Returns (text, truncated).
fn format_strings_dump(
    file_path: &str,
    sha256: &str,
    raw: &[RawString],
    matches: &[Match],
    cap: usize,
) -> (String, bool) {
    // Base64 blobs mStrings decoded: derived text, listed after the raw
    // extraction and labeled, de-duplicated across per-technique Match copies.
    let mut seen = std::collections::HashSet::new();
    let decoded: Vec<&Match> = matches.iter()
        .filter(|m| matches!(m.encoding, Encoding::Base64))
        .filter(|m| seen.insert((m.offset, m.matched_str.as_str())))
        .collect();
    let ascii = raw.iter().filter(|r| r.encoding == "ascii").count();
    let utf16 = raw.len() - ascii;

    let mut out = String::new();
    out.push_str("# mStrings full strings dump\n");
    out.push_str(&format!("# File:    {}\n", file_path));
    out.push_str(&format!("# SHA256:  {}\n", sha256));
    out.push_str("# Extraction: printable runs of 4+ characters, ASCII/UTF-8 and UTF-16LE,\n");
    out.push_str("#   unfiltered (mStrings' ObjC/Swift noise filter is not applied here).\n");
    out.push_str("#   Offsets are file offsets and match the mStrings detail table.\n");
    out.push_str(&format!("# Strings: {} ({} ascii, {} utf16le), {} decoded\n", raw.len(), ascii, utf16, decoded.len()));
    out.push_str("# Columns: offset, encoding, string (tab-separated)\n\n");

    let rows = raw.iter().map(|r| (r.offset, r.encoding, r.text.as_str(), false))
        .chain(decoded.iter().map(|m| (m.offset, "base64", m.matched_str.as_str(), true)));
    let total = raw.len() + decoded.len();
    let mut written = 0usize;
    let mut in_decoded = false;
    for (offset, enc, text, is_decoded) in rows {
        if is_decoded && !in_decoded {
            out.push_str("\n# --- decoded (derived): base64 blobs mStrings decoded; offset is the blob's ---\n");
            in_decoded = true;
        }
        // Tabs and newlines inside a string would break the one-line-per-string format.
        let clean = text.replace(['\t', '\r', '\n'], " ");
        let line = format!("0x{:08X}\t{}\t{}\n", offset, enc, clean);
        if out.len() + line.len() > cap {
            out.push_str(&format!(
                "\n# TRUNCATED at {} MB: {} of {} strings written. Run mstrings on the file directly for the rest.\n",
                cap / (1024 * 1024), written, total
            ));
            return (out, true);
        }
        out.push_str(&line);
        written += 1;
    }
    (out, false)
}

/// Filename stem for a dump, built the same way the server names Analyze's
/// case reports (_rename_case_report in malchela_server.py): the file stem
/// without its extension, each run of characters outside [\w.-] collapsed to
/// one "_", underscores trimmed from both ends, at most 80 characters, and
/// "file" if nothing is left. So 90(2)'s dump, 90_2_strings_<ts>.txt, sorts
/// right next to its report, 90_2_<ts>.md.
fn dump_stem(name_hint: &str) -> String {
    let base = Path::new(name_hint)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| name_hint.to_string());
    let mut out = String::new();
    let mut in_run = false;
    for c in base.chars() {
        if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    let trimmed: String = out.trim_matches('_').chars().take(80).collect();
    if trimmed.is_empty() { "file".to_string() } else { trimmed }
}

fn strings_dump_dir(matches: &ArgMatches) -> std::path::PathBuf {
    match matches.get_one::<String>("case") {
        Some(case_name) => get_output_dir("cases").join(case_name).join("full_strings"),
        None => get_output_dir("full_strings"),
    }
}

/// Write one file's dump and register it with the case. Best-effort: a dump
/// that fails to write warns but never fails the scan or blocks the report.
fn write_strings_dump(result: &FileScanResult, name_hint: &str, matches: &ArgMatches, target: &str) {
    if matches.get_flag("no-strings-dump") {
        return;
    }
    let dir = strings_dump_dir(matches);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("{}", format!("Could not create {}: {}", dir.display(), e).yellow());
        return;
    }
    let stem = dump_stem(name_hint);
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let path = dir.join(format!("{}_strings_{}.txt", stem, timestamp));
    let (body, truncated) = format_strings_dump(&result.file_path, &result.sha256, &result.raw_strings, &result.matches, STRINGS_DUMP_CAP);
    match File::create(&path).and_then(|mut f| f.write_all(body.as_bytes())) {
        Ok(()) => {
            let note = if truncated { " (truncated at cap)" } else { "" };
            println!("{}", format!("Full strings saved to: {}{}", path.display(), note).green());
            if let Some(case_name) = matches.get_one::<String>("case") {
                common_config::register_case_output("full_strings", case_name, target, &path);
            }
        }
        Err(e) => eprintln!("{}", format!("Could not save full strings: {}", e).yellow()),
    }
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
    ip_lists: &[IpList],
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

    let (net_iocs, resolvers) = split_resolvers(net_iocs);
    let net_iocs = &net_iocs;
    if !net_iocs.is_empty() {
        if format == "md" {
            report_buffer.push_str("## Potential Network IOCs\n\n");
            for ioc in net_iocs {
                report_buffer.push_str(&format!("- `{}`\n", defang_network_ioc(ioc)));
            }
        } else {
            report_buffer.push_str("POTENTIAL NETWORK IOCs:\n");
            for ioc in net_iocs {
                report_buffer.push_str(&format!("{}\n", defang_network_ioc(ioc)));
            }
        }
        report_buffer.push('\n');
    }

    if !resolvers.is_empty() {
        let list = resolvers.iter().cloned().collect::<Vec<_>>().join(", ");
        if format == "md" {
            report_buffer.push_str("## Public DNS Resolvers Referenced (not C2)\n\n");
            report_buffer.push_str(&format!("`{}` — hardcoded for name resolution or connectivity checks.\n\n", list));
        } else {
            report_buffer.push_str(&format!("PUBLIC DNS RESOLVERS REFERENCED (not C2): {}\n\n", list));
        }
    }

    if !ip_lists.is_empty() {
        if format == "md" {
            report_buffer.push_str("## IP Address Lists (possible anti-analysis blocklist or C2 pool)\n\n");
            report_buffer.push_str(IP_LIST_NOTE);
            report_buffer.push_str("\n\n");
            for l in ip_lists {
                report_buffer.push_str(&format!("- **{} addresses** at 0x{:X}–0x{:X}: ", l.ips.len(), l.start, l.end));
                report_buffer.push_str(&l.ips.iter().map(|ip| format!("`{}`", defang_network_ioc(ip))).collect::<Vec<_>>().join(", "));
                report_buffer.push_str("\n");
            }
            report_buffer.push('\n');
        } else {
            for l in ip_lists {
                report_buffer.push_str(&format!(
                    "IP ADDRESS LIST ({} addresses at 0x{:X}-0x{:X}; possible anti-analysis blocklist or C2 pool, not listed as network IOCs): {}\n",
                    l.ips.len(), l.start, l.end,
                    l.ips.iter().map(|ip| defang_network_ioc(ip)).collect::<Vec<_>>().join(", ")
                ));
            }
            report_buffer.push('\n');
        }
    }
}

const IP_LIST_NOTE: &str = "These IPs are stored together as a list, so they are not counted as Network IOCs. An embedded run of IP addresses is most often a blocklist of sandbox and analysis hosts the sample checks for before it runs (stealers commonly carry one), and sometimes a pool of C2 servers. Look at the code or strings around it, or look the addresses up, before reporting any of them as C2.";

fn print_ip_lists(ip_lists: &[IpList]) {
    for l in ip_lists {
        println!(
            "{} {}",
            format!("IP ADDRESS LIST ({} addresses at 0x{:X}-0x{:X}; possible anti-analysis blocklist or C2 pool, not network IOCs):", l.ips.len(), l.start, l.end)
                .truecolor(RUST_ORANGE.0, RUST_ORANGE.1, RUST_ORANGE.2),
            l.ips.iter().map(|ip| defang_network_ioc(ip)).collect::<Vec<_>>().join(", ")
        );
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
    print_iocs("POTENTIAL FILESYSTEM IOCs:", &result.fs_iocs, false);

    if !result.net_iocs.is_empty() {
        println!("\n");
        print_net_iocs(&result.net_iocs);
    }
    print_ip_lists(&result.ip_lists);

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
            append_ioc_sections(&mut report_buffer, &result.fs_iocs, &result.net_iocs, &result.ip_lists, format);
            report_buffer
        };

        // Dump first, report second: the report stays the newest file mStrings
        // writes, in case anything downstream still looks for "the latest".
        write_strings_dump(&result, file_path_copy, matches, file_path_copy);
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
    let mut merged_ip_lists: Vec<IpList> = Vec::new();
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
        merged_ip_lists.extend(result.ip_lists.iter().cloned());
        scanned.push((rel_path, result, table_str));
    }

    // Combined IOC section across all binaries in the bundle
    println!("\n");
    print_iocs("POTENTIAL FILESYSTEM IOCs:", &merged_fs_iocs, false);

    if !merged_net_iocs.is_empty() {
        println!("\n");
        print_net_iocs(&merged_net_iocs);
    }
    print_ip_lists(&merged_ip_lists);

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

            append_ioc_sections(&mut report_buffer, &merged_fs_iocs, &merged_net_iocs, &merged_ip_lists, format);
            report_buffer
        };

        // One dump per embedded binary, named after its path inside the bundle.
        for (rel_path, result, _) in &scanned {
            write_strings_dump(result, &rel_path.replace('/', "_"), matches, file_path_copy);
        }
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
        .arg(
            Arg::new("no-strings-dump")
                .long("no-strings-dump")
                .num_args(0)
                .help("Don't save the full strings dump alongside a saved report"),
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

#[cfg(test)]
mod encoded_table_tests {
    use super::*;

    fn blob(offset: usize) -> Match {
        Match {
            offset,
            encoding: Encoding::Utf8,
            matched_str: "A".repeat(300),
            display_str: String::new(),
            decode_layers: 0,
            rule_name: Some(B64_BLOB_RULE.to_string()),
            tactic: None,
            technique: None,
            technique_id: None,
        }
    }

    #[test]
    fn few_blobs_are_not_a_table() {
        let m: Vec<Match> = (0..ENCODED_TABLE_MIN - 1).map(|i| blob(i * 400)).collect();
        assert!(encoded_string_table_row(&m, 1 << 20).is_none());
    }

    #[test]
    fn many_blobs_make_one_t1027_013_row() {
        let m: Vec<Match> = (0..100).map(|i| blob(0x1000 + i * 400)).collect();
        let r = encoded_string_table_row(&m, 100 * 400).expect("row");
        assert_eq!(r.technique_id, "T1027.013");
        assert_eq!(r.count, "100");
        assert!(r.matched_strings.contains("29 KB"), "{}", r.matched_strings);
        assert!(r.matched_strings.contains("75% of file"), "{}", r.matched_strings);
    }
}

#[cfg(test)]
mod strings_dump_tests {
    use super::*;

    fn raw(offset: usize, enc: &'static str, text: &str) -> RawString {
        RawString { offset, encoding: enc, text: text.to_string() }
    }

    fn decoded(offset: usize, text: &str) -> Match {
        Match {
            offset, encoding: Encoding::Base64, matched_str: text.to_string(),
            display_str: text.to_string(), decode_layers: 1, rule_name: None,
            tactic: None, technique: None, technique_id: None,
        }
    }

    #[test]
    fn dump_lists_every_string_with_offset_and_encoding() {
        let r = vec![raw(0xF0, "ascii", "lsass.exe"), raw(0x200, "utf16le", "mshta.exe")];
        let (out, truncated) = format_strings_dump("/x/90", "abc", &r, &[], STRINGS_DUMP_CAP);
        assert!(!truncated);
        assert!(out.contains("# SHA256:  abc"));
        assert!(out.contains("# Strings: 2 (1 ascii, 1 utf16le), 0 decoded"));
        assert!(out.contains("0x000000F0\tascii\tlsass.exe\n"));
        assert!(out.contains("0x00000200\tutf16le\tmshta.exe\n"));
        assert!(!out.contains("decoded (derived)"));
    }

    #[test]
    fn decoded_strings_are_labeled_and_deduplicated() {
        // Two Match copies of one decoded blob, as a two-technique rule makes.
        let m = vec![decoded(0x40, "powershell -nop"), decoded(0x40, "powershell -nop")];
        let (out, _) = format_strings_dump("f", "h", &[], &m, STRINGS_DUMP_CAP);
        assert!(out.contains("0 utf16le), 1 decoded"));
        assert!(out.contains("# --- decoded (derived)"));
        assert_eq!(out.matches("powershell -nop").count(), 1);
    }

    // Expected values are what the server's _rename_case_report produces for
    // the same names (checked against its Python regex), so each dump pairs
    // with its Analyze report by name.
    #[test]
    fn dump_stem_matches_server_report_naming() {
        assert_eq!(dump_stem("/x/90(2)"), "90_2");
        assert_eq!(dump_stem("%2f"), "2f");
        assert_eq!(dump_stem("%2f(1)"), "2f_1");
        assert_eq!(dump_stem("imgpaper.png"), "imgpaper");
        assert_eq!(dump_stem("90"), "90");
        assert_eq!(dump_stem("Contents_MacOS_Evil App"), "Contents_MacOS_Evil_App");
        assert_eq!(dump_stem("((()))"), "file");
    }

    #[test]
    fn embedded_tabs_and_newlines_stay_on_one_line() {
        let (out, _) = format_strings_dump("f", "h", &[raw(1, "ascii", "a\tb\nc")], &[], STRINGS_DUMP_CAP);
        assert!(out.contains("0x00000001\tascii\ta b c\n"));
    }

    #[test]
    fn dump_stops_at_cap_and_says_so() {
        let r: Vec<RawString> = (0..1000).map(|i| raw(i * 16, "ascii", "AAAAAAAAAAAAAAAAAAAA")).collect();
        let cap = 4096;
        let (out, truncated) = format_strings_dump("f", "h", &r, &[], cap);
        assert!(truncated);
        assert!(out.contains("# TRUNCATED at"));
        assert!(out.contains("of 1000 strings written"));
        // The cap bounds the strings; only the one-line truncation note may exceed it.
        let body_end = out.find("\n# TRUNCATED").unwrap();
        assert!(body_end <= cap, "body {} > cap {}", body_end, cap);
    }
}

#[cfg(test)]
mod detection_file_tests {
    use super::*;

    fn rules() -> HashMap<String, Detection> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../detections.yaml");
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    // apply_yara_detections skips a pattern that fails to compile, and a rule
    // with no technique never fires, both silently: catch either here.
    #[test]
    fn every_pattern_compiles_and_every_rule_can_fire() {
        let mut bad = Vec::new();
        for (key, det) in rules() {
            for p in &det.detection.strings {
                if let Err(e) = Regex::new(p) {
                    bad.push(format!("{key}: {p}: {e}"));
                }
            }
            if det.mitre.is_empty() && !det.ioc_only {
                bad.push(format!("{key}: no mitre entry and not ioc_only"));
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    fn techniques_for(line: &str, rule_title: &str) -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../detections.yaml");
        let mut ms = Mstrings::new();
        ms.process_line(line, 0);
        ms.apply_detections_from_yaml(&std::fs::read_to_string(path).unwrap()).unwrap();
        ms.matches.iter()
            .filter(|m| m.rule_name.as_deref() == Some(rule_title))
            .filter_map(|m| m.technique_id.clone())
            .collect()
    }

    // A rule with several mitre entries used to report only the first one:
    // the dedupe key was (rule, matched text), so the second technique's
    // Match was discarded as a duplicate.
    #[test]
    fn multi_technique_rule_reports_every_technique() {
        let mut ids = techniques_for("SELECT * FROM Win32_OperatingSystem", "WMI System Discovery Query");
        ids.sort();
        assert_eq!(ids, vec!["T1047", "T1082"]);
        let mut ids = techniques_for("LoadLibraryA", "Dynamic API Resolution via LoadLibrary and GetProcAddress");
        ids.sort();
        assert_eq!(ids, vec!["T1106", "T1129"]);
    }

    #[test]
    fn single_technique_rule_reports_once() {
        assert_eq!(techniques_for("nltest /domain_trusts", "Domain Trust Discovery"), vec!["T1482"]);
    }

    #[test]
    fn join_mitre_merges_cells() {
        let cells = vec![
            ("Execution, Discovery".to_string(), "Windows Management Instrumentation".to_string(), "T1047".to_string()),
            ("Discovery".to_string(), "System Information Discovery".to_string(), "T1082".to_string()),
        ];
        assert_eq!(join_mitre(&cells), (
            "Execution, Discovery".to_string(),
            "Windows Management Instrumentation; System Information Discovery".to_string(),
            "T1047, T1082".to_string(),
        ));
        let one = vec![("Discovery".to_string(), "Domain Trust Discovery".to_string(), "T1482".to_string())];
        assert_eq!(join_mitre(&one), ("Discovery".to_string(), "Domain Trust Discovery".to_string(), "T1482".to_string()));
        assert_eq!(join_mitre(&[]), (String::new(), String::new(), String::new()));
    }

    fn hits(key: &str, s: &str) -> bool {
        let r = rules();
        r[key].detection.strings.iter().any(|p| Regex::new(p).unwrap().is_match(s).unwrap())
    }

    #[test]
    fn tightened_rules() {
        // Protocol tables and option syntax are not usage.
        assert!(!hits("TelnetLateralMovement", "telnet\t\t23/tcp"));
        assert!(!hits("TelnetLateralMovement", "[,server][,nowait][,telnet][,websocket]"));
        assert!(hits("TelnetLateralMovement", "telnet 192.168.1.1 23"));
        assert!(hits("TelnetLateralMovement", "/usr/sbin/telnetd"));
        assert!(hits("TelnetLateralMovement", "telnet evil.example.com 23"));
        assert!(!hits("TelnetLateralMovement", "--telnet-option <opt=val> Set telnet option"));
        assert!(!hits("HardcodedIPAddress", "2.5.29.37"));
        assert!(hits("HttpPostExfiltration", "Content-Type                multipart/form-data;boundary=jeus"));
        assert!(hits("HttpPostExfiltration", "multipart/form-data; boundary=%s"));
        assert!(hits("HttpPostExfiltration", "POST /gate.php HTTP/1.1"));
        assert!(!hits("HttpPostExfiltration", "multipart/form-data"));
        assert!(!hits("HttpPostExfiltration", "multipart/form-data; boundary=missingrequired"));
        assert!(!hits("HttpPostExfiltration", "Content-Type: %s%s%s ; boundary="));
        assert!(!hits("HttpPostExfiltration", "%s %s HTTP/1.1"));
        assert!(!hits("HttpPostExfiltration", " POST /api2/"));
        assert!(!hits("TftpIngressTransfer", "tftp\t\t69/udp"));
        assert!(!hits("TftpIngressTransfer", "[,tftp=dir][,tftp-server-name=name]"));
        assert!(hits("TftpIngressTransfer", "tftp -g -l dvrHelper -r mips 1.2.3.4"));
        assert!(!hits("CredentialStrings", "-iscsi [user=user][,password=password]"));
        assert!(!hits("CredentialStrings", "[,sasl][,password=<secret>]"));
        assert!(!hits("CredentialStrings", "x509-key-password=<file>"));
        assert!(hits("CredentialStrings", "password=hunter2"));
        assert!(!hits("MacSandboxVMEvasion", "separatorSpecstartParallelstop signal"));
        // Private addresses are IOC-only; public ones still map to C2.
        assert!(!hits("HardcodedIPAddress", "10.3.180.65"));
        assert!(!hits("HardcodedIPAddress", "192.168.0.1"));
        assert!(!hits("HardcodedIPAddress", "172.20.1.1"));
        assert!(hits("HardcodedIPAddress", "172.32.1.1"));
        assert!(hits("HardcodedIPAddress", "147.75.70.221"));
        assert!(hits("HardcodedPrivateIPAddress", "10.3.180.65"));
        assert!(hits("HardcodedPrivateIPAddress", "192.168.0.1"));
        assert!(!hits("HardcodedPrivateIPAddress", "192.168.0.0"));
        assert!(!hits("HardcodedPrivateIPAddress", "147.75.70.221"));
    }
}
