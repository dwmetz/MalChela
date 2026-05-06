use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use colored::*;
use common_ui::styled_line;
use common_config::get_output_dir;
use clap::{Arg, Command};

// ── Code Signature superblob magic values (big-endian) ────────────────────────
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
const CSMAGIC_CODEDIRECTORY:      u32 = 0xFADE_0C02;
const CSMAGIC_BLOBWRAPPER:        u32 = 0xFADE_0B01; // CMS Signed Data — absent = ad-hoc
const CSMAGIC_ENTITLEMENTS:       u32 = 0xFADE_7171;
const CS_ADHOC:                   u32 = 0x0002;      // CodeDirectory flags bit

fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok()
}

// ── Result of parsing one Mach-O slice's code signature ───────────────────────
#[derive(Default)]
struct CsInfo {
    found:             bool,
    is_adhoc:          bool,
    has_cms:           bool,  // real certificate chain present
    bundle_id:         Option<String>,
    team_id:           Option<String>,
    cd_version:        Option<u32>,
    cd_flags:          Option<u32>,
    has_entitlements:  bool,
    task_allow:        bool,  // get-task-allow entitlement (dev/debug build)
}

// ── Parse a code-signature superblob from raw bytes ───────────────────────────
// `blob` is the slice starting at the superblob (file_bytes[arch_offset + dataoff..])
fn parse_superblob(blob: &[u8]) -> CsInfo {
    let mut info = CsInfo::default();
    if blob.len() < 12 { return info; }

    let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != CSMAGIC_EMBEDDED_SIGNATURE { return info; }
    info.found = true;

    let count = u32::from_be_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;

    for i in 0..count {
        let ix = 12 + i * 8;
        if ix + 8 > blob.len() { break; }
        let blob_offset = u32::from_be_bytes([blob[ix+4], blob[ix+5], blob[ix+6], blob[ix+7]]) as usize;
        if blob_offset + 8 > blob.len() { continue; }

        let blob_magic = u32::from_be_bytes([
            blob[blob_offset], blob[blob_offset+1],
            blob[blob_offset+2], blob[blob_offset+3],
        ]);

        match blob_magic {
            m if m == CSMAGIC_BLOBWRAPPER => {
                info.has_cms = true;
            }
            m if m == CSMAGIC_CODEDIRECTORY => {
                parse_code_directory(&blob[blob_offset..], &mut info);
            }
            m if m == CSMAGIC_ENTITLEMENTS => {
                info.has_entitlements = true;
                // Entitlements blob: 8-byte header, then XML plist
                if blob_offset + 8 < blob.len() {
                    let blob_len = u32::from_be_bytes([
                        blob[blob_offset+4], blob[blob_offset+5],
                        blob[blob_offset+6], blob[blob_offset+7],
                    ]) as usize;
                    let xml_end = (blob_offset + blob_len).min(blob.len());
                    if let Ok(xml) = std::str::from_utf8(&blob[blob_offset+8..xml_end]) {
                        if xml.contains("get-task-allow") && xml.contains("<true/>") {
                            info.task_allow = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    info
}

fn parse_code_directory(cd: &[u8], info: &mut CsInfo) {
    if cd.len() < 44 { return; }

    let version     = u32::from_be_bytes([cd[8],  cd[9],  cd[10], cd[11]]);
    let flags       = u32::from_be_bytes([cd[12], cd[13], cd[14], cd[15]]);
    let ident_off   = u32::from_be_bytes([cd[20], cd[21], cd[22], cd[23]]) as usize;

    info.cd_version = Some(version);
    info.cd_flags   = Some(flags);
    info.is_adhoc   = (flags & CS_ADHOC) != 0;

    // Bundle identifier: null-terminated string at ident_off within the CD blob
    if ident_off < cd.len() {
        if let Some(end) = cd[ident_off..].iter().position(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(&cd[ident_off..ident_off + end]) {
                if !s.is_empty() {
                    info.bundle_id = Some(s.to_string());
                }
            }
        }
    }

    // Team ID: present in CodeDirectory version >= 0x20200 at byte offset 48
    if version >= 0x20200 && cd.len() >= 52 {
        let team_off = u32::from_be_bytes([cd[48], cd[49], cd[50], cd[51]]) as usize;
        if team_off > 0 && team_off < cd.len() {
            if let Some(end) = cd[team_off..].iter().position(|&b| b == 0) {
                if let Ok(s) = std::str::from_utf8(&cd[team_off..team_off + end]) {
                    if !s.is_empty() {
                        info.team_id = Some(s.to_string());
                    }
                }
            }
        }
    }
}

// ── Extract CsInfo from a Mach-O binary file ──────────────────────────────────
// arch_offset: byte offset within `data` where this Mach-O slice begins (0 for thin)
fn codesign_from_macho(data: &[u8], arch_offset: usize) -> CsInfo {
    let slice = &data[arch_offset..];
    match goblin::mach::MachO::parse(slice, 0) {
        Ok(macho) => {
            for lc in &macho.load_commands {
                if let goblin::mach::load_command::CommandVariant::CodeSignature(cs) = lc.command {
                    let off  = arch_offset + cs.dataoff as usize;
                    let size = cs.datasize as usize;
                    if off + size <= data.len() {
                        return parse_superblob(&data[off..off + size]);
                    }
                }
            }
            CsInfo::default()
        }
        Err(_) => CsInfo::default(),
    }
}

// ── Resolve input to (binary_path, codesig_dir, display_name) ─────────────────
fn resolve_input(input: &Path) -> (Option<PathBuf>, Option<PathBuf>, String) {
    if input.is_dir() {
        // .app bundle: read Info.plist for CFBundleExecutable
        let info_plist = input.join("Contents/Info.plist");
        let codesig_dir = input.join("Contents/_CodeSignature");
        let display = input.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| input.display().to_string());

        let binary = plist::from_file::<_, plist::Dictionary>(&info_plist).ok()
            .and_then(|d| d.get("CFBundleExecutable")?.as_string().map(String::from))
            .map(|name| input.join("Contents/MacOS").join(name));

        (binary, Some(codesig_dir), display)
    } else if input.is_file() {
        // Binary file: look for _CodeSignature two levels up (Contents/_CodeSignature)
        let codesig_dir = input.parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("_CodeSignature"))
            .filter(|p| p.exists());
        let display = input.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| input.display().to_string());
        (Some(input.to_path_buf()), codesig_dir, display)
    } else {
        (None, None, input.display().to_string())
    }
}

// ── Output helpers ─────────────────────────────────────────────────────────────
fn flag(label: &str, value: &str, color: &str) {
    let colored_val = match color {
        "green"  => value.green().to_string(),
        "red"    => value.red().to_string(),
        "yellow" => value.yellow().to_string(),
        "cyan"   => value.cyan().to_string(),
        _        => value.normal().to_string(),
    };
    println!("  {:<26}{}", label.cyan(), colored_val);
}

fn flag_str(label: &str, value: &str) {
    println!("  {:<26}{}", label.cyan(), value);
}

fn warn(msg: &str) {
    println!("  {}", format!("⚠  {}", msg).yellow());
}

fn ok(msg: &str) {
    println!("  {}", format!("✓  {}", msg).green());
}

// ── Build plain-text report for saving ────────────────────────────────────────
fn build_report(
    display_name: &str,
    binary_path:  Option<&Path>,
    codesig_dir:  Option<&PathBuf>,
    cs:           &CsInfo,
    flags_text:   &[String],
    format:       &str,
) -> String {
    let mut buf = String::new();

    let header = format!("codesign_check — {}", display_name);
    if format == "md" {
        buf.push_str(&format!("# {}\n\n", header));
        if let Some(p) = binary_path { buf.push_str(&format!("**Binary:** `{}`  \n", p.display())); }
        buf.push('\n');
        buf.push_str("## Code Signature Summary\n\n");

        let sig_status = if !cs.found { "None (unsigned)"
        } else if cs.is_adhoc || !cs.has_cms { "Ad-hoc (not developer-signed)"
        } else { "Developer-signed (CMS present)" };
        buf.push_str(&format!("| Field | Value |\n|---|---|\n"));
        buf.push_str(&format!("| Signature | {} |\n", sig_status));
        if let Some(bid) = &cs.bundle_id { buf.push_str(&format!("| Bundle ID | `{}` |\n", bid)); }
        if let Some(tid) = &cs.team_id   { buf.push_str(&format!("| Team ID | `{}` |\n", tid)); }
        if let Some(v) = cs.cd_version   { buf.push_str(&format!("| CD Version | `{:#010x}` |\n", v)); }
        buf.push_str(&format!("| Entitlements | {} |\n", if cs.has_entitlements { "Yes" } else { "No" }));
        if cs.task_allow { buf.push_str("| get-task-allow | Yes (debug build) |\n"); }

        let cs_dir_exists = codesig_dir.map(|d| d.exists()).unwrap_or(false);
        buf.push_str(&format!("| _CodeSignature/ | {} |\n\n", if cs_dir_exists { "Present" } else { "Absent" }));

        if !flags_text.is_empty() {
            buf.push_str("## Flags\n\n");
            for f in flags_text { buf.push_str(&format!("- {}\n", f)); }
        }
    } else {
        buf.push_str(&format!("{}\n{}\n\n", header, "=".repeat(header.len())));
        if let Some(p) = binary_path { buf.push_str(&format!("Binary: {}\n\n", p.display())); }

        let sig_status = if !cs.found { "None (unsigned)"
        } else if cs.is_adhoc || !cs.has_cms { "Ad-hoc (not developer-signed)"
        } else { "Developer-signed (CMS present)" };
        buf.push_str(&format!("Signature:           {}\n", sig_status));
        if let Some(bid) = &cs.bundle_id { buf.push_str(&format!("Bundle ID:           {}\n", bid)); }
        if let Some(tid) = &cs.team_id   { buf.push_str(&format!("Team ID:             {}\n", tid)); }
        if let Some(v) = cs.cd_version   { buf.push_str(&format!("CD Version:          {:#010x}\n", v)); }
        buf.push_str(&format!("Entitlements:        {}\n", if cs.has_entitlements { "Yes" } else { "No" }));
        if cs.task_allow { buf.push_str("get-task-allow:      Yes (debug build)\n"); }
        let cs_dir_exists = codesig_dir.map(|d| d.exists()).unwrap_or(false);
        buf.push_str(&format!("_CodeSignature/:     {}\n", if cs_dir_exists { "Present" } else { "Absent" }));

        if !flags_text.is_empty() {
            buf.push_str("\nFlags:\n");
            for f in flags_text { buf.push_str(&format!("  {}\n", f)); }
        }
    }
    buf
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Command::new("codesign_check")
        .version("4.1.0")
        .about("Inspect macOS code signing: signature type, team ID, entitlements, ad-hoc detection")
        .arg(Arg::new("input").help("Path to .app bundle or Mach-O binary").index(1))
        .arg(Arg::new("output").short('o').long("output").num_args(0).help("Save output"))
        .arg(Arg::new("text").short('t').long("text").action(clap::ArgAction::SetTrue)
            .conflicts_with_all(&["json","markdown"]))
        .arg(Arg::new("markdown").short('m').long("markdown").action(clap::ArgAction::SetTrue)
            .conflicts_with_all(&["text","json"]))
        .arg(Arg::new("case").long("case").num_args(1).help("Case name for output grouping"))
        .get_matches();

    // ── Resolve input path ────────────────────────────────────────────────────
    let input_str = match args.get_one::<String>("input").map(String::as_str) {
        Some(p) => p.to_string(),
        None => {
            print!("Enter path to .app bundle or Mach-O binary: ");
            io::stdout().flush()?;
            let mut s = String::new();
            io::stdin().read_line(&mut s)?;
            s.trim().to_string()
        }
    };

    let input_path = PathBuf::from(&input_str);
    if !input_path.exists() {
        eprintln!("{}", format!("Error: path not found: {}", input_str).red());
        std::process::exit(1);
    }

    let (binary_path, codesig_dir, display_name) = resolve_input(&input_path);

    // ── Header ────────────────────────────────────────────────────────────────
    println!("{}", styled_line("cyan", &format!("codesign_check — {}", display_name)));
    if let Some(ref bp) = binary_path {
        println!("{}", styled_line("stone", &format!("Binary: {}", bp.display())));
    }
    println!();

    // ── _CodeSignature/ directory check ───────────────────────────────────────
    let cs_dir_exists = codesig_dir.as_ref().map(|d| d.exists()).unwrap_or(false);
    let cs_resources  = codesig_dir.as_ref()
        .map(|d| d.join("CodeResources"))
        .filter(|p| p.exists());

    println!("{}", styled_line("SECTION", "Code Signature Directory"));
    flag("_CodeSignature/ present:", if cs_dir_exists { "Yes" } else { "No" },
         if cs_dir_exists { "green" } else { "red" });
    flag("CodeResources present:", if cs_resources.is_some() { "Yes" } else { "No" },
         if cs_resources.is_some() { "green" } else { "red" });
    println!();

    // ── Parse Mach-O code signature ───────────────────────────────────────────
    let cs = if let Some(ref bp) = binary_path {
        match fs::read(bp) {
            Ok(data) => {
                use goblin::Object;
                match Object::parse(&data) {
                    Ok(Object::Mach(goblin::mach::Mach::Fat(fat))) => {
                        // Fat/universal binary — use first arch
                        let arch_offset = fat.arches().ok()
                            .and_then(|a| a.into_iter().next())
                            .map(|a| a.offset as usize)
                            .unwrap_or(0);
                        codesign_from_macho(&data, arch_offset)
                    }
                    Ok(Object::Mach(goblin::mach::Mach::Binary(_))) => {
                        codesign_from_macho(&data, 0)
                    }
                    _ => {
                        println!("{}", "  Not a Mach-O binary".yellow());
                        CsInfo::default()
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("  Could not read binary: {}", e).red());
                CsInfo::default()
            }
        }
    } else {
        println!("{}", "  No binary found — bundle Info.plist missing or unresolvable".yellow());
        CsInfo::default()
    };

    // ── Signature summary ─────────────────────────────────────────────────────
    println!("{}", styled_line("SECTION", "Signature"));

    let sig_label = if !cs_dir_exists && !cs.found {
        flag("Status:", "UNSIGNED", "red");
        "UNSIGNED".to_string()
    } else if cs.found && cs.has_cms && !cs.is_adhoc {
        flag("Status:", "Developer-signed", "green");
        "Developer-signed".to_string()
    } else if cs.found && (cs.is_adhoc || !cs.has_cms) {
        flag("Status:", "Ad-hoc (no certificate chain)", "yellow");
        "Ad-hoc".to_string()
    } else if cs_dir_exists && !cs.found {
        flag("Status:", "_CodeSignature/ present but no valid superblob", "yellow");
        "Incomplete".to_string()
    } else {
        flag("Status:", "Unknown", "yellow");
        "Unknown".to_string()
    };

    if let Some(ref bid) = cs.bundle_id {
        flag_str("Bundle ID:", bid);
    }
    if let Some(ref tid) = cs.team_id {
        flag("Team ID:", tid, "cyan");
    } else if cs.found {
        flag("Team ID:", "Not present", "yellow");
    }
    if let Some(v) = cs.cd_version {
        flag_str("CD Version:", &format!("{:#010x}", v));
    }
    println!();

    // ── Entitlements ──────────────────────────────────────────────────────────
    println!("{}", styled_line("SECTION", "Entitlements"));
    flag("Present:", if cs.has_entitlements { "Yes" } else { "No" },
         if cs.has_entitlements { "cyan" } else { "normal" });
    if cs.task_allow {
        flag("get-task-allow:", "Yes  (debug/dev build — allows task port access)", "yellow");
    }
    println!();

    // ── Flags / indicators ────────────────────────────────────────────────────
    println!("{}", styled_line("SECTION", "Indicators"));
    let mut flags_text: Vec<String> = Vec::new();
    let mut any_flag = false;

    if !cs_dir_exists {
        warn("No _CodeSignature/ directory — binary is unsigned");
        flags_text.push("Unsigned: no _CodeSignature/ directory".into());
        any_flag = true;
    }
    if cs.found && !cs.has_cms {
        warn("No CMS blob — ad-hoc signature (not from a developer account)");
        flags_text.push("Ad-hoc signature: no CMS certificate chain".into());
        any_flag = true;
    }
    if cs.found && cs.is_adhoc {
        warn("CS_ADHOC flag set in CodeDirectory");
        flags_text.push("CS_ADHOC flag set in CodeDirectory".into());
        any_flag = true;
    }
    if cs.team_id.is_none() && cs.found {
        warn("No Team ID — ad-hoc, self-signed, or very old signing format");
        flags_text.push("No Team ID present".into());
        any_flag = true;
    }
    if cs.task_allow {
        warn("get-task-allow entitlement present — debug build, not App Store / notarized");
        flags_text.push("get-task-allow entitlement (debug build)".into());
        any_flag = true;
    }
    if !any_flag {
        ok("No suspicious indicators");
    }
    println!();

    // ── Save output ───────────────────────────────────────────────────────────
    let save = args.get_flag("output") || args.contains_id("case");
    if save {
        let fmt = if args.get_flag("text") { "txt" } else { "md" };
        let output_dir = match args.get_one::<String>("case") {
            Some(case_name) => {
                common_config::ensure_case_json(case_name);
                get_output_dir("cases").join(case_name).join("codesign_check")
            }
            None => get_output_dir("codesign_check"),
        };
        fs::create_dir_all(&output_dir)?;
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("report_{}.{}", ts, fmt);
        let report = build_report(
            &display_name,
            binary_path.as_deref(),
            codesig_dir.as_ref(),
            &cs,
            &flags_text,
            fmt,
        );
        let out_path = output_dir.join(&filename);
        fs::write(&out_path, &report)?;
        println!("{}", format!("Report saved to: {}", out_path.display()).green());

        // Signal GUI save
        if is_gui_mode() {
            println!("SAVED_TO_CASE:{}", out_path.display());
        }
    } else if !is_gui_mode() {
        println!("Output was not saved.");
    }

    let _ = sig_label; // suppress unused warning
    Ok(())
}
