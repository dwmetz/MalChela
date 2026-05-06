use clap::Parser;
use common_config::get_output_dir;
use common_ui::styled_line;
use plist::Value;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok() && std::env::var("MALCHELA_WORKSPACE_MODE").is_err()
}

fn plain_text(s: &str) -> String {
    let stripped = strip_ansi_escapes::strip_str(s);
    stripped
        .lines()
        .map(|line| {
            if line.starts_with('[') {
                if let Some(end) = line.find(']') {
                    return line[end + 1..].to_string();
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Parser)]
#[command(name = "plist_analyzer", about = "Parses macOS .plist files and .app bundle Info.plist for malware indicators.")]
struct Args {
    #[arg(help = "Path to a .plist file or .app bundle directory")]
    input: Option<String>,

    #[arg(short, long, help = "Save output to file")]
    output: bool,

    #[arg(short = 't', long, help = "Save as TXT format")]
    text: bool,

    #[arg(short = 'j', long, help = "Save as JSON format")]
    json: bool,

    #[arg(short = 'm', long, help = "Save as Markdown format")]
    markdown: bool,

    #[arg(long, help = "Optional case name for routing output")]
    case: Option<String>,
}

#[derive(Serialize)]
struct PlistReport {
    plist_path: String,
    bundle_executable: Option<String>,
    bundle_identifier: Option<String>,
    bundle_version: Option<String>,
    ls_ui_element: Option<bool>,
    ls_background_only: Option<bool>,
    ls_environment: Option<HashMap<String, String>>,
    ns_principal_class: Option<String>,
    executable_present: Option<bool>,
    executable_path: Option<String>,
    executable_mismatch: bool,
    flags: Vec<String>,
    all_keys: HashMap<String, String>,
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Boolean(b) => b.to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Array(arr) => format!("[{}]", arr.iter().map(value_to_string).collect::<Vec<_>>().join(", ")),
        Value::Dictionary(d) => format!(
            "{{{}}}",
            d.iter()
                .map(|(k, v)| format!("{}: {}", k, value_to_string(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Data(bytes) => format!("<{} bytes of binary data>", bytes.len()),
        Value::Date(dt) => dt.to_xml_format(),
        Value::Uid(uid) => format!("UID({})", uid.get()),
        _ => "<unknown>".to_string(),
    }
}

fn resolve_plist_path(input: &str) -> Option<PathBuf> {
    let p = Path::new(input);
    if p.is_file() {
        return Some(p.to_path_buf());
    }
    if p.is_dir() {
        // Try .app bundle structure
        let candidate = p.join("Contents").join("Info.plist");
        if candidate.exists() {
            return Some(candidate);
        }
        // Try direct plist in dir
        for entry in fs::read_dir(p).ok()?.flatten() {
            let ep = entry.path();
            if ep.extension().and_then(|e| e.to_str()) == Some("plist") {
                return Some(ep);
            }
        }
    }
    None
}

fn main() {
    let args = Args::parse();

    let input = match args.input {
        Some(p) => p,
        None => {
            let line = styled_line("yellow", "\nEnter the path to the .plist file or .app bundle:");
            println!("{}", line);
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).expect("Failed to read input");
            s.trim_end_matches(&['\n', '\r'][..]).to_string()
        }
    };

    let plist_path = match resolve_plist_path(&input) {
        Some(p) => p,
        None => {
            println!("{}", styled_line("yellow", "Could not find a .plist file at the given path."));
            return;
        }
    };

    println!();

    let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
    let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");

    let line = styled_line("NOTE", "--- Plist Analyzer ---");
    println!("{}", line);
    writeln!(temp_file, "{}", plain_text(&line)).ok();

    let line = styled_line("stone", &format!("Plist: {}", plist_path.display()));
    println!("{}", line);
    writeln!(temp_file, "{}", plain_text(&line)).ok();

    let dict = match plist::from_file::<_, plist::Dictionary>(&plist_path) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", styled_line("yellow", &format!("Failed to parse plist: {}", e)));
            return;
        }
    };

    // Extract fields of interest
    let bundle_executable = dict.get("CFBundleExecutable").and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    });
    let bundle_identifier = dict.get("CFBundleIdentifier").and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    });
    let bundle_version = dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None });
    let ls_ui_element = dict.get("LSUIElement")
        .or_else(|| dict.get("NSUIElement"))   // legacy key used by older/macOS 10.7-era bundles
        .and_then(|v| {
            match v {
                Value::Boolean(b) => Some(*b),
                Value::Integer(i) => i.as_signed().map(|n| n != 0),
                Value::String(s) if s == "1" || s.eq_ignore_ascii_case("true") => Some(true),
                Value::String(s) if s == "0" || s.eq_ignore_ascii_case("false") => Some(false),
                _ => None,
            }
        });
    let ls_background_only = dict.get("LSBackgroundOnly").and_then(|v| {
        match v {
            Value::Boolean(b) => Some(*b),
            Value::String(s) if s == "1" || s.eq_ignore_ascii_case("true") => Some(true),
            _ => None,
        }
    });
    let ns_principal_class = dict.get("NSPrincipalClass").and_then(|v| {
        if let Value::String(s) = v { Some(s.clone()) } else { None }
    });
    let ls_environment: Option<HashMap<String, String>> = dict.get("LSEnvironment").and_then(|v| {
        if let Value::Dictionary(d) = v {
            Some(d.iter().map(|(k, v)| (k.clone(), value_to_string(v))).collect())
        } else {
            None
        }
    });

    // NSAllowsArbitraryLoads inside NSAppTransportSecurity
    let allows_arbitrary_loads = dict.get("NSAppTransportSecurity")
        .and_then(|v| if let Value::Dictionary(ats) = v { Some(ats) } else { None })
        .and_then(|ats| ats.get("NSAllowsArbitraryLoads"))
        .and_then(|v| match v {
            Value::Boolean(b) => Some(*b),
            Value::Integer(i) => i.as_signed().map(|n| n != 0),
            Value::String(s) if s == "1" || s.eq_ignore_ascii_case("true") => Some(true),
            _ => None,
        });

    // Custom URL schemes from CFBundleURLTypes
    let url_schemes: Vec<String> = dict.get("CFBundleURLTypes")
        .and_then(|v| if let Value::Array(arr) = v { Some(arr) } else { None })
        .map(|arr| {
            arr.iter().filter_map(|t| {
                if let Value::Dictionary(d) = t {
                    d.get("CFBundleURLSchemes").and_then(|s| {
                        if let Value::Array(schemes) = s {
                            Some(schemes.iter().filter_map(|v| {
                                if let Value::String(s) = v { Some(s.clone()) } else { None }
                            }).collect::<Vec<_>>())
                        } else { None }
                    })
                } else { None }
            }).flatten().collect()
        })
        .unwrap_or_default();

    // CFBundleSignature (legacy creator code — '????' means unset)
    let bundle_signature = dict.get("CFBundleSignature")
        .and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None });

    // Collect all keys for the report
    let all_keys: HashMap<String, String> = dict
        .iter()
        .map(|(k, v)| (k.clone(), value_to_string(v)))
        .collect();

    // Check if CFBundleExecutable matches Contents/MacOS/
    let (executable_present, executable_path, executable_mismatch) = if let Some(ref exe_name) = bundle_executable {
        let macos_dir = plist_path
            .parent() // Contents/
            .map(|p| p.join("MacOS"))
            .unwrap_or_else(|| PathBuf::from("Contents/MacOS"));
        let expected = macos_dir.join(exe_name);
        let present = expected.exists();
        let mismatch = if macos_dir.is_dir() {
            // Check if there are extra binaries not matching CFBundleExecutable
            let extra_binaries: Vec<_> = fs::read_dir(&macos_dir)
                .map(|rd| {
                    rd.flatten()
                        .filter(|e| e.path().is_file())
                        .filter(|e| {
                            e.path().file_name().and_then(|n| n.to_str()) != Some(exe_name.as_str())
                        })
                        .map(|e| e.path().file_name().unwrap_or_default().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default();
            !extra_binaries.is_empty()
        } else {
            false
        };
        (Some(present), Some(expected.to_string_lossy().to_string()), mismatch)
    } else {
        (None, None, false)
    };

    // Build flags list
    let mut flags: Vec<String> = Vec::new();
    if ls_ui_element == Some(true) {
        flags.push("LSUIElement=true: App hidden from Dock (background/stealth)".to_string());
    }
    if ls_background_only == Some(true) {
        flags.push("LSBackgroundOnly=true: App runs only in background".to_string());
    }
    if ls_environment.is_some() {
        flags.push("LSEnvironment present: Malware may inject env vars at launch".to_string());
    }
    if executable_present == Some(false) {
        flags.push(format!(
            "CFBundleExecutable '{}' not found in Contents/MacOS/",
            bundle_executable.as_deref().unwrap_or("?")
        ));
    }
    if executable_mismatch {
        flags.push("Extra binaries found in Contents/MacOS/ beyond CFBundleExecutable".to_string());
    }
    if allows_arbitrary_loads == Some(true) {
        flags.push("NSAllowsArbitraryLoads=true: App Transport Security disabled — allows unencrypted HTTP connections".to_string());
    }
    if !url_schemes.is_empty() {
        flags.push(format!(
            "CFBundleURLTypes registers custom URL scheme(s): {} — may be used for persistence or IPC",
            url_schemes.join(", ")
        ));
    }
    if bundle_signature.as_deref() == Some("????") {
        flags.push("CFBundleSignature='????' — no creator code set, common in unsigned tools and malware".to_string());
    }

    // Print bundle metadata
    println!();
    writeln!(temp_file).ok();
    let heading = styled_line("NOTE", "--- Bundle Metadata ---");
    println!("{}", heading);
    writeln!(temp_file, "{}", plain_text(&heading)).ok();

    macro_rules! print_field {
        ($label:expr, $val:expr) => {
            if let Some(ref v) = $val {
                let line = styled_line("stone", &format!("  {}: {}", $label, v));
                println!("{}", line);
                writeln!(temp_file, "{}", plain_text(&line)).ok();
            }
        };
    }

    print_field!("CFBundleExecutable", bundle_executable);
    print_field!("CFBundleIdentifier", bundle_identifier);
    print_field!("CFBundleVersion", bundle_version);
    print_field!("NSPrincipalClass", ns_principal_class);

    {
        let val = ls_ui_element.map(|b| b.to_string());
        let color = if ls_ui_element == Some(true) { "yellow" } else { "stone" };
        if let Some(ref v) = val {
            let line = styled_line(color, &format!("  LSUIElement: {}", v));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    {
        let val = ls_background_only.map(|b| b.to_string());
        let color = if ls_background_only == Some(true) { "yellow" } else { "stone" };
        if let Some(ref v) = val {
            let line = styled_line(color, &format!("  LSBackgroundOnly: {}", v));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    if let Some(ref env_map) = ls_environment {
        let line = styled_line("yellow", "  LSEnvironment:");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
        for (k, v) in env_map {
            let line = styled_line("yellow", &format!("    {}: {}", k, v));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    // Executable check
    println!();
    writeln!(temp_file).ok();
    let heading = styled_line("NOTE", "--- Executable Verification ---");
    println!("{}", heading);
    writeln!(temp_file, "{}", plain_text(&heading)).ok();

    if let (Some(present), Some(ref path)) = (executable_present, &executable_path) {
        let status = if present { "Found" } else { "MISSING" };
        let color = if present { "stone" } else { "red" };
        let line = styled_line(color, &format!("  CFBundleExecutable binary: {} ({})", status, path));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }
    if executable_mismatch {
        let line = styled_line("yellow", "  WARNING: Extra binaries found in Contents/MacOS/");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    // Print all plist keys
    println!();
    writeln!(temp_file).ok();
    let heading = styled_line("NOTE", "--- All Plist Keys ---");
    println!("{}", heading);
    writeln!(temp_file, "{}", plain_text(&heading)).ok();

    let mut sorted_keys: Vec<_> = dict.iter().collect();
    sorted_keys.sort_by_key(|(k, _)| k.as_str());
    for (k, v) in &sorted_keys {
        let line = styled_line("stone", &format!("  {}: {}", k, value_to_string(v)));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    // Print flags
    if !flags.is_empty() {
        println!();
        writeln!(temp_file).ok();
        let heading = styled_line("NOTE", "--- Flags / Indicators ---");
        println!("{}", heading);
        writeln!(temp_file, "{}", plain_text(&heading)).ok();
        for flag in &flags {
            let line = styled_line("yellow", &format!("  [!] {}", flag));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    } else {
        println!();
        writeln!(temp_file).ok();
        let line = styled_line("stone", "No suspicious plist indicators found.");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    temp_file.flush().expect("Failed to flush temp file");

    if args.output {
        let output_dir = if let Some(ref case) = args.case {
            common_config::ensure_case_json(case);
            let path = format!("saved_output/cases/{}/plist_analyzer", case);
            std::fs::create_dir_all(&path).expect("Failed to create case output directory");
            std::path::PathBuf::from(path)
        } else {
            let path = get_output_dir("plist_analyzer");
            std::fs::create_dir_all(&path).expect("Failed to create default output directory");
            path
        };

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let format = if args.text { "txt" } else if args.json { "json" } else { "md" };

        let report = PlistReport {
            plist_path: plist_path.to_string_lossy().to_string(),
            bundle_executable: bundle_executable.clone(),
            bundle_identifier: bundle_identifier.clone(),
            bundle_version: bundle_version.clone(),
            ls_ui_element,
            ls_background_only,
            ls_environment: ls_environment.clone(),
            ns_principal_class: ns_principal_class.clone(),
            executable_present,
            executable_path: executable_path.clone(),
            executable_mismatch,
            flags: flags.clone(),
            all_keys: all_keys.clone(),
        };

        let out_path = match format {
            "txt" => output_dir.join(format!("report_{}.txt", timestamp)),
            "json" => output_dir.join(format!("report_{}.json", timestamp)),
            _ => output_dir.join(format!("report_{}.md", timestamp)),
        };

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create output directories");
        }

        match format {
            "txt" => {
                fs::copy(&temp_path, &out_path).expect("Failed to save text report");
                println!("\n{}\n", styled_line("green", &format!("Text report saved to: {}", out_path.display())));
            }
            "json" => {
                let json = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
                let mut f = File::create(&out_path).expect("Failed to create JSON report");
                f.write_all(json.as_bytes()).expect("Failed to write JSON report");
                println!("\n{}\n", styled_line("green", &format!("JSON report saved to: {}", out_path.display())));
            }
            _ => {
                let mut md = String::new();
                md.push_str("# Plist Analyzer Report\n\n");
                md.push_str(&format!("**File:** `{}`\n\n", plist_path.display()));
                md.push_str("## Bundle Metadata\n\n");
                md.push_str("| Key | Value |\n|-----|-------|\n");
                if let Some(ref v) = report.bundle_executable { md.push_str(&format!("| CFBundleExecutable | `{}` |\n", v)); }
                if let Some(ref v) = report.bundle_identifier { md.push_str(&format!("| CFBundleIdentifier | `{}` |\n", v)); }
                if let Some(ref v) = report.bundle_version { md.push_str(&format!("| CFBundleVersion | `{}` |\n", v)); }
                if let Some(v) = report.ls_ui_element { md.push_str(&format!("| LSUIElement | `{}` |\n", v)); }
                if let Some(v) = report.ls_background_only { md.push_str(&format!("| LSBackgroundOnly | `{}` |\n", v)); }
                if let Some(ref v) = report.ns_principal_class { md.push_str(&format!("| NSPrincipalClass | `{}` |\n", v)); }

                if !report.flags.is_empty() {
                    md.push_str("\n## Flags / Indicators\n\n");
                    for f in &report.flags {
                        md.push_str(&format!("- **[!]** {}\n", f));
                    }
                }

                if let Some(ref env_map) = report.ls_environment {
                    md.push_str("\n## LSEnvironment\n\n");
                    for (k, v) in env_map {
                        md.push_str(&format!("- `{}`: `{}`\n", k, v));
                    }
                }

                md.push_str("\n## All Plist Keys\n\n");
                md.push_str("| Key | Value |\n|-----|-------|\n");
                let mut sorted: Vec<_> = report.all_keys.iter().collect();
                sorted.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in sorted {
                    md.push_str(&format!("| {} | {} |\n", k, v.replace('|', "\\|")));
                }

                let mut f = File::create(&out_path).expect("Failed to create markdown report");
                f.write_all(md.as_bytes()).expect("Failed to write markdown report");
                println!("\n{}\n", styled_line("green", &format!("Markdown report saved to: {}", out_path.display())));
            }
        }
    } else if !is_gui_mode() {
        println!();
        let line = styled_line("stone", "Output was not saved. Use -o with -t, -j, or -m to export results.");
        println!("{}", line);
        println!();
        let _ = std::io::stdout().flush();
    }

    if std::env::var("MALCHELA_GUI_MODE").is_ok() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
