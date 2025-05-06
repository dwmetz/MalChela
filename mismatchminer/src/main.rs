use clap::Parser;
use chrono::Utc;
use serde_json;

fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok()
}

#[derive(Parser)]
#[command(name = "MismatchMiner")]
#[command(about = "Scans a directory for files with matching YARA rules and hashes", long_about = None)]
struct Args {
    #[arg(help = "Directory to scan")]
    input: Option<PathBuf>,

    #[arg(short, long, help = "Save output to file")]
    output: bool,

    #[arg(short = 't', long, help = "Output as text format")]
    text: bool,

    #[arg(short = 'j', long, help = "Output as JSON format")]
    json: bool,

    #[arg(short = 'm', long, help = "Output as Markdown format")]
    markdown: bool,
}
use colored::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use yara::{Rules, Compiler};
use common_config::get_output_dir;
use common_ui::styled_line;

const YARA_RULES: &str = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}
    condition:
        $mz at 0
}
"#;

const TARGET_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "jpg", "png", "bmp", "txt", "zip", "rar", "scr", "ppt", "pps", "lnk", "js", "jse", "hta"
];

fn compile_yara_rules() -> Result<Rules, Box<dyn std::error::Error>> {
    let compiler = Compiler::new()?;
    let compiler = compiler.add_rules_str(YARA_RULES)?;
    let rules = compiler.compile_rules()?;
    Ok(rules)
}

fn calculate_sha256(file_path: &Path) -> Option<String> {
    let file = File::open(file_path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];

    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

fn is_target_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| TARGET_EXTENSIONS.iter().any(|&e| e.eq_ignore_ascii_case(ext)))
        .unwrap_or(false)
}

fn scan_and_hash_matches(
    directory: &Path,
    rules: &Rules,
    output_file: &Option<PathBuf>,
    output_format: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut match_count = 0;
    let mut output: Option<File> = None;
    let mut scanner = rules.scanner()?;

    let mut matches: Vec<(String, String, String)> = Vec::new();
    let save_output = output_file.is_some();

    for entry in WalkDir::new(directory)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if path.is_file() && is_target_extension(path) {
            match scanner.scan_file(path) {
                Ok(yara_matches) => {
                    if !yara_matches.is_empty() {
                        if let Some(sha256_hash) = calculate_sha256(path) {
                            let ext = path.extension().unwrap().to_string_lossy().to_string();
                            let path_str = path.display().to_string();
                            matches.push((sha256_hash.clone(), ext.clone(), path_str.clone()));
                            if save_output {
                                if output.is_none() {
                                    if let Some(ref path) = output_file {
                                        output = Some(File::create(path)?);
                                    }
                                }
                            if let Some(ref mut out) = output {
                                writeln!(out, "--- Match {} ---", match_count)?;
                                writeln!(out, "Hash     : {}", sha256_hash)?;
                                writeln!(out, "Extension: .{}", ext)?;
                                writeln!(out, "Path     : {}", path.display())?;
                                writeln!(out)?;
                            }
                            }
                            match_count += 1;
                        }
                    }
                }
                Err(e) => eprintln!(
                    "{} {} {:?}: {}",
                    "[WARNING]".bold().yellow(),
                    "YARA error scanning".bold(),
                    path,
                    e
                ),
            }
        }
    }

    if !matches.is_empty() {
        if is_gui_mode() {
            println!("{}", styled_line("green", "Scan Results:"));
            for (i, (hash, ext, path)) in matches.iter().enumerate() {
                println!("{}", styled_line("yellow", &format!("--- Match {} ---", i + 1)));
                println!("{}", styled_line("bold", "Hash     :"));
                println!("{}", styled_line("green", hash));
                println!("{}", styled_line("cyan", &format!("Extension: .{}", ext)));
                println!("{}", styled_line("gray", &format!("Path     : {}", path)));
                println!();
            }
        } else {
            println!("\n{}", "Scan Results:".bold().green());
            for (i, (hash, ext, path)) in matches.iter().enumerate() {
                println!("{}", format!("--- Match {} ---", i + 1).bold().yellow());
                println!("{} {}", "Hash     :".bold(), hash.green());
                println!("{} {}", "Extension:".bold(), format!(".{}", ext).cyan());
                println!("{} {}", "Path     :".bold(), path);
                println!();
            }
        }
    } else {
        println!("{}", "No matches found.".bold().green());
    }

    println!("\n{}", "Scan completed.".bold().blue());
    println!(
        "{} {}",
        "Total number of matches written:".bold(),
        match_count.to_string().bold().green()
    );

    if save_output && output_format == Some("json") {
        if let Some(ref path) = output_file {
            let json_output = serde_json::to_string_pretty(
                &matches.iter().map(|(hash, ext, path)| {
                    serde_json::json!({
                        "hash": hash,
                        "extension": ext,
                        "path": path
                    })
                }).collect::<Vec<_>>()
            )?;
            fs::write(path, json_output)?;
        }
    }

    if save_output && !is_gui_mode() {
        if let Some(path) = output_file {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            let msg = match output_format {
                Some("txt") => format!("Text report was saved to: {}", canonical.display()),
                Some("json") => format!("JSON report was saved to: {}", canonical.display()),
                Some("md") => format!("Markdown report was saved to: {}", canonical.display()),
                _ => format!("Report was saved to: {}", canonical.display()),
            };
            println!("{}", msg.bold().green());
        }
    } else if !save_output {
        println!("{}", "Output was not saved.".bold().yellow());
    }

    Ok(())
}

fn prompt_for_directory() -> PathBuf {
    println!("{}", "Enter the path to the directory to scan:".bold().blue());
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    PathBuf::from(input.trim())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let input_dir = args.input.unwrap_or_else(prompt_for_directory);
    if !input_dir.is_dir() {
        eprintln!("{}", "Provided path is not a directory.".bold().red());
        return Ok(());
    }

    let output_dir = get_output_dir("mismatchminer");
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();

    let save_output = args.output;
    let output_format = if args.text {
        Some("txt")
    } else if args.json {
        Some("json")
    } else if args.markdown {
        Some("md")
    } else {
        None
    };

    if save_output && output_format.is_none() {
        println!("{}", "Output format required. Use -t, -j, or -m with -o.".bold().red());
        return Ok(());
    }

    let output_file = if let Some(fmt) = output_format {
        let path = output_dir.join(format!("report_{}.{}", timestamp, fmt));
        Some(path)
    } else {
        None
    };

    fs::create_dir_all(&output_dir)?;
    scan_and_hash_matches(&input_dir, &compile_yara_rules()?, &output_file, output_format)?;

    //println!("Text output saved to {}", output_file.display());
    println!(); // adds a final blank line

    Ok(())
}