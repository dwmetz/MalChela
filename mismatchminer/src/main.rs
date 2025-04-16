use colored::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use yara::{Rules, Compiler};
use common_config::get_output_dir;

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
    output_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut match_count = 0;
    let mut output = File::create(output_file)?;
    let mut scanner = rules.scanner()?;

    let mut matches: Vec<(String, String, String)> = Vec::new();

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
                            writeln!(output, "{} {}", sha256_hash, path.display())?;
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
        println!("\n{}", "Scan Results:".bold().blue());
    
        for (i, (hash, ext, path)) in matches.iter().enumerate() {
            println!("{}", format!("--- Match {} ---", i + 1).bold().blue());
            println!("{} {}", "Hash     :".bold(), hash.green());
            println!("{} {}", "Extension:".bold(), format!(".{}", ext).yellow());
            println!("{} {}", "Path     :".bold(), path.cyan());
            println!(); // blank line between blocks
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

    let canonical = output_file.canonicalize()?;
    let output_path = canonical.to_string_lossy();
    println!(
        "{} {}",
        "Output file location:".bold(),
        output_path.bold().green()
    );

    Ok(())
}

fn prompt_for_directory() -> PathBuf {
    println!("{}", "Enter the path to the directory to scan:".bold().blue());
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    PathBuf::from(input.trim())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input_dir = prompt_for_directory();
    if !input_dir.is_dir() {
        eprintln!("{}", "Provided path is not a directory.".bold().red());
        return Ok(());
    }

    let output_dir = get_output_dir("mismatchminer");
    let output_file = output_dir.join("matches.txt");

    fs::create_dir_all(&output_dir)?;
    scan_and_hash_matches(&input_dir, &compile_yara_rules()?, &output_file)?;

    //println!("Text output saved to {}", output_file.display());
    println!(); // adds a final blank line

    Ok(())
}