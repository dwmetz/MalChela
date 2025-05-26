use sha1::Sha1;
use md5::Md5;
use std::collections::HashMap;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use common_config::get_output_dir;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use yara::{Compiler, Rules};
use sha2::{Digest, Sha256};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Instant;

const YARA_RULES: &str = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}  // MZ header in hex
    condition:
        $mz at 0  // Match if MZ header is at the start of the file
}

rule pdf_header {
    meta:
        description = "Matches files with PDF header"
    strings:
        $pdf = {25 50 44 46}  // PDF header in hex (%PDF)
    condition:
        $pdf at 0  // Match if PDF header is at the start of the file
}

rule zip_header {
    meta:
        description = "Matches files with ZIP header"
    strings:
        $zip = {50 4B 03 04}  // ZIP header in hex
    condition:
        $zip at 0  // Match if ZIP header is at the start of the file
}
"#;

/// Compiles YARA rules from a string.
fn compile_yara_rules() -> Result<Rules, Box<dyn std::error::Error>> {
    let compiler = Compiler::new()?;
    let compiler = compiler.add_rules_str(YARA_RULES)?;
    let rules = compiler.compile_rules()?;
    Ok(rules)
}

fn calculate_md5(file_path: &Path) -> Option<String> {
    let mut file = File::open(file_path).ok()?;
    let mut hasher = Md5::new();
    let mut buffer = [0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn calculate_sha1(file_path: &Path) -> Option<String> {
    let mut file = File::open(file_path).ok()?;
    let mut hasher = Sha1::new();
    let mut buffer = [0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    Some(format!("{:x}", hasher.finalize()))
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

/// Recursively scans a directory for files that do not match YARA rules and calculates their SHA256 hashes.
fn scan_and_hash_files(directory: &Path, _rules: &Rules, output_file: &Path, algorithms: &[String]) -> io::Result<(usize, usize, Vec<String>)> {
    let start_time = Instant::now();

    if let Some(parent) = output_file.parent() {
        fs::create_dir_all(parent).expect("Failed to ensure output directory exists");
    }

    let mut hash_outputs: HashMap<String, Arc<Mutex<File>>> = HashMap::new();
    let mut index_outputs: HashMap<String, Arc<Mutex<File>>> = HashMap::new();
    for algo in algorithms {
        let hash_path = output_file.with_file_name(format!("XMZ{}_HASHES.txt", algo.to_uppercase()));
        let index_path = output_file.with_file_name(format!("XMZ{}_index.tsv", algo.to_uppercase()));
        hash_outputs.insert(algo.clone(), Arc::new(Mutex::new(File::create(hash_path)?)));
        index_outputs.insert(algo.clone(), Arc::new(Mutex::new(File::create(index_path)?)));
    }
    let timeout_log = Arc::new(Mutex::new(OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_file.with_file_name("timeout.log"))
        .expect("Failed to create timeout log file")));

    let entries: Vec<_> = WalkDir::new(directory)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();

    println!("Starting scan of {} files...", entries.len());
    let _ = std::io::stdout().flush();

    let gui_mode = std::env::var("MALCHELA_GUI_MODE").is_ok();

    let show_progress = std::env::var("MZHASH_PROGRESS").ok().as_deref() == Some("1");
    let verbose_mode = !show_progress;

    let bar = if !gui_mode && show_progress {
        let pb = ProgressBar::new(entries.len() as u64);
        pb.set_style(ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)"
        ).unwrap());
        Some(Arc::new(pb))
    } else {
        None
    };

    let hash_count = Arc::new(Mutex::new(0usize));
    let timeout_count = Arc::new(Mutex::new(0usize));
    let file_count = Arc::new(Mutex::new(0usize));

    if gui_mode {
        let mut scanned = 0usize;
        let total = entries.len();
        for entry in &entries {
            let path = entry.path();
            scanned += 1;
            println!("[PROGRESS] {}/{}", scanned, total);
            let _ = std::io::stdout().flush();

            // Removed verbose "Scanning: ..." output

            let rules = match compile_yara_rules() {
                Ok(r) => r,
                Err(e) => {
                    println!("[THREAD ERROR] Failed to compile YARA rules: {}", e);
                    continue;
                }
            };

            match rules.scan_file(path, 15) {
                Ok(matches) => {
                    if matches.is_empty() {
                        if let Ok(mut count) = file_count.lock() {
                            *count += 1;
                        }
                        for algo in algorithms {
                            let hash = match algo.as_str() {
                                "md5" => calculate_md5(path),
                                "sha1" => calculate_sha1(path),
                                "sha256" => calculate_sha256(path),
                                _ => None,
                            };
                            if let Some(hash) = hash {
                                if !show_progress {
                                    println!("Writing hash to file [{}]: {}", algo.to_uppercase(), hash);
                                    let _ = std::io::stdout().flush();
                                }
                                if let Some(output) = hash_outputs.get(algo) {
                                    if let Ok(mut file) = output.lock() {
                                        writeln!(file, "{}", hash).ok();
                                    }
                                }
                                if let Some(index) = index_outputs.get(algo) {
                                    if let Ok(mut file) = index.lock() {
                                        writeln!(file, "{}\t{}", hash, path.display()).ok();
                                    }
                                }
                                if let Ok(mut count) = hash_count.lock() {
                                    *count += 1;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.to_string().contains("Timeouted") {
                        if let Ok(mut log) = timeout_log.lock() {
                            writeln!(log, "[TIMEOUT] {:?}: {}", path, e).ok();
                        }
                        if let Ok(mut count) = timeout_count.lock() {
                            *count += 1;
                        }
                    }
                    println!("[ERROR] YARA scan failed for {:?}: {}", path, e);
                    let _ = std::io::stdout().flush();
                }
            }
        }
    } else {
        entries.par_iter().for_each(|entry| {
            let path = entry.path();

            // Removed verbose "Scanning: ..." output

            // Compile fresh rules per thread
            let rules = match compile_yara_rules() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[THREAD ERROR] Failed to compile YARA rules: {}", e);
                    return;
                }
            };

            match rules.scan_file(path, 15) {
                Ok(matches) => {
                    if matches.is_empty() {
                        if let Ok(mut count) = file_count.lock() {
                            *count += 1;
                        }
                        for algo in algorithms {
                            let hash = match algo.as_str() {
                                "md5" => calculate_md5(path),
                                "sha1" => calculate_sha1(path),
                                "sha256" => calculate_sha256(path),
                                _ => None,
                            };
                            if let Some(hash) = hash {
                                if !show_progress {
                                    println!("Writing hash to file [{}]: {}", algo.to_uppercase(), hash);
                                    let _ = std::io::stdout().flush();
                                }
                                if let Some(output) = hash_outputs.get(algo) {
                                    if let Ok(mut file) = output.lock() {
                                        writeln!(file, "{}", hash).ok();
                                    }
                                }
                                if let Some(index) = index_outputs.get(algo) {
                                    if let Ok(mut file) = index.lock() {
                                        writeln!(file, "{}\t{}", hash, path.display()).ok();
                                    }
                                }
                                if let Ok(mut count) = hash_count.lock() {
                                    *count += 1;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.to_string().contains("Timeouted") {
                        if let Ok(mut log) = timeout_log.lock() {
                            writeln!(log, "[TIMEOUT] {:?}: {}", path, e).ok();
                        }
                        if let Ok(mut count) = timeout_count.lock() {
                            *count += 1;
                        }
                    }
                    println!("[ERROR] YARA scan failed for {:?}: {}", path, e);
                    let _ = std::io::stdout().flush();
                }
            }
            if let Some(ref bar) = bar {
                bar.inc(1);
            } else if verbose_mode {
                // Print hash for the last calculated hash if available
                for algo in algorithms {
                    let hash = match algo.as_str() {
                        "md5" => calculate_md5(path),
                        "sha1" => calculate_sha1(path),
                        "sha256" => calculate_sha256(path),
                        _ => None,
                    };
                    if let Some(hash) = hash {
                        println!("Writing hash to file [{}]: {}", algo.to_uppercase(), hash);
                    }
                }
                let _ = std::io::stdout().flush();
            }
        });
    }

    if let Some(bar) = bar {
        bar.finish_with_message("Scan complete");
    }
    let count = hash_count.lock().unwrap();
    let timeouts = timeout_count.lock().unwrap();
    let scanned = *file_count.lock().unwrap();

    let mut output_paths = vec![];
    for algo in algorithms {
        output_paths.push(output_file.with_file_name(format!("XMZ{}_HASHES.txt", algo.to_uppercase())).display().to_string());
        output_paths.push(output_file.with_file_name(format!("XMZ{}_index.tsv", algo.to_uppercase())).display().to_string());
    }

    if *timeouts > 0 {
        println!("{} file(s) timed out during scanning.", *timeouts);
        println!("Timeout log location: {:?}", output_file.with_file_name("timeout.log").canonicalize()?);
    }

    println!("\nScan completed.");
    println!("Number of files scanned: {}", entries.len());
    println!("Files Matched: {} files", scanned);
    println!("Number of hashes written: {}", count);
    println!("Output file location(s):");
    for path in &output_paths {
        println!("    {}", path);
    }
    println!("Scan duration: {:.2?}", start_time.elapsed());

    Ok((*count, scanned, output_paths))
}

fn main() {
    let directory_to_scan = if let Ok(path) = std::env::var("MALCHELA_INPUT") {
        path.trim().to_string()
    } else if std::env::var("MALCHELA_GUI_MODE").is_ok() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() > 1 {
            args[1].trim().to_string()
        } else {
            eprintln!("No path provided to xmzhash in GUI mode. Set MALCHELA_INPUT or pass a path.");
            std::process::exit(1);
        }
    } else {
        eprintln!("Please enter the directory to scan:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read input.");
        input.trim().to_string()
    };
    let directory_to_scan = PathBuf::from(directory_to_scan);

    if !directory_to_scan.is_dir() {
        eprintln!("[ERROR] The provided path is not a valid directory: {:?}", directory_to_scan);
        return;
    }

    // Compile YARA rules
    let yara_rules = match compile_yara_rules() {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("[ERROR] Failed to compile YARA rules: {}", e);
            return;
        }
    };

    let output_dir = get_output_dir("xmzhash");
    let output_filename = output_dir.join("XMZ256.txt");

    let args: Vec<String> = std::env::args().collect();
    let mut allow_overwrite = std::env::var("MZHASH_ALLOW_OVERWRITE").ok().as_deref() == Some("1");
    allow_overwrite = allow_overwrite || args.contains(&"-o".to_string());

    let all_outputs = vec![
        output_filename.clone(),
        output_filename.with_file_name("XMZ256_index.tsv"),
        output_filename.with_file_name("XMZMD5_HASHES.txt"),
        output_filename.with_file_name("XMZMD5_index.tsv"),
        output_filename.with_file_name("XMZSHA1_HASHES.txt"),
        output_filename.with_file_name("XMZSHA1_index.tsv"),
        output_filename.with_file_name("XMZSHA256_HASHES.txt"),
        output_filename.with_file_name("XMZSHA256_index.tsv"),
    ];

    for path in &all_outputs {
        if path.exists() && !allow_overwrite {
            if std::env::var("MALCHELA_GUI_MODE").is_ok() {
                println!("File already exists. Enable 'Allow Overwrite' if you want to replace this file.");
                return;
            } else {
                println!("File already exists at {}. Do you want to overwrite it? (y/n):", path.display());
                let mut choice = String::new();
                std::io::stdin().read_line(&mut choice).expect("Failed to read input.");
                if !choice.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted by user. No files were overwritten.");
                    return;
                }
                break;
            }
        }
    }

    // Enable progress-only mode if -p is passed
    if args.contains(&"-p".to_string()) {
        std::env::set_var("MZHASH_PROGRESS", "1");
    }

    let mut selected_algorithms: Vec<String> = vec![];
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-a" && i + 1 < args.len() {
            selected_algorithms.push(args[i + 1].to_lowercase());
            i += 1;
        }
        i += 1;
    }
    if selected_algorithms.is_empty() {
        selected_algorithms = vec!["sha256".to_string()];
    }

    // Scan the directory recursively and write results to the output file
    let _ = scan_and_hash_files(&directory_to_scan, &yara_rules, &output_filename, &selected_algorithms);
}