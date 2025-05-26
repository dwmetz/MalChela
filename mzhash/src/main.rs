use std::time::Instant;
use common_config::get_output_dir;
use std::fs::{self, File};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::process;
use sha2::{Sha256, Digest};
use md5::Md5;
use sha1::Sha1;
use yara::{Compiler, Rules};
use walkdir::WalkDir;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use indicatif::{ProgressBar, ProgressStyle};

/// Compile YARA rules for detecting MZ headers.
fn compile_yara_rules() -> Result<Rules, yara::Error> {
    let rule = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}  // MZ header in hex
    condition:
        $mz at 0  // Match if MZ header is at the start of the file
}
"#;

    Compiler::new()
        .map_err(|e| yara::Error::from(e))?
        .add_rules_str(rule)
        .map_err(|e| yara::Error::from(e))?
        .compile_rules()
        .map_err(|e| yara::Error::from(e))
}

/// Calculate the SHA256 hash of a file.
fn calculate_sha256(file_path: &Path) -> Option<String> {
    let mut file = File::open(file_path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];

    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

/// Calculate the MD5 hash of a file.
fn calculate_md5(file_path: &Path) -> Option<String> {
    let mut file = File::open(file_path).ok()?;
    let mut hasher = Md5::new();
    let mut buffer = [0; 4096];

    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

/// Calculate the SHA1 hash of a file.
fn calculate_sha1(file_path: &Path) -> Option<String> {
    let mut file = File::open(file_path).ok()?;
    let mut hasher = Sha1::new();
    let mut buffer = [0; 4096];

    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

/// Scan files in a directory using YARA rules and write results to output files.
fn scan_and_hash_files(directory: &Path, _rules: &Rules, output_file: &Path, algorithms: &[String]) -> (usize, usize, Vec<String>) {
    let entries: Vec<_> = WalkDir::new(directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();

    let _gui_mode = std::env::var("MALCHELA_GUI_MODE").is_ok();

    let show_progress = std::env::var("MZHASH_PROGRESS").ok().as_deref() == Some("1");
    let bar = if show_progress {
        let pb = ProgressBar::new(entries.len() as u64);
        pb.set_style(ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)"
        ).unwrap());
        Some(Arc::new(pb))
    } else {
        None
    };

    use std::collections::HashMap;
    let mut hash_outputs: HashMap<&str, Arc<Mutex<File>>> = HashMap::new();
    let mut index_outputs: HashMap<&str, Arc<Mutex<File>>> = HashMap::new();
    let algorithms = algorithms;

    for algo in algorithms {
        let hash_path = output_file.with_file_name(format!("MZ{}.txt", algo.to_uppercase()));
        let index_path = output_file.with_file_name(format!("MZ{}_index.tsv", algo.to_uppercase()));
        hash_outputs.insert(algo.as_str(), Arc::new(Mutex::new(File::create(hash_path).expect("Failed to create hash file"))));
        index_outputs.insert(algo.as_str(), Arc::new(Mutex::new(File::create(index_path).expect("Failed to create index file"))));
    }

    let timeout_log = Arc::new(Mutex::new(OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_file.with_file_name("timeout.log"))
        .expect("Failed to create timeout log file")));

    let timeout_count = Arc::new(Mutex::new(0usize));

    let hash_count = Arc::new(Mutex::new(0usize));
    let file_count = Arc::new(Mutex::new(0usize));

    entries.par_iter().for_each(|entry| {
        let path = entry.path();

        let rules = match compile_yara_rules() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Thread error: failed to compile rules: {}", e);
                return;
            }
        };

        match rules.scan_file(path, 0) {
            Ok(matches) => {
                if matches.iter().any(|m| m.identifier == "mz_header") {
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

                            if let Some(output) = hash_outputs.get(algo.as_str()) {
                                if let Ok(mut file) = output.lock() {
                                    writeln!(file, "{}", hash).ok();
                                }
                            }

                            if let Some(index) = index_outputs.get(algo.as_str()) {
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
            }
        }

        if let Some(ref bar) = bar {
            bar.inc(1);
        }
    });

    if let Some(bar) = bar {
        bar.finish_with_message("Scan complete");
    }

    let scanned = *file_count.lock().unwrap();
    let count = *hash_count.lock().unwrap();

    let timeouts = timeout_count.lock().unwrap();
    if *timeouts > 0 {
        println!("{} file(s) timed out during scanning.", *timeouts);
        println!("Timeout log location: {:?}", output_file.with_file_name("timeout.log").canonicalize().unwrap());
    }

    let mut output_paths = vec![];
    for algo in algorithms {
        output_paths.push(output_file.with_file_name(format!("MZ{}.txt", algo.to_uppercase())).display().to_string());
        output_paths.push(output_file.with_file_name(format!("MZ{}_index.tsv", algo.to_uppercase())).display().to_string());
    }

    (count, scanned, output_paths)
}

fn main() {
    let start_time = Instant::now();
    let input = if let Ok(gui_path) = std::env::var("MALCHELA_INPUT") {
        gui_path.trim().to_string()
    } else if std::env::var("MALCHELA_GUI_MODE").is_ok() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() > 1 {
            args[1].trim().to_string()
        } else {
            eprintln!("No path provided to mzhash in GUI mode. Pass a folder or set MALCHELA_INPUT.");
            std::process::exit(1);
        }
    } else {
        println!("Please enter the directory to scan:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read input.");
        input.trim().to_string()
    };

    let directory_to_scan = match fs::canonicalize(input.trim()) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Error: Failed to resolve path. Details: {}", err);
            process::exit(1);
        }
    };

    let metadata = match fs::metadata(&directory_to_scan) {
        Ok(meta) => meta,
        Err(err) => {
            eprintln!("Error: The specified path does not exist or cannot be accessed. Details: {}", err);
            process::exit(1);
        }
    };

    if !metadata.is_dir() {
        eprintln!("Error: The specified path is not a directory or volume.");
        process::exit(1);
    }

    let mut output_file_path = get_output_dir("mzhash");
    output_file_path.push("MZSHA256.txt");

    let mut allow_overwrite = std::env::var("MZHASH_ALLOW_OVERWRITE").ok().as_deref() == Some("1");
    let args: Vec<String> = std::env::args().collect();
    allow_overwrite = allow_overwrite || args.contains(&"-o".to_string());

    if output_file_path.exists() && !allow_overwrite {
        if std::env::var("MALCHELA_GUI_MODE").is_ok() {
            println!("File already exists. Enable 'Allow Overwrite' if you want to replace this file.");
            process::exit(0);
        } else {
            println!("File already exists. Do you want to overwrite it? (y/n):");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).expect("Failed to read input.");
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted by user. No file was overwritten.");
                process::exit(0);
            }
        }
    }

    let yara_rules = match compile_yara_rules() {
        Ok(rules) => rules,
        Err(err) => {
            eprintln!("Failed to compile YARA rules: {}", err);
            process::exit(1);
        }
    };

    let args: Vec<String> = std::env::args().collect();
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

    let (total_hashes, mz_matches, output_paths) =
        scan_and_hash_files(&directory_to_scan, &yara_rules, &output_file_path, &selected_algorithms);

    println!("\nScan completed.");
    println!("Number of files scanned: {}", WalkDir::new(&directory_to_scan).into_iter().filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count());
    println!("MZ headers: {} files", mz_matches);
    println!("Number of hashes written: {}", total_hashes);
    println!("Output file location(s):");
    for path in output_paths {
        println!("    {}", path);
    }
    println!("Scan duration: {:.2?}", start_time.elapsed());
}