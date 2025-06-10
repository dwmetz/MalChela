use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use sha2::{Sha256, Digest};
use clap::Parser;
use serde::Serialize;
use walkdir::WalkDir;
use infer;
use std::process::Command;
use tabled::Tabled;



fn join_suggested_tools(tools: &Vec<(String, String)>) -> String {
    tools.iter().map(|(label, _)| label.clone()).collect::<Vec<_>>().join(", ")
}

fn simplify_mime(mime: &str) -> &str {
    match mime {
        "application/vnd.microsoft.portable-executable" => "PE-EXE",
        "application/zip" => "ZIP",
        "application/pdf" => "PDF",
        "image/jpeg" => "JPG",
        "image/png" => "PNG",
        "text/plain" => "TXT",
        "Unknown" => "Unknown",
        _ => "Other",
    }
}

fn format_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1_048_576 => format!("{:.1} MB", b as f64 / 1_048_576.0),
        b if b >= 1024 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{} B", b),
    }
}

#[derive(Parser)]
#[command(name = "FileMiner")]
#[command(about = "Analyze files in a directory by magic bytes and hash (formerly MismatchMiner)", long_about = None)]
struct Cli {
    #[arg(value_name = "DIR", help = "Directory to analyze")]
    path: Option<String>,

    #[arg(long, help = "Save results to JSON file")]
    json: bool,

    #[arg(long, help = "Optional case name to save output under")]
    case: Option<String>,

    #[arg(short = 'm', long, help = "Only display entries with extension mismatches")]
    mismatches_only: bool,
}

#[derive(Serialize, Clone)]
struct ScanResult {
    filename: String,
    filepath: String,
    filetype: String,
    size: u64,
    sha256: String,
    suggested_tools: Vec<(String, String)>,
    extension_label: String,
    extension_mismatch: bool,
    actual_type: String,
    extension_inferred: String,
}

impl Tabled for ScanResult {
    const LENGTH: usize = 9;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        use std::borrow::Cow;
        vec![
            Cow::from(self.filename.as_str()),
            Cow::from(self.filepath.as_str()),
            Cow::from(simplify_mime(&self.actual_type)),
            Cow::from(format_size(self.size)),
            Cow::from(self.sha256.as_str()),
            Cow::from(self.extension_label.as_str()),
            Cow::from(self.extension_inferred.as_str()),
            Cow::from(self.extension_mismatch.to_string()),
            Cow::from(join_suggested_tools(&self.suggested_tools)),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        use std::borrow::Cow;
        vec![
            Cow::from("Filename"),
            Cow::from("Path"),
            Cow::from("Type"),
            Cow::from("Size"),
            Cow::from("SHA256"),
            Cow::from("Ext"),
            Cow::from("Inferred"),
            Cow::from("Mismatch"),
            Cow::from("Suggested"),
        ]
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let is_gui = std::env::var("MALCHELA_GUI_MODE").is_ok();
    let dir_path = match cli.path {
        Some(p) => p,
        None => {
            print!("Enter directory path to analyze: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        }
    };

    let case_name = cli.case.as_deref();

    let save_json = cli.json || cli.case.is_some();

    if !Path::new(&dir_path).is_dir() {
        eprintln!("Provided path is not a directory.");
        std::process::exit(1);
    }

    match analyze_directory(&dir_path, save_json, case_name) {
        Ok(results) => {
            use std::collections::HashMap;

            println!("Analysis complete.\n");

            let display_results: Vec<_> = if cli.mismatches_only {
                results.iter().filter(|r| r.extension_mismatch).collect()
            } else {
                results.iter().collect()
            };

            let mut grouped: HashMap<String, Vec<&ScanResult>> = HashMap::new();
            for res in &display_results {
                grouped.entry(res.sha256.clone()).or_default().push(res);
            }

            if is_gui {
                #[derive(Serialize)]
                struct FileMinerOutput {
                    tool: &'static str,
                    total: usize,
                    results: Vec<ScanResult>,
                }

                let _output = FileMinerOutput {
                    tool: "fileminer",
                    total: display_results.len(),
                    results: display_results.clone().into_iter().cloned().collect(),
                };
            }

            use tabled::builder::Builder;
            use tabled::settings::{Style, Modify, object::{Columns}, Alignment, Width};

            let mut builder = Builder::default();
            builder.push_record([
                "#", "Filename", "Path", "Type", "Size", "SHA256", "Ext", "Inferred", "Mismatch", "Suggested"
            ]);

            for (i, r) in display_results.iter().enumerate() {
                builder.push_record([
                    i.to_string(),
                    r.filename.clone(),
                    r.filepath.clone(),
                    simplify_mime(&r.actual_type).to_string(),
                    format_size(r.size),
                    r.sha256.clone(),
                    r.extension_label.clone(),
                    r.extension_inferred.clone(),
                    r.extension_mismatch.to_string(),
                    join_suggested_tools(&r.suggested_tools),
                ]);
            }

            let mismatch_column = Columns::single(9);
            let mut built = builder.build();
            let table = built
                .with(Style::modern())
                .with(Modify::new(Columns::single(1)).with(Width::wrap(25).keep_words(true)))
                .with(Modify::new(Columns::new(0..)).with(Alignment::left()))
                .with(Modify::new(Columns::new(0..)).with(Width::wrap(40).keep_words(true)))
                .with(Modify::new(Columns::single(2)).with(Width::wrap(30).keep_words(true)))
                .with(Modify::new(Columns::single(5)).with(Width::wrap(30).keep_words(true)))
                .with(Modify::new(mismatch_column).with(Width::wrap(24).keep_words(true)));

            println!("{}", table);

            if !is_gui {
                println!("\nSelect a file to process:");
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                let sel_index: usize = match input.trim().parse::<usize>() {
                    Ok(num) if num < results.len() => num,
                    _ => {
                        eprintln!("Invalid selection.");
                        return Ok(());
                    }
                };
                let selected_file = &results[sel_index];

                // Map filetype to MIME type category for tool selection prompt
                let mime_category = if selected_file.filetype.contains("portable-executable") {
                    "portable-executable"
                } else if selected_file.filetype == "Unknown" {
                    "unknown"
                } else if selected_file.filetype.starts_with("application/") {
                    "application"
                } else if selected_file.filetype.starts_with("text/") {
                    "text"
                } else {
                    "other"
                };

                println!("\nAvailable tools for {}:", mime_category);
                for (i, (label, _)) in selected_file.suggested_tools.iter().enumerate() {
                    println!("- [{}] {}", i + 1, label);
                }
                println!("Select tool:");
                input.clear();
                io::stdin().read_line(&mut input).unwrap();
                let tool_index: usize = match input.trim().parse::<usize>() {
                    Ok(i) if i > 0 && i <= selected_file.suggested_tools.len() => i - 1,
                    _ => {
                        eprintln!("Invalid tool selection.");
                        return Ok(());
                    }
                };

                let (_, tool_name) = &selected_file.suggested_tools[tool_index];

                println!("Running {} on {}...", tool_name, selected_file.filename);

                // Actually run the selected tool using cargo run
                let mut args = vec!["run", "-p", tool_name, "--"];

                if tool_name == "malhash" {
                    args.push(&selected_file.sha256);
                } else {
                    args.push(&selected_file.filepath);
                }

                if let Some(case) = case_name {
                    args.push("--case");
                    args.push(case);
                }

                let status = Command::new("cargo")
                    .args(args)
                    .status()
                    .expect("Failed to run tool");

                if !status.success() {
                    eprintln!("{} failed to execute properly.", tool_name);
                }
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
    Ok(())
}

fn analyze_directory(
    path: &str,
    save_json: bool,
    case: Option<&str>,
) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        let path = entry.path().to_path_buf();

        if path.is_file() {
            let file_type = identify_magic(&path)?;
            let actual_type = file_type.clone();
            let metadata = fs::metadata(&path)?;
            let file_size = metadata.len();
            let hash = calculate_sha256(&path)?;

            let extension = path
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase();

            let extension_inferred = if file_type.contains("portable-executable") {
                "exe"
            } else if file_type.contains("zip") {
                "zip"
            } else if file_type.contains("jpeg") {
                "jpg"
            } else if file_type.contains("png") {
                "png"
            } else if file_type.contains("pdf") {
                "pdf"
            } else if file_type.starts_with("text/") {
                "txt"
            } else {
                ""
            }.to_string();

            let ext_mismatch = match extension.as_str() {
                "exe" | "dll" => !file_type.contains("portable-executable"),
                "txt" | "log" => !file_type.starts_with("text/"),
                "zip" => !file_type.contains("zip"),
                "jpg" | "jpeg" => !file_type.contains("jpeg"),
                "png" => !file_type.contains("png"),
                "pdf" => !file_type.contains("pdf"),
                _ => false,
            };

            let mut suggested_tools = Vec::new();
            if file_type.contains("portable-executable") {
                suggested_tools.push(("FileAnalyzer".into(), "fileanalyzer".into()));
                suggested_tools.push(("mStrings".into(), "mstrings".into()));
                suggested_tools.push(("malhash".into(), "malhash".into()));
            } else if file_type == "Unknown" && file_size > 10_000 {
                suggested_tools.push(("FileAnalyzer".into(), "fileanalyzer".into()));
                suggested_tools.push(("malhash".into(), "malhash".into()));
            }



            results.push(ScanResult {
                filename: path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                filepath: path.to_string_lossy().to_string(),
                filetype: file_type,
                size: file_size,
                sha256: hash,
                suggested_tools,
                extension_label: extension,
                extension_mismatch: ext_mismatch,
                actual_type,
                extension_inferred,
            });
        }
    }

    if save_json {
        let output_dir = if let Some(case) = case {
            Path::new("saved_output").join(case).join("fileminer")
        } else {
            Path::new("saved_output").join("fileminer")
        };
        fs::create_dir_all(&output_dir)?;
        let out_path = output_dir.join("fileminer_output.json");
        let file = File::create(&out_path)?;
        serde_json::to_writer_pretty(file, &results)?;
        println!("Results saved to {}", out_path.display());
    }

    Ok(results)
}

fn identify_magic(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if let Some(kind) = infer::get(&buffer) {
        Ok(kind.mime_type().to_string())
    } else {
        Ok("Unknown".to_string())
    }
}

fn calculate_sha256(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}