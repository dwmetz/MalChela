use clap::{Arg, Command, ValueEnum};
use reqwest;
use serde_json;
use serde_json::Value;
use std::io;
use common_ui::styled_line;
use common_config::get_output_dir;

fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok() && std::env::var("MALCHELA_WORKSPACE_MODE").is_err()
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args: Vec<String> = std::env::args().collect();

    let matches = Command::new("nsrlquery")
        .about("Query CIRCL Hash Lookup")
        .arg(
            Arg::new("hash")
                .help("Hash value to look up")
                .required(false)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Save output to a report file")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("text")
                .short('t')
                .long("text")
                .help("Save output in text format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Save output in JSON format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("markdown")
                .short('m')
                .long("markdown")
                .help("Save output in Markdown format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("case")
                .long("case")
                .value_name("CASE")
                .help("Specify case name"),
        )
        .arg(
            Arg::new("output-file")
                .long("output-file")
                .value_name("FILENAME")
                .help("Specify output file name (without extension)"),
        )
        .get_matches_from(args);

    let mut hash = matches.get_one::<String>("hash").cloned();
    if hash.is_none() {
        println!("Enter the hash value:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        hash = Some(input.trim().to_string());
    }
    let hash = hash.unwrap();
    let save_output = *matches.get_one::<bool>("output").unwrap_or(&false)
        || std::env::var("MALCHELA_SAVE_OUTPUT").ok().as_deref() == Some("1");
    let output_format = if *matches.get_one::<bool>("json").unwrap_or(&false) {
        Some(OutputFormat::Json)
    } else if *matches.get_one::<bool>("markdown").unwrap_or(&false) {
        Some(OutputFormat::Markdown)
    } else if *matches.get_one::<bool>("text").unwrap_or(&false) {
        Some(OutputFormat::Text)
    } else {
        None
    };

    if save_output && output_format.is_none() {
        println!("Error: --output (-o) was specified but no format flag (-t, -j, or -m) was provided.");
        println!("Please specify one of: --text (-t), --json (-j), or --markdown (-m).");
        return Ok(());
    }

    let output_format = output_format.unwrap_or(OutputFormat::Text);
    let case_name = matches.get_one::<String>("case");
    let output_filename = matches.get_one::<String>("output-file");

    if is_gui_mode() {
        println!("\n{}", styled_line("NOTE", "Results from CIRCL Hash Lookup:"));
    } else {
        println!("\nResults from CIRCL Hash Lookup:");
    }

    // Determine the hash type based on length
    let hash_type = match hash.len() {
        32 => "md5",
        40 => "sha1",
        _ => {
            println!("Error: Unsupported hash length. Please enter a valid MD5 (32 chars) or SHA1 (40 chars) hash.");
            return Ok(());
        }
    };

    // Construct the URL
    let url = format!("https://hashlookup.circl.lu/lookup/{}/{}", hash_type, hash);

    // Make the API request
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    // Check if the request was successful
    if response.status().is_success() {
        // Parse the JSON response
        let json: Value = response.json().await?;

        // Check if any key fields exist, if none print message and return early
        let has_valid_content = json.get("FileName").is_some()
            || json.get("FileSize").is_some()
            || json.get("MD5").is_some()
            || json.get("SHA-1").is_some()
            || json.get("SHA-256").is_some()
            || json.get("mimetype").is_some()
            || json.get("ProductCode").is_some()
            || json.get("PackageName").is_some()
            || json.get("PackageDescription").is_some()
            || json.get("OpSystemCode").is_some()
            || json.get("hashlookup:trust").is_some()
            || json.get("parents").is_some()
            || json.get("SSDEEP").is_some()
            || json.get("TLSH").is_some();

        if !has_valid_content {
            println!("No valid response content was found.");
            return Ok(());
        }

        let mut report = String::new();
        report += &format!("Results from CIRCL Hash Lookup:\n\n");

        if let Some(filename) = json.get("FileName").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("highlight", &format!("FileName: {}", filename)));
            } else {
                println!("FileName: {}", filename);
            }
            report += &format!("FileName: {}\n", filename);
        }
        if let Some(filesize) = json.get("FileSize").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("highlight", &format!("FileSize: {} bytes", filesize)));
            } else {
                println!("FileSize: {} bytes", filesize);
            }
            report += &format!("FileSize: {} bytes\n", filesize);
        }
        if let Some(md5) = json.get("MD5").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("highlight_hash", &format!("MD5: {}", md5)));
            } else {
                println!("MD5: {}", md5);
            }
            report += &format!("MD5: {}\n", md5);
        }
        if let Some(sha1) = json.get("SHA-1").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("highlight_hash", &format!("SHA-1: {}", sha1)));
            } else {
                println!("SHA-1: {}", sha1);
            }
            report += &format!("SHA-1: {}\n", sha1);
        }
        if let Some(sha256) = json.get("SHA-256").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("highlight_hash", &format!("SHA-256: {}", sha256)));
            } else {
                println!("SHA-256: {}", sha256);
            }
            report += &format!("SHA-256: {}\n", sha256);
        }
        if let Some(mimetype) = json.get("mimetype").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("stone", &format!("Mimetype: {}", mimetype)));
            } else {
                println!("Mimetype: {}", mimetype);
            }
            report += &format!("Mimetype: {}\n", mimetype);
        }
        if let Some(product) = json.get("ProductCode") {
            if let Some(name) = product.get("ProductName").and_then(|v| v.as_str()) {
                if let Some(version) = product.get("ProductVersion").and_then(|v| v.as_str()) {
                    if is_gui_mode() {
                        println!("{}", styled_line("stone", &format!("Platform: {} (v{})", name, version)));
                    } else {
                        println!("Platform: {} (v{})", name, version);
                    }
                    report += &format!("Platform: {} (v{})\n", name, version);
                } else {
                    if is_gui_mode() {
                        println!("{}", styled_line("stone", &format!("Platform: {}", name)));
                    } else {
                        println!("Platform: {}", name);
                    }
                    report += &format!("Platform: {}\n", name);
                }
            }
        }
        if let Some(pkg_name) = json.get("PackageName").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("highlight", &format!("Package Name: {}", pkg_name)));
            } else {
                println!("Package Name: {}", pkg_name);
            }
            report += &format!("Package Name: {}\n", pkg_name);
        }
        if let Some(pkg_desc) = json.get("PackageDescription").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("stone", &format!("Package Description:\n{}", pkg_desc)));
            } else {
                println!("Package Description:\n{}", pkg_desc);
            }
            report += &format!("Package Description:\n{}\n", pkg_desc);
        }
        if let Some(os) = json.get("OpSystemCode") {
            if let Some(name) = os.get("OpSystemName").and_then(|v| v.as_str()) {
                if is_gui_mode() {
                    println!("{}", styled_line("stone", &format!("Operating System: {}", name)));
                } else {
                    println!("Operating System: {}", name);
                }
                report += &format!("Operating System: {}\n", name);
            }
        }
        if let Some(trust) = json.get("hashlookup:trust").and_then(|v| v.as_u64()) {
            if is_gui_mode() {
                println!("{}", styled_line("yellow", &format!("Trust Score: {}", trust)));
            } else {
                println!("Trust Score: {}", trust);
            }
            report += &format!("Trust Score: {}\n", trust);
        }
        if let Some(parents) = json.get("parents").and_then(|v| v.as_array()) {
            if is_gui_mode() {
                println!("{}", styled_line("stone", &format!("Parent Count: {}", parents.len())));
            } else {
                println!("Parent Count: {}", parents.len());
            }
            report += &format!("Parent Count: {}\n", parents.len());
        }
        if let Some(ssdeep) = json.get("SSDEEP").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("stone", &format!("Fuzzy Hash (SSDEEP): {}", ssdeep)));
            } else {
                println!("Fuzzy Hash (SSDEEP): {}", ssdeep);
            }
            report += &format!("Fuzzy Hash (SSDEEP): {}\n", ssdeep);
        }
        if let Some(tlsh) = json.get("TLSH").and_then(|v| v.as_str()) {
            if is_gui_mode() {
                println!("{}", styled_line("stone", &format!("Fuzzy Hash (TLSH): {}", tlsh)));
            } else {
                println!("Fuzzy Hash (TLSH): {}", tlsh);
            }
            report += &format!("Fuzzy Hash (TLSH): {}\n", tlsh);
        }

        if save_output {
            use std::fs;
            let ext = match output_format {
                OutputFormat::Text => "txt",
                OutputFormat::Json => "json",
                OutputFormat::Markdown => "md",
            };
            let (base_output_dir, base_filename) = if let Some(case) = case_name {
                (
                    get_output_dir("cases").join(case).join("nsrlquery"),
                    format!("report_{}", chrono::Local::now().format("%Y%m%d_%H%M%S")),
                )
            } else {
                (
                    get_output_dir("nsrlquery"),
                    format!("report_{}", chrono::Local::now().format("%Y%m%d_%H%M%S")),
                )
            };
            let output_path = if let Some(name) = output_filename {
                let output_path = {
                    let sanitized = name.trim_end_matches(&format!(".{}", ext)).to_string();
                    let corrected = if sanitized.ends_with(ext) {
                        sanitized
                    } else {
                        format!("{}.{}", sanitized, ext)
                    };
                    base_output_dir.join(corrected)
                };
                output_path
            } else {
                base_output_dir.join(format!("{}.{}", base_filename, ext))
            };
            std::fs::create_dir_all(&base_output_dir)?;
            match output_format {
                OutputFormat::Text | OutputFormat::Markdown => {
                    fs::write(&output_path, &report)?;
                }
                OutputFormat::Json => {
                    fs::write(&output_path, serde_json::to_string_pretty(&json)?)?;
                }
            }
            if is_gui_mode() {
                println!(
                    "{}",
                    styled_line(
                        "green",
                        &format!(
                            "{} report was saved to: {}",
                            match output_format {
                                OutputFormat::Text => "Text",
                                OutputFormat::Json => "JSON",
                                OutputFormat::Markdown => "Markdown",
                            },
                            output_path.display()
                        )
                    )
                );
                println!("{}", styled_line("green", "File write operation completed successfully."));
            } else {
                println!(
                    "{} report was saved to: {}",
                    match output_format {
                        OutputFormat::Text => "Text",
                        OutputFormat::Json => "JSON",
                        OutputFormat::Markdown => "Markdown",
                    },
                    output_path.display()
                );
                println!("File write operation completed successfully.");
            }
        }
    } else if response.status().as_u16() == 404 {
        println!("Hash not found in the database.");
        let mut report = String::new();
        report += "Results from CIRCL Hash Lookup:\n\n";
        report += &format!("{}: {}\n", hash_type.to_uppercase(), hash);
        report += "\nHash not found in the database.\n";

        if save_output {
            use std::fs;
            let ext = match output_format {
                OutputFormat::Text => "txt",
                OutputFormat::Json => "json",
                OutputFormat::Markdown => "md",
            };
            let (base_output_dir, base_filename) = if let Some(case) = case_name {
                (
                    get_output_dir("cases").join(case).join("nsrlquery"),
                    format!("report_{}", chrono::Local::now().format("%Y%m%d_%H%M%S")),
                )
            } else {
                (
                    get_output_dir("nsrlquery"),
                    format!("report_{}", chrono::Local::now().format("%Y%m%d_%H%M%S")),
                )
            };
            let output_path = if let Some(name) = output_filename {
                let output_path = {
                    let sanitized = name.trim_end_matches(&format!(".{}", ext)).to_string();
                    let corrected = if sanitized.ends_with(ext) {
                        sanitized
                    } else {
                        format!("{}.{}", sanitized, ext)
                    };
                    base_output_dir.join(corrected)
                };
                output_path
            } else {
                base_output_dir.join(format!("{}.{}", base_filename, ext))
            };
            std::fs::create_dir_all(&base_output_dir)?;
            match output_format {
                OutputFormat::Text | OutputFormat::Markdown => {
                    fs::write(&output_path, &report)?;
                }
                OutputFormat::Json => {
                    fs::write(&output_path, serde_json::to_string_pretty(&serde_json::json!({
                        "hash_type": hash_type,
                        "hash": hash,
                        "status": "not_found"
                    }))?)?;
                }
            }
            if is_gui_mode() {
                println!(
                    "{}",
                    styled_line(
                        "yellow",
                        &format!(
                            "{} report was saved to: {}",
                            match output_format {
                                OutputFormat::Text => "Text",
                                OutputFormat::Json => "JSON",
                                OutputFormat::Markdown => "Markdown",
                            },
                            output_path.display()
                        )
                    )
                );
                println!("{}", styled_line("yellow", "File write operation completed."));
            } else {
                println!(
                    "{} report was saved to: {}",
                    match output_format {
                        OutputFormat::Text => "Text",
                        OutputFormat::Json => "JSON",
                        OutputFormat::Markdown => "Markdown",
                    },
                    output_path.display()
                );
                println!("File write operation completed.");
            }
        }
    } else {
        println!("Error: {}", response.status());
    }

    Ok(())
}
