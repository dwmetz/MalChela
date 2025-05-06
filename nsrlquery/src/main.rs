use clap::{Parser, ValueEnum};
use reqwest;
use serde_json;
use serde_json::Value;
use std::io;
use colored::*;
use common_ui::styled_line;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Parser, Debug)]
#[clap(next_help_heading = "Output Control", disable_help_flag = true)]
#[clap(author, version, about)]
struct CliArgs {
    /// Hash value to look up
    hash: Option<String>,

    /// Save output to a report file
    #[clap(short = 'o', long = "output")]
    save_output: bool,

    /// Choose output format: text, json, or markdown
    #[clap(value_enum, short = 't', long = "type", requires = "save_output")]
    output_format: Option<OutputFormat>,
}

fn normalize_output_flags(args: &mut Vec<String>) {
    if args.contains(&"-o".to_string()) || args.contains(&"--output".to_string()) {
        let mut output_specified = false;

        if let Some(index) = args.iter().position(|x| x == "-j") {
            args.remove(index);
            args.push("-t".to_string());
            args.push("json".to_string());
            output_specified = true;
        } else if let Some(index) = args.iter().position(|x| x == "-m") {
            args.remove(index);
            args.push("-t".to_string());
            args.push("markdown".to_string());
            output_specified = true;
        }

        if let Some(index) = args.iter().position(|x| x == "-t" || x == "--type") {
            if index + 1 >= args.len() {
                args.push("text".to_string());
                output_specified = true;
            } else {
                let next_arg = &args[index + 1];
                let valid_formats = ["text", "json", "markdown"];
                if !next_arg.starts_with('-') && valid_formats.contains(&next_arg.to_lowercase().as_str()) {
                    output_specified = true;
                } else {
                    eprintln!("Error: Output format required. Use -t, -j, or -m with -o.");
                    std::process::exit(1);
                }
            }
        }

        if !output_specified {
            eprintln!("Error: Output format required. Use -t, -j, or -m with -o.");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut args: Vec<String> = std::env::args().collect();
    normalize_output_flags(&mut args);
    let mut cli = CliArgs::parse_from(args);

    if cli.hash.is_none() {
        println!("Enter the hash value:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        cli.hash = Some(input.trim().to_string());
    }

    let hash = cli.hash.clone().unwrap();

    println!("\n{}", styled_line("NOTE", "Results from CIRCL Hash Lookup:"));

    let save_output = cli.save_output || std::env::var("MALCHELA_SAVE_OUTPUT").ok().as_deref() == Some("1");
    let output_format = cli.output_format.unwrap_or(OutputFormat::Text);
    let mut report = String::new();
    report += &format!("Results from CIRCL Hash Lookup:\n\n");

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

        if let Some(filename) = json.get("FileName").and_then(|v| v.as_str()) {
            println!("{}", styled_line("highlight", &format!("FileName: {}", filename)));
            report += &format!("FileName: {}\n", filename);
        }
        if let Some(filesize) = json.get("FileSize").and_then(|v| v.as_str()) {
            println!("{}", styled_line("highlight", &format!("FileSize: {} bytes", filesize)));
            report += &format!("FileSize: {} bytes\n", filesize);
        }
        if let Some(md5) = json.get("MD5").and_then(|v| v.as_str()) {
            println!("{}", styled_line("highlight_hash", &format!("MD5: {}", md5)));
            report += &format!("MD5: {}\n", md5);
        }
        if let Some(sha1) = json.get("SHA-1").and_then(|v| v.as_str()) {
            println!("{}", styled_line("highlight_hash", &format!("SHA-1: {}", sha1)));
            report += &format!("SHA-1: {}\n", sha1);
        }
        if let Some(sha256) = json.get("SHA-256").and_then(|v| v.as_str()) {
            println!("{}", styled_line("highlight_hash", &format!("SHA-256: {}", sha256)));
            report += &format!("SHA-256: {}\n", sha256);
        }
        if let Some(mimetype) = json.get("mimetype").and_then(|v| v.as_str()) {
            println!("{}", styled_line("stone", &format!("Mimetype: {}", mimetype)));
            report += &format!("Mimetype: {}\n", mimetype);
        }
        if let Some(product) = json.get("ProductCode") {
            if let Some(name) = product.get("ProductName").and_then(|v| v.as_str()) {
                if let Some(version) = product.get("ProductVersion").and_then(|v| v.as_str()) {
                    println!("{}", styled_line("stone", &format!("Platform: {} (v{})", name, version)));
                    report += &format!("Platform: {} (v{})\n", name, version);
                } else {
                    println!("{}", styled_line("stone", &format!("Platform: {}", name)));
                    report += &format!("Platform: {}\n", name);
                }
            }
        }
        if let Some(pkg_name) = json.get("PackageName").and_then(|v| v.as_str()) {
            println!("{}", styled_line("highlight", &format!("Package Name: {}", pkg_name)));
            report += &format!("Package Name: {}\n", pkg_name);
        }
        if let Some(pkg_desc) = json.get("PackageDescription").and_then(|v| v.as_str()) {
            println!("{}", styled_line("stone", &format!("Package Description:\n{}", pkg_desc)));
            report += &format!("Package Description:\n{}\n", pkg_desc);
        }
        if let Some(os) = json.get("OpSystemCode") {
            if let Some(name) = os.get("OpSystemName").and_then(|v| v.as_str()) {
                println!("{}", styled_line("stone", &format!("Operating System: {}", name)));
                report += &format!("Operating System: {}\n", name);
            }
        }
        if let Some(trust) = json.get("hashlookup:trust").and_then(|v| v.as_u64()) {
            println!("{}", styled_line("yellow", &format!("Trust Score: {}", trust)));
            report += &format!("Trust Score: {}\n", trust);
        }
        if let Some(parents) = json.get("parents").and_then(|v| v.as_array()) {
            println!("{}", styled_line("stone", &format!("Parent Count: {}", parents.len())));
            report += &format!("Parent Count: {}\n", parents.len());
        }
        if let Some(ssdeep) = json.get("SSDEEP").and_then(|v| v.as_str()) {
            println!("{}", styled_line("stone", &format!("Fuzzy Hash (SSDEEP): {}", ssdeep)));
            report += &format!("Fuzzy Hash (SSDEEP): {}\n", ssdeep);
        }
        if let Some(tlsh) = json.get("TLSH").and_then(|v| v.as_str()) {
            println!("{}", styled_line("stone", &format!("Fuzzy Hash (TLSH): {}", tlsh)));
            report += &format!("Fuzzy Hash (TLSH): {}\n", tlsh);
        }

        if save_output {
            use std::fs;
            let ext = match output_format {
                OutputFormat::Text => "txt",
                OutputFormat::Json => "json",
                OutputFormat::Markdown => "md",
            };
            let output_dir = std::env::current_dir()?.join("saved_output/nsrlquery");
            fs::create_dir_all(&output_dir)?;
            let output_path = output_dir.join(format!("report_{}.{}", hash, ext));
            match output_format {
                OutputFormat::Text | OutputFormat::Markdown => {
                    fs::write(&output_path, &report)?;
                }
                OutputFormat::Json => {
                    fs::write(&output_path, serde_json::to_string_pretty(&json)?)?;
                }
            }
            println!(
                "\n{}",
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
        } else {
            println!("{}", "Output was not saved.".bold().yellow());
        }
    } else if response.status().as_u16() == 404 {
        println!("Hash not found in the database.");
    } else {
        println!("Error: {}", response.status());
    }

    Ok(())
}
