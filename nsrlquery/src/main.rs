use clap::Parser;
use reqwest;
use serde_json::Value;
use std::io;
use colored::*;
use common_ui::styled_line;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct CliArgs {
    /// Hash value to look up
    hash: Option<String>,

    /// Save output to a report file
    #[clap(short = 'o', long = "output")]
    save_output: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let cli = CliArgs::parse();
    let hash = cli.hash.unwrap_or_else(|| {
        println!("Enter the hash value:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        input.trim().to_string()
    });

    println!("\n{}", styled_line("NOTE", "Results from CIRCL Hash Lookup:"));

    let save_output = cli.save_output || std::env::var("MALCHELA_SAVE_OUTPUT").ok().as_deref() == Some("1");
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
            let output_dir = std::env::current_dir()?.join("saved_output/nsrlquery");
            fs::create_dir_all(&output_dir)?;
            let output_path = output_dir.join(format!("report_{}.txt", hash));
            fs::write(&output_path, &report)?;
            println!("\n{}", styled_line("green", &format!("Saved report to: {}", output_path.display())));
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
