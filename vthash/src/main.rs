extern crate prettytable;
use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::process;

fn main() {
    // Display ASCII art and metadata
    println!(
        "                                                                                                                                                                                                                                    
        ██████████████                        ░░░░░░████████                
        ████░░░░████████████                ░░░░░░██████                      
        ████░░░░████████████              ░░░░░░██                            
        ██░░░░░░████████████            ░░░░████                              
        ██░░░░░░████████████          ░░░░████                                
        ██░░░░░░░░██████████        ░░░░████                                  
        ██░░░░░░░░██████████    ░░░░░░████                                    
        ████░░░░░░██████████░░░░░░░░████                                      
        ██░░░░░░██████████░░░░██████                                        
        ██████████████████████████                                          
          ██████████████████████                                            
            ████████████████                                                
                                                                    
\n" 
    );
    println!("               VTHash");
    println!("     @dwmetz | bakerstreetforensics.com\n");
    println!("   It submits the hash to VirusTotal or it");
    println!("   gets the hose again.\n");

    // Prompt user for malware hash
    let mut hash = String::new();
    print!("Enter the malware hash value: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut hash).unwrap();
    let hash = hash.trim();

    // Generate timestamp and report filename
    let timestamp = Utc::now().format("%Y%m%d%H%M").to_string();
    let report_filename = format!("malhash-{}-{}.txt", hash, timestamp);

    // Open report file for writing
    let mut report_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&report_filename)
        .expect("Failed to create report file");

    // Write initial metadata
    write_output(&mut report_file, &format!("HASH: {}", hash));
    write_output(&mut report_file, &format!("DATE/TIME UTC: {}", Utc::now()));

    // Read VirusTotal API key
    let vt_api_key = read_api_key("vt-api.txt");

    // Submit hash to VirusTotal
    write_output(&mut report_file, &format!("\nSubmitting the hash {} to VirusTotal...\n", hash));
    let vt_url = format!(
        "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",
        vt_api_key, hash
    );

    match submit_request(&vt_url) {
        Ok(vt_results) => {
            write_output(&mut report_file, "** VIRUS TOTAL RESULTS: **");
            format_vt_results(&vt_results, &mut report_file);
        }
        Err(err) => {
            eprintln!("Failed to submit to VirusTotal: {}", err);
            process::exit(1);
        }
    }

    // Read Malware Bazaar API key
    let mb_api_key = read_api_key("mb-api.txt");

    // Submit hash to Malware Bazaar
    write_output(
        &mut report_file,
        &format!("\nSubmitting the hash {} to Malware Bazaar...\n", hash),
    );
    let mb_url = "https://mb-api.abuse.ch/api/v1/";

    let mb_data = json!({
        "query": "get_info",
        "hash": hash,
    });

    match submit_post_request(mb_url, mb_data, &mb_api_key) {
        Ok(mb_results) => {
            write_output(&mut report_file, "\n** MALWARE BAZAAR RESULTS: **");
            format_mb_results(&mb_results, &mut report_file);
        }
        Err(err) => {
            eprintln!("Failed to submit to Malware Bazaar: {}", err);
            process::exit(1);
        }
    }

    write_output(&mut report_file, "** END REPORT **");

    // Report the location of the output file
    println!("\nThe results have been saved to: {}", report_filename);
}

// Unified function to write output to both console and file
fn write_output<W: Write>(writer: &mut W, message: &str) {
    println!("{}", message); // Print to console
    writeln!(writer, "{}", message).unwrap(); // Write to file
}

// Function to read an API key from a file
fn read_api_key(file_path: &str) -> String {
    std::fs::read_to_string(file_path)
        .expect(&format!("Failed to read API key from '{}'", file_path))
        .trim()
        .to_string()
}

// Function to send GET requests and parse JSON responses
fn submit_request(url: &str) -> Result<Value, reqwest::Error> {
    let client = Client::new();
    let response = client.get(url).send()?;
    
    response.json()
}

// Function to send POST requests with form data and parse JSON responses
fn submit_post_request(
    url: &str,
    data: Value,
    api_key: &str,
) -> Result<Value, reqwest::Error> {
    let client = Client::new();

    client
        .post(url)
        .header("Auth-Key", api_key)
        .form(&data)
        .send()?
        .json()
}

// Function to extract and display VirusTotal results with permalink and detection summary
fn format_vt_results<W: Write>(vt_results: &Value, writer: &mut W) {
    if let Some(permalink) = vt_results.get("permalink").and_then(|v| v.as_str()) {
        write_output(writer, &format!("VirusTotal Permalink: {}", permalink));
        write_output(writer, "");
    }

    if let (Some(positives), Some(total)) = (
        vt_results.get("positives").and_then(|v| v.as_i64()),
        vt_results.get("total").and_then(|v| v.as_i64()),
    ) {
        write_output(writer, &format!("{} out of {} detected this sample.", positives, total));
        write_output(writer, "");
    }

    if let Some(scans) = vt_results.get("scans").and_then(|v| v.as_object()) {
        write_output(writer, "Detection Names:");
        for (engine_name, engine_data) in scans.iter() {
            if let Some(detected) = engine_data.get("detected").and_then(|v| v.as_bool()) {
                if detected {
                    if let Some(result) = engine_data.get("result").and_then(|v| v.as_str()) {
                        write_output(writer, &format!("- {}: {}", engine_name, result));
                    }
                }
            }
        }
        write_output(writer, "");
    } else {
        write_output(writer, "No detections found.");
        write_output(writer, "");
    }
}

fn format_mb_results<W: Write>(mb_results: &Value, writer: &mut W) {
    if let Some(data_array) = mb_results.get("data").and_then(|v| v.as_array()) {
        for data in data_array.iter() {
            if let Some(first_seen) = data.get("first_seen").and_then(|v| v.as_str()) {
                write_output(writer, &format!("First Seen: {}", first_seen));
            }
            if let Some(last_seen) = data.get("last_seen").and_then(|v| v.as_str()) {
                write_output(writer, &format!("Last Seen: {}", last_seen));
            }
            if let Some(file_type) = data.get("file_type").and_then(|v| v.as_str()) {
                write_output(writer, &format!("File Type: {}", file_type));
            }
            if let Some(delivery_method) = data.get("delivery_method").and_then(|v| v.as_str()) {
                write_output(writer, &format!("Delivery Method: {}", delivery_method));
            }

            // Add a blank line before hashes section
            write_output(writer, "");

            // Display hashes in a separate section at the end
            if let Some(sha256_hash) = data.get("sha256_hash").and_then(|v| v.as_str()) {
                write_output(writer, "Hashes:");
                write_output(writer, &format!("- SHA256 Hash: {}", sha256_hash));
            }
            if let Some(md5_hash) = data.get("md5_hash").and_then(|v| v.as_str()) {
                write_output(writer, &format!("- MD5 Hash: {}", md5_hash));
            }
            if let Some(sha1_hash) = data.get("sha1_hash").and_then(|v| v.as_str()) {
                write_output(writer, &format!("- SHA1 Hash: {}", sha1_hash));
            }

            // Add a blank line for readability after hashes section
            write_output(writer, "");

            // Process only one entry for clarity
            break;
        }

        if !data_array.is_empty() && data_array[0].get("yara_rules").is_some() {
            write_output(writer, "YARA Rule Matches:");

            for rule in data_array[0]["yara_rules"].as_array().unwrap_or(&vec![]) {
                if let Some(rule_name) = rule.get("rule_name").and_then(|v| v.as_str()) {
                    write_output(writer, &format!("- Rule Name: {}", rule_name));
                }
                if let Some(author) = rule.get("author").and_then(|v| v.as_str()) {
                    write_output(writer, &format!("  Author: {}", author));
                }
                if let Some(description) =
                    rule.get("description").and_then(|v| v.as_str())
                {
                    write_output(writer, &format!("  Description: {}", description));
                }
            }

            write_output(writer, "");
        } else {
            write_output(writer, "No YARA rules matched.");
        }
    } else {
        write_output(writer, "No data available from Malware Bazaar.");
    }
}

