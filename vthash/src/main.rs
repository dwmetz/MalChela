extern crate prettytable;
use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Write, stdin, stdout as std_stdout};
use std::process;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

fn write_both<W: Write>(writer: &mut W, stdout: &mut StandardStream, message: &str, color: Option<Color>) {
    if let Some(c) = color {
        stdout.set_color(ColorSpec::new().set_fg(Some(c))).unwrap();
        writeln!(stdout, "{}", message).unwrap();
        stdout.reset().unwrap();
    } else {
        writeln!(stdout, "{}", message).unwrap();
    }
    writeln!(writer, "{}", message).unwrap();
}

fn write_console(stdout: &mut StandardStream, message: &str, color: Option<Color>) {
    if let Some(c) = color {
        stdout.set_color(ColorSpec::new().set_fg(Some(c))).unwrap();
        write!(stdout, "{}", message).unwrap();
        stdout.reset().unwrap();
    } else {
        print!("{}", message);
    }
}

fn read_api_key(file_path: &str) -> String {
    if !std::path::Path::new(file_path).exists() {
        println!("API key file '{}' not found. Please enter your API key:", file_path);
        print!("> ");
        std_stdout().flush().unwrap();
        let mut api_key = String::new();
        stdin().read_line(&mut api_key).unwrap();
        let api_key = api_key.trim().to_string();

        fs::write(file_path, api_key.clone()).expect(&format!("Failed to create API key file '{}'", file_path));
        return api_key;
    }
    std::fs::read_to_string(file_path)
        .expect(&format!("Failed to read API key from '{}'", file_path))
        .trim()
        .to_string()
}

fn submit_request(url: &str) -> Result<Value, reqwest::Error> {
    let client = Client::new();
    let response = client.get(url).send()?;
    response.json()
}

fn submit_post_request(url: &str, data: Value, api_key: &str) -> Result<Value, reqwest::Error> {
    let client = Client::new();
    client
        .post(url)
        .header("Auth-Key", api_key)
        .form(&data)
        .send()?
        .json()
}
fn format_vt_results<W: Write>(vt_results: &Value, writer: &mut W, stdout: &mut StandardStream) {
    if let Some(permalink) = vt_results.get("permalink").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("VirusTotal Permalink: {}", permalink), Some(Color::Blue));
    }

    if let (Some(positives), Some(total)) = (
        vt_results.get("positives").and_then(|v| v.as_i64()),
        vt_results.get("total").and_then(|v| v.as_i64()),
    ) {
        write_both(writer, stdout, &format!("Detections: {} / {}", positives, total), Some(Color::Red));
    }

    if let Some(md5) = vt_results.get("md5").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("MD5: {}", md5), None);
    }
    if let Some(sha1) = vt_results.get("sha1").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("SHA1: {}", sha1), None);
    }
    if let Some(sha256) = vt_results.get("sha256").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("SHA256: {}", sha256), None);
    }
    if let Some(scan_date) = vt_results.get("scan_date").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("Scan Date: {}", scan_date), None);
    }

    if let Some(file_type_magic) = vt_results.get("file_type_magic").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("File Type (Magic): {}", file_type_magic), None);
    }
    if let Some(file_type) = vt_results.get("file_type").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("File Type: {}", file_type), None);
    }
    if let Some(size) = vt_results.get("size").and_then(|v| v.as_i64()) {
        write_both(writer, stdout, &format!("File Size: {} bytes", size), None);
    }
    if let Some(reputation) = vt_results.get("reputation").and_then(|v| v.as_i64()) {
        write_both(writer, stdout, &format!("Reputation: {}", reputation), None);
    }

    if let Some(last_analysis_stats) = vt_results.get("last_analysis_stats").and_then(|v| v.as_object()) {
        if let (Some(malicious), Some(suspicious), Some(harmless), Some(undetected), Some(type_unsupported)) = (
            last_analysis_stats.get("malicious").and_then(|v| v.as_i64()),
            last_analysis_stats.get("suspicious").and_then(|v| v.as_i64()),
            last_analysis_stats.get("harmless").and_then(|v| v.as_i64()),
            last_analysis_stats.get("undetected").and_then(|v| v.as_i64()),
            last_analysis_stats.get("type-unsupported").and_then(|v| v.as_i64()),
        ) {
            write_both(
                writer,
                stdout,
                &format!("Malicious: {}, Suspicious: {}, Harmless: {}, Undetected: {}, Type Unsupported: {}", malicious, suspicious, harmless, undetected, type_unsupported),
                None,
            );
        }
    }

    if let Some(pe_info) = vt_results.get("pe_info").and_then(|v| v.as_object()) {
        if let Some(imphash) = pe_info.get("imphash").and_then(|v| v.as_str()) {
            write_both(writer, stdout, &format!("PE Imphash: {}", imphash), None);
        }
        if let Some(entry_point) = pe_info.get("entry_point").and_then(|v| v.as_str()) {
            write_both(writer, stdout, &format!("PE Entry Point: {}", entry_point), None);
        }
        if let Some(timestamp) = pe_info.get("timestamp").and_then(|v| v.as_i64()) {
            write_both(writer, stdout, &format!("PE Timestamp: {}", timestamp), None);
        }
        if let (Some(company_name), Some(product_name)) = (pe_info.get("company_name").and_then(|v| v.as_str()), pe_info.get("product_name").and_then(|v| v.as_str())){
            write_both(writer, stdout, &format!("PE Company Name: {}, Product Name: {}", company_name, product_name), None);
        }

    }

    if let Some(scans) = vt_results.get("scans").and_then(|v| v.as_object()) {
        let mut seen_detections = HashSet::new();
        for (scanner, scan_result) in scans.iter() {
            if let (Some(detected), Some(result)) = (
                scan_result.get("detected").and_then(|v| v.as_bool()),
                scan_result.get("result").and_then(|v| v.as_str()),
            ) {
                if detected {
                    let detection_string = format!("{}: Detected - {}", scanner, result);
                    if seen_detections.insert(detection_string.clone()) {
                        write_both(writer, stdout, &detection_string, Some(Color::Cyan));
                    }
                }
            }
        }
    }
    write_both(writer, stdout, "", None);
}
fn format_mb_results<W: Write>(mb_results: &Value, writer: &mut W, stdout: &mut StandardStream) {
    if let Some(data) = mb_results.get("data").and_then(|v| v.as_array()) {
        if let Some(item) = data.get(0) {
            if let Some(sha256_hash) = item.get("sha256_hash").and_then(|v| v.as_str()) {
                // Permalink first
                write_both(writer, stdout, &format!("Malware Bazaar Permalink: https://mb-api.abuse.ch/sample/{}", sha256_hash), Some(Color::Blue));
                write_both(writer, stdout, &format!("Malware Bazaar SHA256: {}", sha256_hash), Some(Color::Cyan));
            }
            if let Some(file_type) = item.get("file_type").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar File Type: {}", file_type), None); // Removed Green Color
            }
            if let Some(file_name) = item.get("file_name").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar File Name: {}", file_name), None);
            }
            if let Some(file_size) = item.get("file_size").and_then(|v| v.as_i64()) {
                write_both(writer, stdout, &format!("Malware Bazaar File Size: {} bytes", file_size), None);
            }
            if let Some(first_seen) = item.get("first_seen").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar First Seen: {}", first_seen), None);
            }
            if let Some(tags) = item.get("tags").and_then(|v| v.as_array()) {
                let tags_str = tags
                    .iter()
                    .filter_map(|tag| tag.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ");
                write_both(writer, stdout, &format!("Malware Bazaar Tags: {}", tags_str), None);
            }
            if let Some(signature) = item.get("signature").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar Signature: {}", signature), None);
            }
            if let Some(imphash) = item.get("imphash").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar Imphash: {}", imphash), None);
            }
            if let Some(tlsh) = item.get("tlsh").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar TLSH: {}", tlsh), None);
            }
            if let Some(reporter) = item.get("reporter").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar Reporter: {}", reporter), None);
            }
            if let Some(intelligence) = item.get("intelligence").and_then(|v| v.as_object()) {
                 if let Some(clamav) = intelligence.get("clamav").and_then(|v| v.as_str()) {
                    write_both(writer, stdout,&format!("Malware Bazaar ClamAV: {}", clamav), None);
                 }
                 if let Some(yara_rules) = intelligence.get("yara_rules").and_then(|v| v.as_array()){
                    if !yara_rules.is_empty() {
                        let yara_rules_str = yara_rules.iter().filter_map(|rule| rule.as_str()).collect::<Vec<&str>>().join(", ");
                        write_both(writer, stdout, &format!("Malware Bazaar Yara Rules: {}", yara_rules_str), None);
                    } else {
                        write_both(writer, stdout, "Malware Bazaar Yara Rules: None", None);
                    }
                 } else {
                    write_both(writer, stdout, "Malware Bazaar Yara Rules: None", None);
                 }
            } else {
                write_both(writer,stdout,"Malware Bazaar Yara Rules: None",None);
            }
            if let Some(vendor_intel) = item.get("vendor_intel").and_then(|v| v.as_object()){
                for (vendor,intel) in vendor_intel.iter(){
                    if let Some(result) = intel.as_str(){
                        write_both(writer, stdout, &format!("Malware Bazaar Vendor Intel {}: {}",vendor, result), None);
                    }
                }
            }
        }
    } else if let Some(query_status) = mb_results.get("query_status").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("Malware Bazaar Query status: {}", query_status), Some(Color::Red));
    } else {
        write_both(writer, stdout, "Malware Bazaar: No Results found", Some(Color::Red));
    }
}
fn main() {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    write_console(&mut stdout, "                                                                                                                                                                                                                                    \n", Some(Color::Green));
    write_console(&mut stdout, "        ██████████████                        ░░░░░░████████                \n", Some(Color::Green));
    write_console(&mut stdout, "        ████░░░░████████████                ░░░░░░██████                      \n", Some(Color::Green));
    write_console(&mut stdout, "        ████░░░░████████████              ░░░░░░██                            \n", Some(Color::Green));
    write_console(&mut stdout, "        ██░░░░░░████████████            ░░░░████                              \n", Some(Color::Green));
    write_console(&mut stdout, "        ██░░░░░░████████████          ░░░░████                                \n", Some(Color::Green));
    write_console(&mut stdout, "        ██░░░░░░░░██████████        ░░░░████                                  \n", Some(Color::Green));
    write_console(&mut stdout, "        ████░░░░░░██████████░░░░░░░░████                                      \n", Some(Color::Green));
    write_console(&mut stdout, "        ██░░░░░░██████████░░░░██████                                        \n", Some(Color::Green));
    write_console(&mut stdout, "        ██████████████████████████                                          \n", Some(Color::Green));
    write_console(&mut stdout, "          ██████████████████████                                            \n", Some(Color::Green));
    write_console(&mut stdout, "            ████████████████                                                \n", Some(Color::Green));
    write_console(&mut stdout, "                                                                    \n\n", Some(Color::Green));

    write_console(&mut stdout, "               VTHash\n", Some(Color::Yellow));
    write_console(&mut stdout, "     @dwmetz | bakerstreetforensics.com\n", Some(Color::Yellow));
    write_console(&mut stdout, "   It submits the hash to VirusTotal or it\n", Some(Color::Yellow));
    write_console(&mut stdout, "   gets the hose again.\n\n", Some(Color::Yellow));

    let vt_api_key = read_api_key("vt-api.txt");
    let mb_api_key = read_api_key("mb-api.txt");

    let mut hash = String::new();
    print!("Enter the malware hash value: ");
    std_stdout().flush().unwrap();
    stdin().read_line(&mut hash).unwrap();
    let hash = hash.trim();

    let timestamp = Utc::now().format("%Y%m%d%H%M").to_string();
    let report_filename = format!("Saved_Output/malhash-{}-{}.txt", hash, timestamp);

    if let Err(e) = fs::create_dir_all("Saved_Output") {
        eprintln!("Failed to create Saved_Output directory: {}", e);
        process::exit(1);
    }

    let mut report_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&report_filename)
        .expect("Failed to create report file");

    write_both(&mut report_file, &mut stdout, &format!("HASH: {}", hash), None);
    write_both(&mut report_file, &mut stdout, &format!("DATE/TIME UTC: {}", Utc::now()), None);

    write_both(&mut report_file, &mut stdout, &format!("\nSubmitting the hash {} to VirusTotal...\n", hash), None);
    let vt_url = format!(
        "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",
        vt_api_key, hash
    );

    match submit_request(&vt_url) {
        Ok(vt_results) => {
            write_both(&mut report_file, &mut stdout, "VIRUS TOTAL RESULTS:", Some(Color::Yellow));
            format_vt_results(&vt_results, &mut report_file, &mut stdout);
        }
        Err(err) => {
            eprintln!("Failed to submit to VirusTotal: {}", err);
            process::exit(1);
        }
    }

    write_both(&mut report_file, &mut stdout, &format!("\nSubmitting the hash {} to Malware Bazaar...\n", hash), None);
    let mb_url = "https://mb-api.abuse.ch/api/v1/";

    let mb_data = json!({
        "query": "get_info",
        "hash": hash,
    });

    match submit_post_request(mb_url, mb_data, &mb_api_key) {
        Ok(mb_results) => {
            write_both(&mut report_file, &mut stdout, "\nMALWARE BAZAAR RESULTS:", Some(Color::Yellow));
            format_mb_results(&mb_results, &mut report_file, &mut stdout);
        }
        Err(err) => {
            eprintln!("Failed to submit to Malware Bazaar: {}", err);
            process::exit(1);
        }
    }

    write_both(&mut report_file, &mut stdout, "** END REPORT **", None);

    println!("\nThe results have been saved to: {}", report_filename);
}