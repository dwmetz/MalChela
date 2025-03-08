// SECTION 1: Start of main.rs

extern crate prettytable;
use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
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
        write_both(writer, stdout, &format!("VirusTotal Permalink: {}", permalink), Some(Color::Cyan));
    }

    if let (Some(positives), Some(total)) = (
        vt_results.get("positives").and_then(|v| v.as_i64()),
        vt_results.get("total").and_then(|v| v.as_i64()),
    ) {
        write_both(writer, stdout, &format!("Detections: {} / {}", positives, total), Some(Color::Green));
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
                        write_both(writer, stdout, &detection_string, Some(Color::Red));
                    }
                }
            }
        }
    }
    write_both(writer, stdout, "", None); // Add a blank line
}

fn format_mb_results<W: Write>(mb_results: &Value, writer: &mut W, stdout: &mut StandardStream) {
    if let Some(data) = mb_results.get("data").and_then(|v| v.as_array()) {
        if let Some(item) = data.get(0) {
            if let Some(sha256_hash) = item.get("sha256_hash").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar SHA256: {}", sha256_hash), Some(Color::Cyan));
            }
            if let Some(file_type) = item.get("file_type").and_then(|v| v.as_str()) {
                write_both(writer, stdout, &format!("Malware Bazaar File Type: {}", file_type), Some(Color::Green));
            }
        }
    } else if let Some(query_status) = mb_results.get("query_status").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("Malware Bazaar Query status: {}", query_status), Some(Color::Red));
    } else {
        write_both(writer, stdout, "Malware Bazaar: No Results found", Some(Color::Red));
    }
}
// SECTION 2: Start of main.rs (Continued)

fn main() {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    // Only write ASCII art and program description to the console
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

    let mut hash = String::new();
    print!("Enter the malware hash value: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut hash).unwrap();
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

    let vt_api_key = read_api_key("vt-api.txt");

    write_both(&mut report_file, &mut stdout, &format!("\nSubmitting the hash {} to VirusTotal...\n", hash), None);
    let vt_url = format!(
        "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",
        vt_api_key, hash
    );

    match submit_request(&vt_url) {
        Ok(vt_results) => {
            write_both(&mut report_file, &mut stdout, "** VIRUS TOTAL RESULTS: **", None);
            format_vt_results(&vt_results, &mut report_file, &mut stdout);
        }
        Err(err) => {
            eprintln!("Failed to submit to VirusTotal: {}", err);
            process::exit(1);
        }
    }

    let mb_api_key = read_api_key("mb-api.txt");

    write_both(&mut report_file, &mut stdout, &format!("\nSubmitting the hash {} to Malware Bazaar...\n", hash), None);
    let mb_url = "https://mb-api.abuse.ch/api/v1/";

    let mb_data = json!({
        "query": "get_info",
        "hash": hash,
    });

    match submit_post_request(mb_url, mb_data, &mb_api_key) {
        Ok(mb_results) => {
            write_both(&mut report_file, &mut stdout, "\n** MALWARE BAZAAR RESULTS: **", None);
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

// SECTION 2: End of main.rs