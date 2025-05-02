extern crate prettytable;

use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{stdin, stdout as std_stdout, Write};
use std::path::PathBuf;
use std::process;
use common_config::get_output_dir;
use common_ui::styled_line;

fn write_both<W: Write>(writer: &mut W, stdout: &mut dyn Write, message: &str) {
    writeln!(stdout, "{}", message).unwrap();
    writeln!(writer, "{}", message).unwrap();
}

fn read_api_key(file_path: &str) -> Option<String> {
    if !std::path::Path::new(file_path).exists() {
        return None;
    }
    std::fs::read_to_string(file_path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn submit_request(url: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client.get(url).send()?;
    let text = response.text()?;
    let json = serde_json::from_str(&text)?;
    Ok(json)
}

fn submit_post_request(url: &str, data: Value, api_key: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client
        .post(url)
        .header("Auth-Key", api_key)
        .form(&data)
        .send()?;

    let text = response.text()?;  // Raw response for debugging
    let json: Value = serde_json::from_str(&text)?;
    Ok(json)
}

fn format_vt_results<W: Write>(vt_results: &Value, writer: &mut W, stdout: &mut dyn Write) {
    if let Some(permalink) = vt_results.get("permalink").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &format!("VirusTotal Permalink: {}", permalink));
    }

    if let (Some(positives), Some(total)) = (
        vt_results.get("positives").and_then(|v| v.as_i64()),
        vt_results.get("total").and_then(|v| v.as_i64()),
    ) {
        let detection_msg = format!("Detections: {} / {}", positives, total);
        let detection_tag = if positives > 0 { "red" } else { "stone" };
        write_both(writer, stdout, &styled_line(detection_tag, &detection_msg));
    }

    if let Some(md5) = vt_results.get("md5").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &styled_line("highlight", &format!("MD5: {}", md5)));
    }
    if let Some(sha1) = vt_results.get("sha1").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &styled_line("highlight", &format!("SHA1: {}", sha1)));
    }
    if let Some(sha256) = vt_results.get("sha256").and_then(|v| v.as_str()) {
        write_both(writer, stdout, &styled_line("highlight", &format!("SHA256: {}", sha256)));
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
                        write_both(writer, stdout, &detection_string);
                    }
                }
            }
        }
    }

    write_both(writer, stdout, "");
}

fn format_mb_results<W: Write>(mb_results: &Value, writer: &mut W, stdout: &mut dyn Write) {
    if let Some(data) = mb_results.get("data").and_then(|v| v.as_array()) {
        if let Some(item) = data.get(0) {
            for (key, val) in item.as_object().unwrap() {
                if let Some(val) = val.as_str() {
                    write_both(
                        writer,
                        stdout,
                        &format!("Malware Bazaar {}: {}", key.replace("_", " ").to_uppercase(), val),
                    );
                }
            }
        }
    } else {
        write_both(writer, stdout, "Malware Bazaar: No Results found");
    }
}

fn main() {
    let mut stdout = std_stdout();
    let args: Vec<String> = std::env::args().collect();
    let save_output = args.iter().any(|arg| arg == "-o" || arg == "--output")
        || std::env::var("MALCHELA_SAVE_OUTPUT").is_ok();

    let is_gui = args.len() > 1;

    let vt_api_key = read_api_key("vt-api.txt");
    let mb_api_key = read_api_key("mb-api.txt");

    if vt_api_key.is_none() || mb_api_key.is_none() {
        if is_gui {
            eprintln!(
                "Missing API key(s).  Please provide your VirusTotal and MalwareBazaar API keys in the Configuration menu."
            );
            process::exit(1);
        } else {
            if vt_api_key.is_none() {
                println!("vt-api.txt not found. Please enter your VirusTotal API key:");
                print!("> ");
                std_stdout().flush().unwrap();
                let mut key = String::new();
                stdin().read_line(&mut key).unwrap();
                let key = key.trim().to_string();
                fs::write("vt-api.txt", &key).expect("Failed to write vt-api.txt");
            }

            if mb_api_key.is_none() {
                println!("mb-api.txt not found. Please enter your MalwareBazaar API key:");
                print!("> ");
                std_stdout().flush().unwrap();
                let mut key = String::new();
                stdin().read_line(&mut key).unwrap();
                let key = key.trim().to_string();
                fs::write("mb-api.txt", &key).expect("Failed to write mb-api.txt");
            }
        }
    }

    let vt_api_key = read_api_key("vt-api.txt").unwrap();
    let mb_api_key = read_api_key("mb-api.txt").unwrap();

    let hash = args.iter()
        .skip(1)
        .find(|arg| !arg.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| {
            print!("Enter the malware hash value: ");
            std_stdout().flush().unwrap();
            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

    let in_gui = std::env::var("MALCHELA_GUI_MODE").is_ok();
    let (mut report_file, report_path) = if save_output && !in_gui {
        let timestamp = Utc::now().format("%Y%m%d%H%M").to_string();
        let filename = format!("malhash-{}-{}.txt", hash, timestamp);
        let output_dir: PathBuf = get_output_dir("malhash");
        let report_path = output_dir.join(&filename);

        if let Some(parent) = report_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("Failed to create output directory: {}", e);
                process::exit(1);
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&report_path)
            .expect("Failed to create report file");
        (file, Some(report_path))
    } else {
        (OpenOptions::new().write(true).open("/dev/null").unwrap(), None)
    };

    write_both(&mut report_file, &mut stdout, &format!("HASH: {}", hash));
    write_both(&mut report_file, &mut stdout, &format!("DATE/TIME UTC: {}", Utc::now()));

    write_both(
        &mut report_file,
        &mut stdout,
        &format!("\nSubmitting the hash {} to VirusTotal...\n", hash),
    );

    let vt_url = format!(
        "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",
        vt_api_key, hash
    );

    match submit_request(&vt_url) {
        Ok(vt_results) => {
            write_both(&mut report_file, &mut stdout, &styled_line("NOTE", "VIRUS TOTAL RESULTS:"));
            format_vt_results(&vt_results, &mut report_file, &mut stdout);
        }
        Err(err) => {
            eprintln!("Failed to submit to VirusTotal: {}", err);
            process::exit(1);
        }
    }

    write_both(
        &mut report_file,
        &mut stdout,
        &format!("\nSubmitting the hash {} to Malware Bazaar...\n", hash),
    );

    let mb_url = "https://mb-api.abuse.ch/api/v1/";
    let mb_data = json!({ "query": "get_info", "hash": hash });

    match submit_post_request(mb_url, mb_data, &mb_api_key) {
        Ok(mb_results) => {
            write_both(&mut report_file, &mut stdout, &styled_line("NOTE", "MALWARE BAZAAR RESULTS:"));
            format_mb_results(&mb_results, &mut report_file, &mut stdout);
        }
        Err(err) => {
            eprintln!("Failed to submit to Malware Bazaar: {}", err);
            process::exit(1);
        }
    }

    write_both(&mut report_file, &mut stdout, &styled_line("green", "** END REPORT **"));
    if let Some(path) = report_path {
        println!("\n{}\n", styled_line("green", &format!("The results have been saved to: {}", path.display())));
    } else {
        println!("{}", styled_line("stone", "Output was not saved."));
    }
}