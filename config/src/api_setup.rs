use std::fs;
use std::io::{self, Write};

pub fn run() {
    setup_api_key("VirusTotal", "vt-api.txt");
    setup_api_key("MalwareBazaar", "mb-api.txt");
}

fn setup_api_key(service_name: &str, file_name: &str) {
    println!("Enter your {} API key:", service_name);
    print!("> ");
    io::stdout().flush().unwrap();

    let mut api_key = String::new();
    io::stdin().read_line(&mut api_key).unwrap();
    let api_key = api_key.trim();

    if api_key.is_empty() {
        println!("No API key entered. Skipping {}.", service_name);
        return;
    }

    match fs::write(file_name, api_key) {
        Ok(_) => println!("Saved {} API key to {}", service_name, file_name),
        Err(e) => eprintln!("Failed to save {} API key: {}", service_name, e),
    }
}