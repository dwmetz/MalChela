use reqwest::{Client, Error, header};
use serde_json::Value;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn find_workspace_root() -> io::Result<PathBuf> {
    let exe_path = env::current_exe()?;
    let mut current_dir = exe_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Executable parent not found"))?
        .to_path_buf();

    loop {
        let cargo_toml_path = current_dir.join("Cargo.toml");
        if cargo_toml_path.exists() && cargo_toml_path.is_file() {
            let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
            if cargo_toml_content.contains("[workspace]") {
                return Ok(current_dir);
            } else {
                let mut parent_dir = current_dir.clone();
                while parent_dir.pop() {
                    let parent_cargo_toml_path = parent_dir.join("Cargo.toml");
                    if parent_cargo_toml_path.exists() && parent_cargo_toml_path.is_file() {
                        let parent_cargo_toml_content = fs::read_to_string(&parent_cargo_toml_path)?;
                        if parent_cargo_toml_content.contains("[workspace]") {
                            return Ok(parent_dir);
                        }
                    }
                }
                return Ok(current_dir);
            }
        }
        if !current_dir.pop() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Cargo.toml not found",
            ));
        }
    }
}

fn read_api_key_from_file(workspace_root: &Path) -> io::Result<String> {
    let api_key_path = workspace_root.join("vt-api.txt");
    //println!("Attempting to read API key from: {:?}", api_key_path);
    fs::read_to_string(api_key_path)
}

async fn submit_request(url: &str, api_key: &str) -> Result<Value, Error> {
    let client = Client::new();
    let mut headers = header::HeaderMap::new();
    headers.insert("x-apikey", header::HeaderValue::from_str(api_key).unwrap());

    let response = client.get(url).headers(headers).send().await?;
    response.json().await
}

pub async fn check_virustotal(hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let workspace_root = find_workspace_root()?;
    let api_key = read_api_key_from_file(&workspace_root)?;

    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    match submit_request(&url, &api_key).await {
        Ok(response) => {
            if let Some(malicious) = response["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64() {
                return Ok(malicious > 0);
            }
            Ok(false) // Default to "No" if no data is available
        }
        Err(e) => Err(Box::new(e)),
    }
}