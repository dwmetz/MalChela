use reqwest::{Client, Error, header};
use serde_json::Value;
use std::io;

async fn submit_request(url: &str, api_key: &str) -> Result<Value, Error> {
    let client = Client::new();
    let mut headers = header::HeaderMap::new();
    headers.insert("x-apikey", header::HeaderValue::from_str(api_key).unwrap());

    let response = client.get(url).headers(headers).send().await?;
    response.json().await
}

pub async fn check_virustotal(hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let api_key = common_config::resolve_api_key("vt")
        .ok_or_else(|| io::Error::new(
            io::ErrorKind::NotFound,
            "VT API key not found in api/vt-api.txt. Please set it in the Configuration menu."
        ))?;

    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    match submit_request(&url, &api_key).await {
        Ok(response) => {
            if let Some(malicious) = response["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64() {
                return Ok(malicious > 0);
            }
            Ok(false)
        }
        Err(e) => Err(Box::new(e)),
    }
}