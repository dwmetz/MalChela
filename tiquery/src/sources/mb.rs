use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct MalwareBazaar {
    api_key: Option<String>,
}

impl MalwareBazaar {
    pub fn new(api_key: Option<String>) -> Self {
        MalwareBazaar { api_key }
    }

    /// Download a sample zip from MalwareBazaar into `output_dir`.
    /// Returns the path of the saved zip on success.
    /// Zip is password-protected with "infected" (MalwareBazaar standard).
    pub async fn download_sample(&self, sha256: &str, output_dir: &Path) -> Result<PathBuf, String> {
        let key = self.api_key.as_deref()
            .ok_or("No MalwareBazaar API key configured")?;

        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| e.to_string())?;

        let response = client
            .post("https://mb-api.abuse.ch/api/v1/")
            .header("Auth-Key", key)
            .form(&[("query", "get_file"), ("sha256_hash", sha256)])
            .send()
            .await
            .map_err(|e| format!("request error: {}", e))?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("download error: {}", e))?;

        // Detect by magic bytes — MB sometimes returns a zip with content-type: application/json
        let is_zip = bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06");
        if !is_zip {
            // Try to parse as a JSON error response
            let status = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("query_status").and_then(|s| s.as_str()).map(str::to_string));
            return match status.as_deref() {
                Some(s) => Err(format!("MB API: {}", s)),
                None => Err(format!("unexpected response: {}", String::from_utf8_lossy(&bytes[..bytes.len().min(120)]))),
            };
        }

        std::fs::create_dir_all(output_dir)
            .map_err(|e| format!("could not create output dir: {}", e))?;

        let zip_name = format!("{}.zip", &sha256[..16]);
        let zip_path = output_dir.join(zip_name);
        std::fs::write(&zip_path, &bytes)
            .map_err(|e| format!("write error: {}", e))?;

        Ok(zip_path)
    }
}

#[async_trait]
impl ThreatSource for MalwareBazaar {
    fn name(&self) -> &str {
        "MalwareBazaar"
    }

    fn short_name(&self) -> &str {
        "MB"
    }

    async fn query(&self, hash: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let res = client
            .post("https://mb-api.abuse.ch/api/v1/")
            .header("Auth-Key", &key)
            .form(&[("query", "get_info"), ("hash", hash)])
            .send()
            .await;

        let body: Value = match res {
            Ok(r) => match r.json().await {
                Ok(v) => v,
                Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
            },
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let status = body.get("query_status").and_then(|v| v.as_str()).unwrap_or("");

        if status == "hash_not_found" || status == "illegal_hash" {
            return SourceResult::not_found(self.short_name());
        }

        if status != "ok" {
            return SourceResult::error(self.short_name(), format!("unexpected status: {}", status));
        }

        let data = match body.get("data").and_then(|v| v.as_array()).and_then(|a| a.first()) {
            Some(d) => d.clone(),
            None => return SourceResult::not_found(self.short_name()),
        };

        let sha256 = data.get("sha256_hash").and_then(|v| v.as_str()).unwrap_or(hash);

        let tags: Vec<String> = data
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
            .unwrap_or_default();

        SourceResult {
            source: self.short_name().to_string(),
            status: Some(SourceStatus::Found),
            family: data.get("signature").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
            file_name: data.get("file_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
            file_type: data.get("file_type_guess").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
            first_seen: data.get("first_seen").and_then(|v| v.as_str()).map(str::to_string),
            tags,
            link: Some(format!("https://bazaar.abuse.ch/sample/{}/", sha256)),
            detections: None,
            extra: Default::default(),
        }
    }
}
