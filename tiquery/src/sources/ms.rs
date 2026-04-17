use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct Malshare {
    api_key: Option<String>,
}

impl Malshare {
    pub fn new(api_key: Option<String>) -> Self {
        Malshare { api_key }
    }
}

#[async_trait]
impl ThreatSource for Malshare {
    fn name(&self) -> &str { "Malshare" }
    fn short_name(&self) -> &str { "MS" }

    async fn query(&self, hash: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let url = format!(
            "https://malshare.com/api.php?api_key={}&action=details&hash={}",
            key, hash
        );

        let resp = match client
            .get(&url)
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let status = resp.status();
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        if status == reqwest::StatusCode::NOT_FOUND {
            return SourceResult::not_found(self.short_name());
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return SourceResult::error(self.short_name(), "invalid API key");
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return SourceResult::error(self.short_name(), "rate limited");
        }
        if !status.is_success() {
            let snippet = text.chars().take(120).collect::<String>();
            return SourceResult::error(self.short_name(), format!("HTTP {} — {}", status.as_u16(), snippet));
        }

        // Empty body = not found (Malshare returns 200 with empty body for unknown hashes)
        if text.trim().is_empty() {
            return SourceResult::not_found(self.short_name());
        }

        let body: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), format!("parse: {}", e)),
        };

        // Malshare uses uppercase keys: MD5, SHA1, SHA256, SSDEEP, F_TYPE, FILENAMES
        // An error response looks like {"ERROR": {"CODE": ..., "MESSAGE": "..."}}
        if let Some(err) = body.get("ERROR") {
            let msg = err.get("MESSAGE").and_then(|v| v.as_str()).unwrap_or("unknown error");
            if msg.contains("hash not found") || msg.contains("Not Found") {
                return SourceResult::not_found(self.short_name());
            }
            return SourceResult::error(self.short_name(), msg);
        }

        // If MD5 is missing the record is empty / not found
        if body.get("MD5").and_then(|v| v.as_str()).is_none() {
            return SourceResult::not_found(self.short_name());
        }

        let sha256_val = body.get("SHA256").and_then(|v| v.as_str()).unwrap_or(hash);
        let file_type  = body.get("F_TYPE").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let file_name = body.get("FILENAMES")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // Use F_TYPE as a tag if present
        let tags: Vec<String> = file_type.as_deref()
            .map(|ft| vec![ft.to_string()])
            .unwrap_or_default();

        let link = format!(
            "https://malshare.com/sample.php?action=detail&hash={}",
            sha256_val
        );

        SourceResult {
            source:     self.short_name().to_string(),
            status:     Some(SourceStatus::Found),
            family:     None,
            detections: None,
            file_name,
            file_type,
            first_seen: None,
            tags,
            link: Some(link),
            extra: Default::default(),
        }
    }
}
