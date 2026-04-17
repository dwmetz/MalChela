use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct FileScan {
    api_key: Option<String>,
}

impl FileScan {
    pub fn new(api_key: Option<String>) -> Self {
        FileScan { api_key }
    }
}

#[async_trait]
impl ThreatSource for FileScan {
    fn name(&self) -> &str { "FileScan.IO" }
    fn short_name(&self) -> &str { "FS" }

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
            "https://www.filescan.io/api/reports/search?query={}",
            hash
        );

        let do_request = |client: &reqwest::Client| {
            client
                .get(&url)
                .header("X-Api-Key", &key)
                .header("accept", "application/json")
                .send()
        };

        let resp = match do_request(&client).await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        // On rate-limit: retry up to twice with increasing pauses (20s, then 40s).
        let resp = if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            let r2 = match do_request(&client).await {
                Ok(r) => r,
                Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
            };
            if r2.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                tokio::time::sleep(std::time::Duration::from_secs(40)).await;
                match do_request(&client).await {
                    Ok(r) => r,
                    Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
                }
            } else {
                r2
            }
        } else {
            resp
        };

        let status = resp.status();
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

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

        let body: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), format!("parse: {}", e)),
        };

        let items = match body.get("items").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr,
            _ => return SourceResult::not_found(self.short_name()),
        };

        // Use the most recent result (items are already date-sorted by the API)
        let record = &items[0];

        let verdict   = record.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        let item_id   = record.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let date      = record.get("date").and_then(|v| v.as_str());

        let file      = record.get("file").unwrap_or(&Value::Null);
        let sha256_val = file.get("sha256").and_then(|v| v.as_str()).unwrap_or(hash);
        let file_name = file.get("name").and_then(|v| v.as_str())
            // Skip names that are just the hash itself
            .filter(|n| !n.starts_with(sha256_val))
            .map(str::to_string);
        let file_type = file.get("short_type").and_then(|v| v.as_str())
            .or_else(|| file.get("mime_type").and_then(|v| v.as_str()))
            .map(str::to_string);

        // Collect unique tag names (FileScan can repeat tags across sources)
        let mut seen = std::collections::HashSet::new();
        let tags: Vec<String> = record
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.get("tag").and_then(|tg| tg.get("name")).and_then(|n| n.as_str()))
                    .filter(|name| seen.insert(name.to_string()))
                    .take(8)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let first_seen = date.map(|s| s.chars().take(10).collect::<String>());

        // Link to the specific scan report if we have an id, otherwise search page
        let link = if !item_id.is_empty() {
            format!("https://www.filescan.io/reports/{}", item_id)
        } else {
            format!("https://www.filescan.io/search?query={}", sha256_val)
        };

        // Verdict as detection label
        let detections = if !verdict.is_empty() {
            Some(verdict.to_string())
        } else {
            None
        };

        SourceResult {
            source:     self.short_name().to_string(),
            status:     Some(SourceStatus::Found),
            family:     None,  // FileScan doesn't give family names
            detections,
            file_name,
            file_type,
            first_seen,
            tags,
            link: Some(link),
            extra: Default::default(),
        }
    }
}
