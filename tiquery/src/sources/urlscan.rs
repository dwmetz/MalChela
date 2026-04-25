use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct UrlScan {
    api_key: Option<String>,
}

impl UrlScan {
    pub fn new(api_key: Option<String>) -> Self {
        UrlScan { api_key }
    }
}

#[async_trait]
impl ThreatSource for UrlScan {
    fn name(&self) -> &str {
        "urlscan.io"
    }

    fn short_name(&self) -> &str {
        "URLSCAN"
    }

    async fn query(&self, input: &str) -> SourceResult {
        if !input.starts_with("http://") && !input.starts_with("https://") {
            return SourceResult::skipped(self.short_name(), "URL input required");
        }

        let client = match reqwest::Client::builder()
            .user_agent("malchela/tiquery")
            .build()
        {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        // URL-encode the query value
        let encoded = urlencoding_simple(input);
        let search_url = format!(
            "https://urlscan.io/api/v1/search/?q=page.url%3A%22{}%22&size=1",
            encoded
        );

        let mut req = client.get(&search_url);
        if let Some(ref key) = self.api_key {
            req = req.header("API-Key", key);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return SourceResult::error(self.short_name(), "invalid API key");
        }
        if !status.is_success() {
            return SourceResult::error(self.short_name(), format!("HTTP {}", status));
        }

        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let results = match body.get("results").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr,
            _ => return SourceResult::not_found(self.short_name()),
        };

        let hit = &results[0];
        let uuid = hit.get("_id").and_then(|v| v.as_str()).unwrap_or("");

        let verdicts = hit.get("verdicts").and_then(|v| v.get("overall"));
        let malicious = verdicts
            .and_then(|v| v.get("malicious"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let score = verdicts
            .and_then(|v| v.get("score"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let categories: Vec<String> = verdicts
            .and_then(|v| v.get("categories"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default();

        let brands: Vec<String> = verdicts
            .and_then(|v| v.get("brands"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default();

        let mut tags: Vec<String> = categories;
        tags.extend(brands);
        tags.dedup();

        let family = if malicious {
            tags.first().cloned().or_else(|| Some("malicious".to_string()))
        } else {
            Some("clean".to_string())
        };

        let detections = if malicious {
            Some(format!("malicious (score: {})", score))
        } else {
            Some(format!("clean (score: {})", score))
        };

        let first_seen = hit
            .get("task")
            .and_then(|t| t.get("time"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.get(..10))
            .map(str::to_string);

        let link = if uuid.is_empty() {
            None
        } else {
            Some(format!("https://urlscan.io/result/{}/", uuid))
        };

        SourceResult {
            source: self.short_name().to_string(),
            status: Some(SourceStatus::Found),
            family,
            detections,
            file_type: None,
            first_seen,
            link,
            file_name: None,
            tags,
            extra: Default::default(),
        }
    }
}

fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' | b':' | b'/' | b'?' | b'#'
            | b'[' | b']' | b'@' | b'!' | b'$' | b'&' | b'\'' | b'('
            | b')' | b'*' | b'+' | b',' | b';' | b'=' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
