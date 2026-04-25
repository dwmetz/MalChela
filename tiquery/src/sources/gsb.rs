use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct GoogleSafeBrowsing {
    api_key: Option<String>,
}

impl GoogleSafeBrowsing {
    pub fn new(api_key: Option<String>) -> Self {
        GoogleSafeBrowsing { api_key }
    }
}

#[async_trait]
impl ThreatSource for GoogleSafeBrowsing {
    fn name(&self) -> &str {
        "Google Safe Browsing"
    }

    fn short_name(&self) -> &str {
        "GSB"
    }

    async fn query(&self, input: &str) -> SourceResult {
        if !input.starts_with("http://") && !input.starts_with("https://") {
            return SourceResult::skipped(self.short_name(), "URL input required");
        }

        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let api_url = format!(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}",
            key
        );

        let body = serde_json::json!({
            "client": {
                "clientId": "malchela",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": input}]
            }
        });

        let resp = match client.post(&api_url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
            return SourceResult::error(self.short_name(), "invalid API key");
        }
        if !status.is_success() {
            let msg = resp.text().await.unwrap_or_default();
            let short = msg.lines().next().unwrap_or("HTTP error").to_string();
            return SourceResult::error(self.short_name(), short);
        }

        let data: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let matches = match data.get("matches").and_then(|v| v.as_array()) {
            Some(m) if !m.is_empty() => m.clone(),
            _ => {
                // Empty response body {} means the URL is clean
                return SourceResult::not_found(self.short_name());
            }
        };

        let threat_types: Vec<String> = matches
            .iter()
            .filter_map(|m| m.get("threatType").and_then(|v| v.as_str()))
            .map(|s| s.to_lowercase().replace('_', " "))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let family = threat_types.first().cloned();
        let detections = Some(format!("{} threat type(s)", matches.len()));

        SourceResult {
            source: self.short_name().to_string(),
            status: Some(SourceStatus::Found),
            family,
            detections,
            file_type: None,
            first_seen: None,
            link: Some(format!(
                "https://transparencyreport.google.com/safe-browsing/search?url={}",
                input
            )),
            file_name: None,
            tags: threat_types,
            extra: Default::default(),
        }
    }
}
