use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

/// MetaDefender Cloud (OPSWAT) — hash lookup across 40+ AV engines.
/// Free tier registration: https://metadefender.opswat.com/
pub struct MetaDefender {
    api_key: Option<String>,
}

impl MetaDefender {
    pub fn new(api_key: Option<String>) -> Self {
        MetaDefender { api_key }
    }
}

#[async_trait]
impl ThreatSource for MetaDefender {
    fn name(&self) -> &str { "MetaDefender Cloud" }
    fn short_name(&self) -> &str { "MD" }

    async fn query(&self, hash: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        let client = match reqwest::Client::builder()
            .user_agent("tiquery/0.1 MalChela")
            .build()
        {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let url = format!("https://api.metadefender.com/v4/hash/{}", hash);

        let resp = match client
            .get(&url)
            .header("apikey", &key)
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
        if text.trim().is_empty() {
            return SourceResult::not_found(self.short_name());
        }

        let body: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), format!("parse: {}", e)),
        };

        // Check for API-level error object
        if let Some(errs) = body.get("error").and_then(|v| v.as_array()) {
            if let Some(msg) = errs.first()
                .and_then(|e| e.get("messages"))
                .and_then(|m| m.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                if msg.to_lowercase().contains("not found") {
                    return SourceResult::not_found(self.short_name());
                }
                return SourceResult::error(self.short_name(), msg);
            }
            return SourceResult::not_found(self.short_name());
        }

        let scan = body.get("scan_results").unwrap_or(&Value::Null);
        let file_info = body.get("file_info").unwrap_or(&Value::Null);

        let total_detected = scan.get("total_detected_avs").and_then(|v| v.as_u64());
        let total_avs      = scan.get("total_avs").and_then(|v| v.as_u64());
        let threat_name    = scan.get("threat_found").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let verdict        = scan.get("scan_all_result_a").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let start_time     = scan.get("start_time").and_then(|v| v.as_str())
            .map(|s| s.chars().take(10).collect::<String>());

        let file_name = file_info.get("display_name").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            // Skip names that are just the hash itself
            .filter(|n| n.len() != 32 && n.len() != 40 && n.len() != 64)
            .map(str::to_string);
        let file_type = file_info.get("file_type_description").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let sha256_val = file_info.get("sha256").and_then(|v| v.as_str()).unwrap_or(hash);

        let detections = match (total_detected, total_avs) {
            (Some(d), Some(t)) => Some(format!("{}/{}", d, t)),
            (Some(d), None)    => Some(format!("{} detected", d)),
            _                  => None,
        };

        // Family from threat_found; verdict as tag
        let tags = match verdict {
            Some(v) => vec![v.to_string()],
            None    => vec![],
        };

        let link = format!("https://metadefender.opswat.com/results/file/{}/regular/overview", sha256_val);

        SourceResult {
            source:     self.short_name().to_string(),
            status:     Some(SourceStatus::Found),
            family:     threat_name.map(str::to_string),
            detections,
            file_name,
            file_type,
            first_seen: start_time,
            tags,
            link: Some(link),
            extra:      Default::default(),
        }
    }
}
