use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct HybridAnalysis {
    api_key: Option<String>,
}

impl HybridAnalysis {
    pub fn new(api_key: Option<String>) -> Self {
        HybridAnalysis { api_key }
    }
}

#[async_trait]
impl ThreatSource for HybridAnalysis {
    fn name(&self) -> &str { "Hybrid Analysis" }
    fn short_name(&self) -> &str { "HA" }

    async fn query(&self, hash: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        // HA's report/summary endpoint only accepts SHA256
        if hash.len() != 64 {
            return SourceResult::skipped(self.short_name(), "SHA256 only");
        }

        let client = match reqwest::Client::builder()
            .user_agent("Falcon Sandbox")
            .build()
        {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        // GET /api/v2/report/{sha256}/summary — current replacement for deprecated search/hash
        let url = format!("https://hybrid-analysis.com/api/v2/report/{}/summary", hash);
        let resp = match client
            .get(&url)
            .header("api-key", &key)
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

        // A 400 with "does not exist" message means not found
        if let Some(msg) = body.get("message").and_then(|v| v.as_str()) {
            if msg.contains("does not exist") || msg.contains("Not Found") {
                return SourceResult::not_found(self.short_name());
            }
            return SourceResult::error(self.short_name(), msg);
        }

        let av_detect   = body.get("av_detect").and_then(|v| v.as_u64());
        let threat_score = body.get("threat_score").and_then(|v| v.as_u64());
        let verdict     = body.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        let vx_family   = body.get("vx_family").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        let submit_name = body.get("submit_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        let sha256_val  = body.get("sha256").and_then(|v| v.as_str()).unwrap_or(hash);

        // type_short is an array; join first two entries
        let file_type = body.get("type_short")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str())
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|s| !s.is_empty())
            // fall back to the long "type" field
            .or_else(|| body.get("type").and_then(|v| v.as_str()).map(str::to_string));

        // Trim ISO timestamp to YYYY-MM-DD
        let first_seen = body.get("analysis_start_time")
            .and_then(|v| v.as_str())
            .map(|s| s.chars().take(10).collect::<String>());

        // Detections: prefer threat_score/100, fall back to av_detect count
        let detections = match (threat_score, av_detect) {
            (Some(ts), Some(av)) => Some(format!("{}/100 · {} AV", ts, av)),
            (None,     Some(av)) if av > 0 => Some(format!("{} AV", av)),
            (Some(ts), None)     => Some(format!("{}/100", ts)),
            _                    => None,
        };

        let tags = if !verdict.is_empty() { vec![verdict.to_string()] } else { vec![] };

        SourceResult {
            source:     self.short_name().to_string(),
            status:     Some(SourceStatus::Found),
            family:     vx_family.map(str::to_string),
            detections,
            file_name:  submit_name.map(str::to_string),
            file_type,
            first_seen,
            tags,
            link:       Some(format!("https://hybrid-analysis.com/sample/{}", sha256_val)),
            extra:      Default::default(),
        }
    }
}
