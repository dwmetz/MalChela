use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct Triage {
    api_key: Option<String>,
}

impl Triage {
    pub fn new(api_key: Option<String>) -> Self {
        Triage { api_key }
    }
}

#[async_trait]
impl ThreatSource for Triage {
    fn name(&self) -> &str { "Triage (Recorded Future)" }
    fn short_name(&self) -> &str { "TR" }

    async fn query(&self, hash: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        let client = reqwest::Client::new();

        // Triage requires a typed hash prefix; use reqwest's query builder so the
        // colon is percent-encoded (%3A) which the API requires for exact hash lookups.
        let hash_prefix = match hash.len() {
            32 => "md5",
            40 => "sha1",
            64 => "sha256",
            _  => "sha256",
        };
        let typed_query = format!("{}:{}", hash_prefix, hash);

        // Step 1: search for the hash — /search queries public samples;
        // /samples only returns the authenticated user's own submissions.
        let resp = match client
            .get("https://tria.ge/api/v0/search")
            .query(&[("query", &typed_query)])
            .header("Authorization", format!("Bearer {}", key))
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

        let data = match body.get("data").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr.clone(),
            _ => return SourceResult::not_found(self.short_name()),
        };

        let sample = &data[0];
        let sample_id = match sample.get("id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return SourceResult::error(self.short_name(), "missing sample id"),
        };

        let file_name = sample.get("filename").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let submitted = sample.get("submitted").and_then(|v| v.as_str())
            .map(|s| s.chars().take(10).collect::<String>());

        // Step 2: fetch summary for family/tags/verdict
        let summary_url = format!("https://tria.ge/api/v0/samples/{}/summary", sample_id);
        let sum_resp = match client
            .get(&summary_url)
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let sum_text = match sum_resp.text().await {
            Ok(t) => t,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let sum: Value = serde_json::from_str(&sum_text).unwrap_or(Value::Null);

        let analysis = sum.get("analysis");

        let family: Option<String> = analysis
            .and_then(|a| a.get("family"))
            .and_then(|f| f.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let tags: Vec<String> = analysis
            .and_then(|a| a.get("tags"))
            .and_then(|t| t.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default();

        let score: Option<u64> = analysis
            .and_then(|a| a.get("score"))
            .and_then(|v| v.as_u64());

        let detections = score.map(|s| format!("score {}/10", s));

        SourceResult {
            source:     self.short_name().to_string(),
            status:     Some(SourceStatus::Found),
            family,
            detections,
            file_name,
            file_type:  None,
            first_seen: submitted,
            tags,
            link:       Some(format!("https://tria.ge/{}", sample_id)),
            extra:      Default::default(),
        }
    }
}
