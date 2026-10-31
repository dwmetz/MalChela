//! GreyNoise (IP addresses only).
//!
//! Uses the Community API (`/v3/community/{ip}`), which works with a free
//! key: it says whether an IP has been seen mass-scanning the internet
//! ("noise") or belongs to a known benign business service ("RIOT": CDNs,
//! cloud providers, public DNS, update servers), with GreyNoise's
//! classification. Both answers help tell a hardcoded C2 apart from
//! infrastructure a sample merely references.

use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct GreyNoise {
    api_key: Option<String>,
}

impl GreyNoise {
    pub fn new(api_key: Option<String>) -> Self {
        GreyNoise { api_key }
    }
}

#[async_trait]
impl ThreatSource for GreyNoise {
    fn name(&self) -> &str {
        "GreyNoise"
    }

    fn short_name(&self) -> &str {
        "GN"
    }

    async fn query(&self, input: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };
        let ip: std::net::IpAddr = match input.parse() {
            Ok(ip) => ip,
            Err(_) => return SourceResult::skipped(self.short_name(), "IP addresses only"),
        };
        if ip.is_ipv6() {
            return SourceResult::skipped(self.short_name(), "IPv4 only (Community API)");
        }

        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };
        let url = format!("https://api.greynoise.io/v3/community/{}", ip);
        let resp = match client.get(&url).header("key", &key).header("Accept", "application/json").send().await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            // "IP not observed scanning the internet or contained in RIOT data set."
            return SourceResult::not_found(self.short_name());
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return SourceResult::error(self.short_name(), "rate limited (Community API daily limit)");
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return SourceResult::error(self.short_name(), "API key rejected");
        }
        if !status.is_success() {
            return SourceResult::error(self.short_name(), format!("HTTP {}", status.as_u16()));
        }
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), format!("parse: {}", e)),
        };
        result_from(self.short_name(), &ip.to_string(), &body)
    }
}

/// Build the result from a Community API response (split out for tests).
fn result_from(short: &str, ip: &str, body: &Value) -> SourceResult {
    let noise = body.get("noise").and_then(Value::as_bool).unwrap_or(false);
    let riot = body.get("riot").and_then(Value::as_bool).unwrap_or(false);
    if !noise && !riot {
        return SourceResult::not_found(short);
    }
    let classification = body.get("classification").and_then(Value::as_str).unwrap_or("unknown").to_string();
    let name = body.get("name").and_then(Value::as_str).filter(|n| !n.is_empty() && *n != "unknown").unwrap_or("");
    // Short enough for the results table: "RIOT" is GreyNoise's name for
    // its known-benign business services (CDNs, public DNS, cloud).
    let family = match (riot, name.is_empty()) {
        (true, false) => format!("RIOT: {}", name),
        (true, true) => "RIOT: known benign service".to_string(),
        (false, false) => format!("scanner: {}", name),
        (false, true) => "internet scanner".to_string(),
    };
    // RIOT addresses can also scan; say so, since that is not implied.
    let tags = if riot && noise { vec!["also scanning".to_string()] } else { Vec::new() };
    let mut extra = std::collections::HashMap::new();
    if let Some(ls) = body.get("last_seen").and_then(Value::as_str) {
        extra.insert("last_seen".to_string(), Value::String(ls.to_string()));
    }
    SourceResult {
        source: short.to_string(),
        status: Some(SourceStatus::Found),
        family: Some(family),
        detections: Some(classification),
        tags,
        link: Some(
            body.get("link")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("https://viz.greynoise.io/ip/{}", ip)),
        ),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn riot_and_noise_and_unseen() {
        let riot = result_from("GN", "8.8.8.8", &json!({"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google Public DNS","link":"https://viz.greynoise.io/riot/8.8.8.8"}));
        assert!(matches!(riot.status, Some(SourceStatus::Found)));
        assert_eq!(riot.family.as_deref(), Some("RIOT: Google Public DNS"));
        assert_eq!(riot.detections.as_deref(), Some("benign"));

        let scan = result_from("GN", "1.2.3.4", &json!({"noise":true,"riot":false,"classification":"malicious","name":"unknown"}));
        assert_eq!(scan.family.as_deref(), Some("internet scanner"));
        assert_eq!(scan.detections.as_deref(), Some("malicious"));
        assert_eq!(scan.link.as_deref(), Some("https://viz.greynoise.io/ip/1.2.3.4"));

        let none = result_from("GN", "1.2.3.5", &json!({"noise":false,"riot":false}));
        assert!(matches!(none.status, Some(SourceStatus::NotFound)));
    }
}
