use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;

pub struct VirusTotal {
    api_key: Option<String>,
    verbose: bool,
}

impl VirusTotal {
    pub fn new(api_key: Option<String>) -> Self {
        VirusTotal { api_key, verbose: false }
    }
    pub fn with_verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    async fn query_hash(&self, hash: &str, key: &str) -> SourceResult {
        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
        let resp = match client.get(&url).header("x-apikey", key).send().await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return SourceResult::not_found(self.short_name());
        }

        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        if let Some(err) = body.get("error") {
            let code = err.get("code").and_then(|v| v.as_str()).unwrap_or("unknown");
            if code == "NotFoundError" {
                return SourceResult::not_found(self.short_name());
            }
            return SourceResult::error(self.short_name(), code.to_string());
        }

        let attrs = &body["data"]["attributes"];
        let stats = &attrs["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
        let total = ["malicious", "suspicious", "undetected", "harmless", "timeout"]
            .iter()
            .filter_map(|k| stats[k].as_u64())
            .sum::<u64>();

        let detections = if total > 0 {
            Some(format!("{}/{}", malicious + suspicious, total))
        } else {
            None
        };

        let family = attrs
            .get("popular_threat_classification")
            .and_then(|c| c.get("suggested_threat_label"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let file_type = attrs.get("type_description").and_then(|v| v.as_str()).map(str::to_string);

        let first_seen = attrs
            .get("first_submission_date")
            .and_then(|v| v.as_i64())
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            });

        let mut extra: std::collections::HashMap<String, serde_json::Value> = Default::default();
        if self.verbose {
            if let Some(engines_obj) = attrs.get("last_analysis_results").and_then(|v| v.as_object()) {
                let mut detected: Vec<serde_json::Value> = engines_obj
                    .iter()
                    .filter(|(_, v)| {
                        matches!(
                            v.get("category").and_then(|c| c.as_str()),
                            Some("malicious") | Some("suspicious")
                        )
                    })
                    .map(|(name, v)| serde_json::json!({
                        "engine":   name,
                        "category": v.get("category").and_then(|c| c.as_str()).unwrap_or(""),
                        "result":   v.get("result").and_then(|r| r.as_str()).unwrap_or(""),
                    }))
                    .collect();
                detected.sort_by(|a, b| {
                    a["engine"].as_str().unwrap_or("").cmp(b["engine"].as_str().unwrap_or(""))
                });
                extra.insert("engines".to_string(), serde_json::Value::Array(detected));
            }
        }

        SourceResult {
            source: self.short_name().to_string(),
            status: Some(SourceStatus::Found),
            family,
            detections,
            file_type,
            first_seen,
            link: Some(format!("https://www.virustotal.com/gui/file/{}", hash)),
            file_name: None,
            tags: vec![],
            extra,
        }
    }

    /// IP address report: detections, community reputation, AS owner, and
    /// country — enough to tell a flagged C2 from a cloud or CDN address.
    async fn query_ip(&self, ip: &str, key: &str) -> SourceResult {
        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };
        let api_url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
        let resp = match client.get(&api_url).header("x-apikey", key).send().await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return SourceResult::not_found(self.short_name());
        }
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return SourceResult::error(self.short_name(), "rate limited (VT public API: 4/min)");
        }
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };
        if let Some(err) = body.get("error") {
            let code = err.get("code").and_then(|v| v.as_str()).unwrap_or("unknown");
            if code == "NotFoundError" {
                return SourceResult::not_found(self.short_name());
            }
            return SourceResult::error(self.short_name(), code.to_string());
        }
        ip_result(self.short_name(), ip, &body["data"]["attributes"])
    }

    async fn query_url(&self, url_input: &str, key: &str) -> SourceResult {
        let url_id = URL_SAFE_NO_PAD.encode(url_input.as_bytes());

        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let api_url = format!("https://www.virustotal.com/api/v3/urls/{}", url_id);
        let resp = match client.get(&api_url).header("x-apikey", key).send().await {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return SourceResult::not_found(self.short_name());
        }

        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        if let Some(err) = body.get("error") {
            let code = err.get("code").and_then(|v| v.as_str()).unwrap_or("unknown");
            if code == "NotFoundError" {
                return SourceResult::not_found(self.short_name());
            }
            return SourceResult::error(self.short_name(), code.to_string());
        }

        let attrs = &body["data"]["attributes"];
        let stats = &attrs["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
        let total = ["malicious", "suspicious", "undetected", "harmless", "timeout"]
            .iter()
            .filter_map(|k| stats[k].as_u64())
            .sum::<u64>();

        let detections = if total > 0 {
            Some(format!("{}/{}", malicious + suspicious, total))
        } else {
            None
        };

        // Collect threat names and categories for the family field
        let family = attrs
            .get("threat_names")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // Categories come as a vendor→category object; collect unique values
        let tags: Vec<String> = attrs
            .get("categories")
            .and_then(|v| v.as_object())
            .map(|obj| {
                let mut cats: Vec<String> = obj
                    .values()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect();
                cats.sort();
                cats.dedup();
                cats
            })
            .unwrap_or_default();

        let first_seen = attrs
            .get("first_submission_date")
            .and_then(|v| v.as_i64())
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            });

        SourceResult {
            source: self.short_name().to_string(),
            status: Some(SourceStatus::Found),
            family,
            detections,
            file_type: None,
            first_seen,
            link: Some(format!("https://www.virustotal.com/gui/url/{}", url_id)),
            file_name: None,
            tags,
            extra: Default::default(),
        }
    }
}

#[async_trait]
impl ThreatSource for VirusTotal {
    fn name(&self) -> &str {
        "VirusTotal"
    }

    fn short_name(&self) -> &str {
        "VT"
    }

    async fn query(&self, input: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        if input.starts_with("http://") || input.starts_with("https://") {
            self.query_url(input, &key).await
        } else if input.parse::<std::net::IpAddr>().is_ok() {
            self.query_ip(input, &key).await
        } else {
            self.query_hash(input, &key).await
        }
    }
}

/// VT IP-address attributes -> result (split out for tests).
fn ip_result(short: &str, ip: &str, attrs: &Value) -> SourceResult {
    let stats = &attrs["last_analysis_stats"];
    let bad = stats["malicious"].as_u64().unwrap_or(0) + stats["suspicious"].as_u64().unwrap_or(0);
    let total: u64 = ["malicious", "suspicious", "undetected", "harmless", "timeout"]
        .iter()
        .filter_map(|k| stats[k].as_u64())
        .sum();
    let owner = attrs["as_owner"].as_str().unwrap_or("");
    let asn = attrs["asn"].as_u64().map(|a| format!("AS{} ", a)).unwrap_or_default();
    let country = attrs["country"].as_str().map(|c| format!(" ({})", c)).unwrap_or_default();
    let family = format!("{}{}{}", asn, owner, country).trim().to_string();
    let mut tags: Vec<String> = attrs["tags"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let mut extra = std::collections::HashMap::new();
    if let Some(rep) = attrs["reputation"].as_i64() {
        extra.insert("reputation".to_string(), Value::from(rep));
        if rep != 0 {
            tags.push(format!("reputation {}", rep));
        }
    }
    SourceResult {
        source: short.to_string(),
        status: Some(SourceStatus::Found),
        family: if family.is_empty() { None } else { Some(family) },
        detections: if total > 0 { Some(format!("{}/{}", bad, total)) } else { None },
        tags,
        link: Some(format!("https://www.virustotal.com/gui/ip-address/{}", ip)),
        extra,
        ..Default::default()
    }
}

#[cfg(test)]
mod ip_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ip_attributes() {
        let a = json!({"last_analysis_stats":{"malicious":3,"suspicious":1,"undetected":20,"harmless":70,"timeout":0},
                       "as_owner":"Example Hosting","asn":64500,"country":"NL","reputation":-12,"tags":["tor"]});
        let r = ip_result("VT", "198.51.100.7", &a);
        assert_eq!(r.detections.as_deref(), Some("4/94"));
        assert_eq!(r.family.as_deref(), Some("AS64500 Example Hosting (NL)"));
        assert!(r.tags.contains(&"tor".to_string()) && r.tags.contains(&"reputation -12".to_string()));
        assert_eq!(r.link.as_deref(), Some("https://www.virustotal.com/gui/ip-address/198.51.100.7"));
    }
}
