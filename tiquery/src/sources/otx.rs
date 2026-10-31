use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;

pub struct AlienVaultOTX {
    api_key: Option<String>,
}

impl AlienVaultOTX {
    pub fn new(api_key: Option<String>) -> Self {
        AlienVaultOTX { api_key }
    }
}

#[async_trait]
impl ThreatSource for AlienVaultOTX {
    fn name(&self) -> &str {
        "AlienVault OTX"
    }

    fn short_name(&self) -> &str {
        "OTX"
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

        // IPs use the IPv4/IPv6 indicator endpoints; everything else is a file hash.
        let ip = hash.parse::<std::net::IpAddr>().ok();
        let kind = match ip {
            Some(std::net::IpAddr::V4(_)) => "IPv4",
            Some(std::net::IpAddr::V6(_)) => "IPv6",
            None => "file",
        };
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
            kind, hash
        );

        let resp = match client
            .get(&url)
            .header("X-OTX-API-KEY", &key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return SourceResult::not_found(self.short_name());
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return SourceResult::error(self.short_name(), "rate limited");
        }
        if !status.is_success() {
            return SourceResult::error(self.short_name(), format!("HTTP {}", status.as_u16()));
        }

        // Guard against empty or non-JSON bodies (e.g. maintenance pages)
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };
        if text.trim().is_empty() {
            return SourceResult::not_found(self.short_name());
        }

        let body: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), format!("parse: {}", e)),
        };

        let pulse_count = body
            .get("pulse_info")
            .and_then(|p| p.get("count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if pulse_count == 0 {
            return SourceResult::not_found(self.short_name());
        }

        // Collect up to 5 pulse names as tags
        let tags: Vec<String> = body
            .get("pulse_info")
            .and_then(|p| p.get("pulses"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .take(5)
                    .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        SourceResult {
            source: self.short_name().to_string(),
            status: Some(SourceStatus::Found),
            detections: Some(format!("{} pulse{}", pulse_count, if pulse_count == 1 { "" } else { "s" })),
            tags,
            link: Some(format!(
                "https://otx.alienvault.com/indicator/{}/{}",
                if ip.is_some() { "ip" } else { "file" },
                hash
            )),
            // For IPs: AS and country, so the row says whose address it is.
            family: ip.and_then(|_| {
                let asn = body.get("asn").and_then(|v| v.as_str()).unwrap_or("");
                let cc = body.get("country_name").and_then(|v| v.as_str()).unwrap_or("");
                let f = format!("{}{}", asn, if cc.is_empty() { String::new() } else { format!(" ({})", cc) });
                (!f.trim().is_empty()).then(|| f.trim().to_string())
            }),
            file_name: None,
            file_type: None,
            first_seen: None,
            extra: Default::default(),
        }
    }
}
