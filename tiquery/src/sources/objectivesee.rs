use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const CATALOGUE_URL: &str = "https://objective-see.org/malware.json";
const CACHE_TTL_SECS: u64 = 86_400; // 24 h

pub struct ObjectiveSee;

impl ObjectiveSee {
    pub fn new() -> Self {
        ObjectiveSee
    }

    fn cache_path() -> PathBuf {
        common_config::find_workspace_root()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("cached")
            .join("os-malware.json")
    }

    fn cache_is_fresh(path: &PathBuf) -> bool {
        path.metadata()
            .and_then(|m| m.modified())
            .map(|mtime| {
                SystemTime::now()
                    .duration_since(mtime)
                    .map(|age| age < Duration::from_secs(CACHE_TTL_SECS))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Fetch the catalogue from the web and write it to cache. Returns the JSON.
    async fn fetch_and_cache() -> Result<Value, String> {
        eprintln!("[OS] Fetching ObjectiveSee malware catalogue...");
        let client = reqwest::Client::builder()
            .user_agent("tiquery/0.1 MalChela")
            .build()
            .map_err(|e| e.to_string())?;

        let body: Value = client
            .get(CATALOGUE_URL)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;

        // Persist to cache
        let cache_path = Self::cache_path();
        if let Some(parent) = cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string(&body) {
            let _ = std::fs::write(&cache_path, text);
        }

        Ok(body)
    }

    /// Load catalogue from cache file.
    fn load_cache(path: &PathBuf) -> Result<Value, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl ThreatSource for ObjectiveSee {
    fn name(&self) -> &str {
        "ObjectiveSee"
    }

    fn short_name(&self) -> &str {
        "OS"
    }

    async fn query(&self, hash: &str) -> SourceResult {
        // ObjectiveSee catalogue only contains SHA256 entries
        if hash.len() != 64 {
            return SourceResult::skipped(self.short_name(), "SHA256 only");
        }

        let cache_path = Self::cache_path();

        let catalogue: Value = if Self::cache_is_fresh(&cache_path) {
            match Self::load_cache(&cache_path) {
                Ok(v) => v,
                Err(_) => match Self::fetch_and_cache().await {
                    Ok(v) => v,
                    Err(e) => return SourceResult::error(self.short_name(), e),
                },
            }
        } else {
            match Self::fetch_and_cache().await {
                Ok(v) => v,
                Err(e) => {
                    // Try stale cache as fallback
                    match Self::load_cache(&cache_path) {
                        Ok(v) => {
                            eprintln!("[OS] Using stale cache (fetch failed: {})", e);
                            v
                        }
                        Err(_) => return SourceResult::error(self.short_name(), e),
                    }
                }
            }
        };

        // The catalogue JSON is {"malware": [...]}; each entry has "sha256" field
        let malware_arr = match catalogue.get("malware").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => return SourceResult::error(self.short_name(), "unexpected catalogue format"),
        };

        let hash_lower = hash.to_lowercase();
        let entry = malware_arr.iter().find(|m| {
            // Hashes live in the VirusTotal URL: .../file/{sha256}/
            m.get("virusTotal")
                .and_then(|v| v.as_str())
                .and_then(|url| url.split("/file/").nth(1))
                .map(|s| s.trim_end_matches('/').to_lowercase() == hash_lower)
                .unwrap_or(false)
        });

        match entry {
            None => SourceResult {
                source: self.short_name().to_string(),
                status: Some(SourceStatus::NotFound),
                detections: Some("not in catalogue".to_string()),
                ..Default::default()
            },
            Some(e) => {
                let family = e
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);

                SourceResult {
                    source: self.short_name().to_string(),
                    status: Some(SourceStatus::Found),
                    family,
                    link: Some("https://objective-see.org/malware.html".to_string()),
                    ..Default::default()
                }
            }
        }
    }
}
