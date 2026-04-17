use anyhow::Result;
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct SourceConfig {
    pub enabled: Option<bool>,
    pub api_key: Option<String>,
    pub rate_limit_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct TiQueryConfig {
    #[serde(default)]
    pub sources: HashMap<String, SourceConfig>,
    #[serde(default)]
    pub query_order: Vec<String>,
}

impl TiQueryConfig {
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let cfg: TiQueryConfig = serde_yaml::from_str(&content)?;
            return Ok(cfg);
        }
        Ok(TiQueryConfig::default())
    }

    fn config_path() -> PathBuf {
        config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("malchela")
            .join("tiquery.yaml")
    }

    /// Check whether a source is enabled (defaults to true if not specified).
    pub fn source_enabled(&self, id: &str) -> bool {
        self.sources
            .get(id)
            .and_then(|s| s.enabled)
            .unwrap_or(true)
    }

    /// Explicit API key override from the YAML config (overrides file-based key).
    pub fn source_api_key(&self, id: &str) -> Option<String> {
        self.sources.get(id)?.api_key.clone()
    }
}
