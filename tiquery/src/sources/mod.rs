use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod fs;
pub mod gsb;
pub mod ha;
pub mod mb;
pub mod md;
pub mod ms;
pub mod objectivesee;
pub mod otx;
pub mod tier2;
pub mod tr;
pub mod urlscan;
pub mod vt;

pub use fs::FileScan;
pub use gsb::GoogleSafeBrowsing;
pub use ha::HybridAnalysis;
pub use mb::MalwareBazaar;
pub use md::MetaDefender;
pub use ms::Malshare;
pub use objectivesee::ObjectiveSee;
pub use otx::AlienVaultOTX;
pub use tier2::StubSource;
pub use tr::Triage;
pub use urlscan::UrlScan;
pub use vt::VirusTotal;

// ── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Found,
    NotFound,
    NoKey,
    Error(String),
    Skipped(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceResult {
    pub source: String,
    pub status: Option<SourceStatus>,
    pub family: Option<String>,
    /// Human-readable detection summary, e.g. "47/72" or "3 pulses"
    pub detections: Option<String>,
    pub file_name: Option<String>,
    pub file_type: Option<String>,
    pub first_seen: Option<String>,
    pub tags: Vec<String>,
    pub link: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

impl SourceResult {
    pub fn not_found(source: &str) -> Self {
        SourceResult {
            source: source.to_string(),
            status: Some(SourceStatus::NotFound),
            ..Default::default()
        }
    }

    pub fn no_key(source: &str) -> Self {
        SourceResult {
            source: source.to_string(),
            status: Some(SourceStatus::NoKey),
            ..Default::default()
        }
    }

    pub fn error(source: &str, msg: impl Into<String>) -> Self {
        SourceResult {
            source: source.to_string(),
            status: Some(SourceStatus::Error(msg.into())),
            ..Default::default()
        }
    }

    pub fn skipped(source: &str, reason: impl Into<String>) -> Self {
        SourceResult {
            source: source.to_string(),
            status: Some(SourceStatus::Skipped(reason.into())),
            ..Default::default()
        }
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait ThreatSource: Send + Sync {
    /// Full display name (used in verbose / future UI contexts).
    #[allow(dead_code)]
    fn name(&self) -> &str;
    /// Short identifier shown in the results matrix (e.g. "MB", "VT").
    fn short_name(&self) -> &str;
    async fn query(&self, hash: &str) -> SourceResult;
}
