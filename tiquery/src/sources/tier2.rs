/// Placeholder source for Tier 2 integrations not yet implemented.
/// Returns a Skipped result with "coming soon" so the matrix still shows
/// the row when the user explicitly requests a Tier 2 source.
use super::{SourceResult, ThreatSource};
use async_trait::async_trait;

pub struct StubSource {
    short: String,
    #[allow(dead_code)]
    full: String,
}

impl StubSource {
    pub fn new(id: &str) -> Self {
        let full = match id {
            "mp" => "Malpedia",
            "ha" => "Hybrid Analysis",
            "mw" => "MWDB",
            "tr" => "Triage",
            "fs" => "FileScan.IO",
            "ms" => "Malshare",
            other => other,
        };
        StubSource {
            short: id.to_uppercase(),
            full: full.to_string(),
        }
    }
}

#[async_trait]
impl ThreatSource for StubSource {
    fn name(&self) -> &str { &self.full }
    fn short_name(&self) -> &str { &self.short }

    async fn query(&self, _hash: &str) -> SourceResult {
        SourceResult::skipped(&self.short, "coming soon")
    }
}
