/// Fallback for a source id tiquery doesn't recognize (for example a typo in
/// `--sources`). Returns a Skipped row so the matrix still shows what was asked
/// for, instead of silently dropping it.
use super::{SourceResult, ThreatSource};
use async_trait::async_trait;

pub struct StubSource {
    short: String,
    #[allow(dead_code)]
    full: String,
}

impl StubSource {
    pub fn new(id: &str) -> Self {
        StubSource {
            short: id.to_uppercase(),
            full: id.to_string(),
        }
    }
}

#[async_trait]
impl ThreatSource for StubSource {
    fn name(&self) -> &str { &self.full }
    fn short_name(&self) -> &str { &self.short }

    async fn query(&self, _hash: &str) -> SourceResult {
        SourceResult::skipped(&self.short, "unknown source id")
    }
}
