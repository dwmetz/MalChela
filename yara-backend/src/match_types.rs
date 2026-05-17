//! Match and scan report types.
//!
//! `Match` carries every field the underlying engine surfaces; callers that
//! only need rule names use [`ScanReport::rule_names_sorted`]. We keep the
//! full surface so JSON serializers and future tooling can elide what they
//! do not need rather than us re-introducing the field set later.
//!
//! Determinism: `meta` is a `BTreeMap`, never `HashMap`. `ScanReport::matches`
//! is sorted at the wrapper boundary so two runs of the same scan produce
//! byte identical reports.

use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub matched_strings: Vec<MatchedString>,
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedString {
    pub identifier: String,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub matches: Vec<Match>,
    pub elapsed: Duration,
    pub rules_evaluated: usize,
    pub compile_warnings: Vec<String>,
}

impl ScanReport {
    /// Rule names only, alphabetically sorted, deduplicated.
    ///
    /// This is the convenience callers (notably fileanalyzer's JSON
    /// serializer) reach for. Sorting + dedup at the wrapper guarantees
    /// the same input produces the same output regardless of underlying
    /// engine match order.
    pub fn rule_names_sorted(&self) -> Vec<String> {
        let mut names: Vec<String> = self.matches.iter().map(|m| m.rule_name.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// True iff the scan produced no matches.
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
}

impl Default for ScanReport {
    fn default() -> Self {
        Self {
            matches: Vec::new(),
            elapsed: Duration::ZERO,
            rules_evaluated: 0,
            compile_warnings: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_match(rule_name: &str) -> Match {
        Match {
            rule_name: rule_name.to_string(),
            namespace: "default".to_string(),
            tags: Vec::new(),
            matched_strings: Vec::new(),
            meta: BTreeMap::new(),
        }
    }

    #[test]
    fn default_scan_report_is_empty() {
        let r = ScanReport::default();
        assert!(r.is_empty());
        assert_eq!(r.matches.len(), 0);
        assert_eq!(r.rules_evaluated, 0);
        assert_eq!(r.elapsed, Duration::ZERO);
        assert!(r.compile_warnings.is_empty());
    }

    #[test]
    fn rule_names_sorted_empty_report_returns_empty() {
        let r = ScanReport::default();
        assert!(r.rule_names_sorted().is_empty());
    }

    #[test]
    fn rule_names_sorted_alphabetic_ordering() {
        let r = ScanReport {
            matches: vec![mk_match("zebra"), mk_match("alpha"), mk_match("mango")],
            ..ScanReport::default()
        };
        assert_eq!(r.rule_names_sorted(), vec!["alpha", "mango", "zebra"]);
    }

    #[test]
    fn rule_names_sorted_dedups_consecutive_duplicates() {
        let r = ScanReport {
            matches: vec![mk_match("dup"), mk_match("dup"), mk_match("other")],
            ..ScanReport::default()
        };
        assert_eq!(r.rule_names_sorted(), vec!["dup", "other"]);
    }

    #[test]
    fn rule_names_sorted_dedups_after_sorting_not_in_input_order() {
        let r = ScanReport {
            matches: vec![mk_match("b"), mk_match("a"), mk_match("b"), mk_match("a")],
            ..ScanReport::default()
        };
        assert_eq!(r.rule_names_sorted(), vec!["a", "b"]);
    }

    #[test]
    fn meta_is_btreemap_not_hashmap() {
        let mut m = mk_match("r");
        m.meta.insert("z_key".to_string(), "z".to_string());
        m.meta.insert("a_key".to_string(), "a".to_string());
        m.meta.insert("m_key".to_string(), "m".to_string());
        let keys: Vec<&String> = m.meta.keys().collect();
        assert_eq!(keys, vec!["a_key", "m_key", "z_key"]);
    }

    #[test]
    fn match_and_matched_string_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Match>();
        assert_send_sync::<MatchedString>();
        assert_send_sync::<ScanReport>();
    }
}
