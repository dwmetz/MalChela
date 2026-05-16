//! Determinism tests for YaraBackend.
//!
//! Two scans of the same input must produce identical match data (rule
//! names, namespaces, tags, metadata, matched bytes, and matched offsets).
//! Wall clock fields like `elapsed` are excluded — those vary by design.

use std::time::Duration;

use yara_backend::{Match, ScanReport, YaraBackend};

const TAGGED_RULE: &str = r#"
    rule tagged_demo : alpha beta {
        meta:
            author = "test"
            severity = 9
            shipped = true
        strings:
            $a = "marker_alpha"
            $b = "marker_beta"
        condition: any of them
    }
"#;

fn strip_timing(r: &ScanReport) -> Vec<Match> {
    r.matches.clone()
}

#[test]
fn two_runs_same_input_produce_identical_matches() {
    let backend = YaraBackend::from_inline_sources(&[("default", TAGGED_RULE)]).unwrap();
    let buf = b"some prefix marker_alpha and marker_beta here";
    let r1 = backend.scan_bytes(buf, Duration::ZERO).unwrap();
    let r2 = backend.scan_bytes(buf, Duration::ZERO).unwrap();
    assert_eq!(strip_timing(&r1), strip_timing(&r2));
    assert_eq!(r1.rules_evaluated, r2.rules_evaluated);
    assert_eq!(r1.compile_warnings, r2.compile_warnings);
}

#[test]
fn rule_names_sorted_helper_is_deterministic() {
    const TWO_RULES: &str = r#"
        rule zebra { strings: $a = "hit" condition: $a }
        rule alpha { strings: $a = "hit" condition: $a }
        rule mango { strings: $a = "hit" condition: $a }
    "#;
    let backend = YaraBackend::from_inline_sources(&[("default", TWO_RULES)]).unwrap();
    let buf = b"hit";
    let r1 = backend.scan_bytes(buf, Duration::ZERO).unwrap();
    let r2 = backend.scan_bytes(buf, Duration::ZERO).unwrap();
    let names1 = r1.rule_names_sorted();
    let names2 = r2.rule_names_sorted();
    assert_eq!(names1, names2);
    assert_eq!(names1, vec!["alpha", "mango", "zebra"]);
}

#[test]
fn metadata_iteration_order_is_alphabetic() {
    let backend = YaraBackend::from_inline_sources(&[("default", TAGGED_RULE)]).unwrap();
    let buf = b"marker_alpha";
    let r = backend.scan_bytes(buf, Duration::ZERO).unwrap();
    assert_eq!(r.matches.len(), 1);
    let keys: Vec<&String> = r.matches[0].meta.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "BTreeMap should yield alphabetic keys");
    assert_eq!(keys, vec!["author", "severity", "shipped"]);
}

#[test]
fn matches_are_ordered_by_rule_name_alphabetically() {
    const MULTI: &str = r#"
        rule zulu { strings: $a = "x" condition: $a }
        rule alpha { strings: $a = "x" condition: $a }
        rule mike { strings: $a = "x" condition: $a }
        rule bravo { strings: $a = "x" condition: $a }
    "#;
    let backend = YaraBackend::from_inline_sources(&[("default", MULTI)]).unwrap();
    let r = backend.scan_bytes(b"x", Duration::ZERO).unwrap();
    let names: Vec<&str> = r.matches.iter().map(|m| m.rule_name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "bravo", "mike", "zulu"]);
}

#[test]
fn ten_runs_same_input_match_byte_for_byte() {
    let backend = YaraBackend::from_inline_sources(&[("default", TAGGED_RULE)]).unwrap();
    let buf = b"marker_alpha marker_beta";
    let baseline = backend.scan_bytes(buf, Duration::ZERO).unwrap();
    let baseline_matches = strip_timing(&baseline);
    for run in 1..10 {
        let r = backend.scan_bytes(buf, Duration::ZERO).unwrap();
        assert_eq!(strip_timing(&r), baseline_matches, "run {run} drifted");
    }
}
