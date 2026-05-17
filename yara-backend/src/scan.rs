//! Scanning paths.
//!
//! These helpers wrap `yara_x::Scanner` so the rest of the crate works in
//! terms of our own `ScanReport` and `Match` types. The `YaraBackend`
//! facade calls into here once it has resolved the current `Arc<Rules>`
//! from the cache.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use yara_x::{MetaValue, Rules, Scanner};

use crate::error::{Error, Result};
use crate::match_types::{Match, MatchedString, ScanReport};

/// Hard cap on the size of any single scan input, file or buffer. 256 MiB
/// covers the largest realistic malware sample by a wide margin while
/// keeping a runaway caller from passing the wrapper a multi gigabyte
/// buffer that would dominate memory.
pub(crate) const MAX_SCAN_INPUT_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) fn scan_file_with(
    rules: &Arc<Rules>,
    path: &Path,
    timeout: Duration,
    target: &str,
    compile_warnings: Vec<String>,
) -> Result<ScanReport> {
    let size = std::fs::metadata(path)
        .map_err(|e| Error::ScanFailed {
            target: target.to_string(),
            reason: format!("could not stat: {e}"),
        })?
        .len();
    if size > MAX_SCAN_INPUT_BYTES {
        return Err(Error::ScanInputTooLarge {
            target: target.to_string(),
            size,
            limit: MAX_SCAN_INPUT_BYTES,
        });
    }
    let start = Instant::now();
    let rules_for_scanner = rules.clone();
    let matches = run_scan_collect(target, move || {
        let mut scanner = Scanner::new(rules_for_scanner.as_ref());
        if !timeout.is_zero() {
            scanner.set_timeout(timeout);
        }
        scanner
            .scan_file(path)
            .map(|results| collect_matches(&results))
    })?
    .map_err(|e| translate_scan_error(e, target, timeout))?;
    let elapsed = start.elapsed();
    Ok(ScanReport {
        matches,
        elapsed,
        rules_evaluated: rules.iter().count(),
        compile_warnings,
    })
}

pub(crate) fn scan_bytes_with(
    rules: &Arc<Rules>,
    data: &[u8],
    timeout: Duration,
    target: &str,
    compile_warnings: Vec<String>,
) -> Result<ScanReport> {
    let size = data.len() as u64;
    if size > MAX_SCAN_INPUT_BYTES {
        return Err(Error::ScanInputTooLarge {
            target: target.to_string(),
            size,
            limit: MAX_SCAN_INPUT_BYTES,
        });
    }
    let start = Instant::now();
    let rules_for_scanner = rules.clone();
    let matches = run_scan_collect(target, move || {
        let mut scanner = Scanner::new(rules_for_scanner.as_ref());
        if !timeout.is_zero() {
            scanner.set_timeout(timeout);
        }
        scanner.scan(data).map(|results| collect_matches(&results))
    })?
    .map_err(|e| translate_scan_error(e, target, timeout))?;
    let elapsed = start.elapsed();
    Ok(ScanReport {
        matches,
        elapsed,
        rules_evaluated: rules.iter().count(),
        compile_warnings,
    })
}

// Runs the scanner closure under catch_unwind so a yara-x panic on
// adversarial input becomes a normal Error::ScanFailed rather than
// aborting the calling process. The closure must convert yara-x's
// borrowed ScanResults into owned data (Vec<Match>) before returning,
// since the scanner's lifetime ends with the closure.
//
// AssertUnwindSafe is sound here because we discard the scanner after
// any panic; no shared state is left observably inconsistent.
fn run_scan_collect<F>(
    target: &str,
    f: F,
) -> Result<std::result::Result<Vec<Match>, yara_x::ScanError>>
where
    F: FnOnce() -> std::result::Result<Vec<Match>, yara_x::ScanError>,
{
    panic::catch_unwind(AssertUnwindSafe(f)).map_err(|payload| {
        let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "yara-x panicked with no string payload".to_string()
        };
        Error::ScanFailed {
            target: target.to_string(),
            reason: format!("internal panic: {msg}"),
        }
    })
}

fn translate_scan_error(e: yara_x::ScanError, target: &str, timeout: Duration) -> Error {
    match e {
        yara_x::ScanError::Timeout => Error::Timeout {
            target: target.to_string(),
            elapsed: timeout,
        },
        other => Error::ScanFailed {
            target: target.to_string(),
            reason: format!("{other}"),
        },
    }
}

fn collect_matches(results: &yara_x::ScanResults<'_, '_>) -> Vec<Match> {
    let mut matches: Vec<Match> = results
        .matching_rules()
        .map(|rule| {
            let mut meta: BTreeMap<String, String> = BTreeMap::new();
            for (key, value) in rule.metadata() {
                meta.insert(key.to_string(), meta_value_to_string(&value));
            }
            let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();
            let matched_strings: Vec<MatchedString> = rule
                .patterns()
                .flat_map(|pattern| {
                    let ident = pattern.identifier().to_string();
                    pattern.matches().map(move |m| MatchedString {
                        identifier: ident.clone(),
                        offset: m.range().start as u64,
                        data: m.data().to_vec(),
                    })
                })
                .collect();
            Match {
                rule_name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags,
                matched_strings,
                meta,
            }
        })
        .collect();
    matches.sort_by(|a, b| {
        a.rule_name
            .cmp(&b.rule_name)
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| {
                let a_off = a.matched_strings.first().map(|s| s.offset).unwrap_or(0);
                let b_off = b.matched_strings.first().map(|s| s.offset).unwrap_or(0);
                a_off.cmp(&b_off)
            })
    });
    matches
}

fn meta_value_to_string(v: &MetaValue<'_>) -> String {
    match v {
        MetaValue::Integer(i) => i.to_string(),
        MetaValue::Float(f) => f.to_string(),
        MetaValue::Bool(b) => b.to_string(),
        MetaValue::String(s) => (*s).to_string(),
        MetaValue::Bytes(b) => format!("{b}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::compile_sources;

    const MZ_RULE: &str = r#"
        rule mz_header {
            strings: $mz = { 4D 5A }
            condition: $mz at 0
        }
    "#;

    const TAGGED_RULE: &str = r#"
        rule tagged_rule : tag_a tag_b {
            meta:
                author = "test"
                severity = 5
                stable = true
            strings: $a = "marker"
            condition: $a
        }
    "#;

    fn mz_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 60];
        v[0] = 0x4D;
        v[1] = 0x5A;
        v
    }

    #[test]
    fn scan_bytes_matches_mz_header() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let r = scan_bytes_with(&rules, &mz_bytes(), Duration::ZERO, "buf", Vec::new()).unwrap();
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].rule_name, "mz_header");
        assert_eq!(r.matches[0].matched_strings.len(), 1);
        assert_eq!(r.matches[0].matched_strings[0].offset, 0);
        assert_eq!(r.matches[0].matched_strings[0].data, vec![0x4D, 0x5A]);
    }

    #[test]
    fn scan_bytes_no_match_returns_empty() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let zeros = vec![0u8; 60];
        let r = scan_bytes_with(&rules, &zeros, Duration::ZERO, "buf", Vec::new()).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn scan_bytes_with_empty_buffer_returns_empty() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let r = scan_bytes_with(&rules, &[], Duration::ZERO, "buf", Vec::new()).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn scan_with_no_rules_returns_empty_report() {
        let rules = compile_sources(&[]).unwrap();
        let r = scan_bytes_with(&rules, &mz_bytes(), Duration::ZERO, "buf", Vec::new()).unwrap();
        assert_eq!(r.rules_evaluated, 0);
        assert!(r.is_empty());
    }

    #[test]
    fn scan_file_matches_when_content_matches() {
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("sample.bin");
        std::fs::write(&p, mz_bytes()).unwrap();
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let r = scan_file_with(&rules, &p, Duration::ZERO, "sample.bin", Vec::new()).unwrap();
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].rule_name, "mz_header");
    }

    #[test]
    fn scan_file_missing_path_returns_scan_failed() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let phantom = Path::new("/definitely/does/not/exist/file.bin");
        let err =
            scan_file_with(&rules, phantom, Duration::ZERO, "phantom", Vec::new()).unwrap_err();
        assert!(matches!(err, Error::ScanFailed { .. }));
    }

    #[test]
    fn scan_report_carries_compile_warnings_through() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let warnings = vec!["one".to_string(), "two".to_string()];
        let r =
            scan_bytes_with(&rules, &mz_bytes(), Duration::ZERO, "buf", warnings.clone()).unwrap();
        assert_eq!(r.compile_warnings, warnings);
    }

    #[test]
    fn tags_and_meta_are_collected() {
        let rules = compile_sources(&[("default", TAGGED_RULE)]).unwrap();
        let buf = b"marker bytes here";
        let r = scan_bytes_with(&rules, buf, Duration::ZERO, "buf", Vec::new()).unwrap();
        assert_eq!(r.matches.len(), 1);
        let m = &r.matches[0];
        assert!(m.tags.iter().any(|t| t == "tag_a"));
        assert!(m.tags.iter().any(|t| t == "tag_b"));
        assert_eq!(m.meta.get("author").map(String::as_str), Some("test"));
        assert_eq!(m.meta.get("severity").map(String::as_str), Some("5"));
        assert_eq!(m.meta.get("stable").map(String::as_str), Some("true"));
    }

    #[test]
    fn multiple_matches_are_sorted_by_rule_name() {
        const TWO_RULES: &str = r#"
            rule zebra { strings: $z = "hit" condition: $z }
            rule alpha { strings: $a = "hit" condition: $a }
        "#;
        let rules = compile_sources(&[("default", TWO_RULES)]).unwrap();
        let r = scan_bytes_with(&rules, b"hit", Duration::ZERO, "buf", Vec::new()).unwrap();
        assert_eq!(r.matches.len(), 2);
        assert_eq!(r.matches[0].rule_name, "alpha");
        assert_eq!(r.matches[1].rule_name, "zebra");
        assert_eq!(r.rule_names_sorted(), vec!["alpha", "zebra"]);
    }

    #[test]
    fn scan_bytes_rejects_oversized_buffer() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let oversized = vec![0u8; (MAX_SCAN_INPUT_BYTES + 1) as usize];
        let err =
            scan_bytes_with(&rules, &oversized, Duration::ZERO, "huge", Vec::new()).unwrap_err();
        match err {
            Error::ScanInputTooLarge {
                size,
                limit,
                target,
            } => {
                assert!(size > limit);
                assert_eq!(limit, MAX_SCAN_INPUT_BYTES);
                assert_eq!(target, "huge");
            }
            other => panic!("expected ScanInputTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn scan_file_rejects_oversized_file() {
        let rules = compile_sources(&[("default", MZ_RULE)]).unwrap();
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("huge.bin");
        let huge = vec![0u8; (MAX_SCAN_INPUT_BYTES + 1) as usize];
        std::fs::write(&p, &huge).unwrap();
        let err = scan_file_with(&rules, &p, Duration::ZERO, "huge.bin", Vec::new()).unwrap_err();
        match err {
            Error::ScanInputTooLarge {
                size,
                limit,
                target,
            } => {
                assert!(size > limit);
                assert_eq!(limit, MAX_SCAN_INPUT_BYTES);
                assert_eq!(target, "huge.bin");
            }
            other => panic!("expected ScanInputTooLarge, got {other:?}"),
        }
    }
}
