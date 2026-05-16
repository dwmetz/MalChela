//! Integration tests for the file-based rule loading path using the
//! committed fixtures in `tests/fixtures/rules/`.
//!
//! Unit tests in `src/compile.rs` and `src/backend.rs` already use temp
//! directories built up at test time. These tests exercise the same path
//! against the real on-disk fixtures so reviewers can see the rule files
//! and trace the behaviour back to them.

use std::path::PathBuf;
use std::time::Duration;

use yara_backend::{Error, YaraBackend};

fn fixture_dir(subdir: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(subdir);
    p
}

fn copy_rules_to_tmp(rules: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let td = tempfile::TempDir::new().expect("tempdir");
    let src = fixture_dir("rules");
    for r in rules {
        let from = src.join(r);
        let to = td.path().join(r);
        std::fs::copy(&from, &to).unwrap_or_else(|e| panic!("copy {r}: {e}"));
    }
    let path = td.path().to_path_buf();
    (td, path)
}

#[test]
fn load_from_dir_with_only_mz_header_compiles_one_rule() {
    let (_td, dir) = copy_rules_to_tmp(&["mz_header.yar"]);
    let b = YaraBackend::load_from_dir(&dir).unwrap();
    assert_eq!(b.rule_count(), 1);
    assert!(b.rule_names().contains(&"mz_header".to_string()));
}

#[test]
fn load_from_dir_with_multi_file_types_compiles_three_rules() {
    let (_td, dir) = copy_rules_to_tmp(&["multi_file_types.yar"]);
    let b = YaraBackend::load_from_dir(&dir).unwrap();
    assert_eq!(b.rule_count(), 3);
    let names = b.rule_names();
    assert!(names.contains(&"mz_header".to_string()));
    assert!(names.contains(&"pdf_header".to_string()));
    assert!(names.contains(&"zip_header".to_string()));
}

#[test]
fn load_from_dir_with_tagged_rule_surfaces_tags_and_meta() {
    let (_td, dir) = copy_rules_to_tmp(&["with_tags.yar"]);
    let b = YaraBackend::load_from_dir(&dir).unwrap();
    let r = b
        .scan_bytes(b"some prefix tagged-marker suffix", Duration::ZERO)
        .unwrap();
    assert_eq!(r.matches.len(), 1);
    let m = &r.matches[0];
    assert!(m.tags.iter().any(|t| t == "alpha"));
    assert!(m.tags.iter().any(|t| t == "beta"));
    assert!(m.tags.iter().any(|t| t == "gamma"));
    assert_eq!(
        m.meta.get("author").map(String::as_str),
        Some("yara-backend tests")
    );
    assert_eq!(m.meta.get("severity").map(String::as_str), Some("5"));
    assert_eq!(m.meta.get("stable").map(String::as_str), Some("true"));
}

#[test]
fn load_from_dir_with_multi_namespace_file_compiles_both_rules() {
    let (_td, dir) = copy_rules_to_tmp(&["multi_namespace.yar"]);
    let b = YaraBackend::load_from_dir(&dir).unwrap();
    assert_eq!(b.rule_count(), 2);
}

#[test]
fn load_from_dir_with_malformed_rule_fails_at_initial_load() {
    let (_td, dir) = copy_rules_to_tmp(&["malformed.yar"]);
    let err = YaraBackend::load_from_dir(&dir).unwrap_err();
    assert!(matches!(err, Error::CompileFailed { .. }));
}

#[test]
fn load_from_dir_with_uses_magic_fails_with_unsupported_module() {
    let (_td, dir) = copy_rules_to_tmp(&["uses_magic.yar"]);
    let err = YaraBackend::load_from_dir(&dir).unwrap_err();
    match err {
        Error::UnsupportedModule { module, path } => {
            assert_eq!(module, "magic");
            assert!(path.ends_with("uses_magic.yar"));
        }
        other => panic!("expected UnsupportedModule, got {other:?}"),
    }
}

#[test]
fn load_from_dir_with_empty_file_compiles_clean() {
    let (_td, dir) = copy_rules_to_tmp(&["empty.yar"]);
    let b = YaraBackend::load_from_dir(&dir).unwrap();
    assert_eq!(b.rule_count(), 0);
}

#[test]
fn load_from_dir_with_colliding_rule_names_across_files_fails() {
    // mz_header.yar declares `mz_header`; multi_file_types.yar also
    // declares `mz_header`. yara-x catches the duplicate at compile
    // time and refuses the whole load. This documents the behaviour
    // so future contributors do not assume rules across files are
    // namespaced automatically.
    let (_td, dir) = copy_rules_to_tmp(&["mz_header.yar", "multi_file_types.yar"]);
    let err = YaraBackend::load_from_dir(&dir).unwrap_err();
    assert!(matches!(err, Error::CompileFailed { .. }));
}

#[test]
fn load_from_dir_with_non_colliding_good_rules_picks_up_all() {
    // with_tags + multi_namespace have no overlapping rule names,
    // so the load succeeds and produces one rule from with_tags plus
    // two from multi_namespace.
    let (_td, dir) = copy_rules_to_tmp(&["with_tags.yar", "multi_namespace.yar"]);
    let b = YaraBackend::load_from_dir(&dir).unwrap();
    assert_eq!(b.rule_count(), 3);
    let names = b.rule_names();
    assert!(names.contains(&"tagged_marker".to_string()));
    assert!(names.contains(&"rule_one".to_string()));
    assert!(names.contains(&"rule_two".to_string()));
}
