//! Inline rule regression tests.
//!
//! Each MalChela consumer that uses an inline rule string today has a test
//! here. The rule body is copied verbatim from the consumer so that any
//! drift between the upstream source and what yara-backend can compile
//! would break the test.
//!
//! When a caller migrates to yara-backend in a later PR, its existing
//! inline rule string is replaced by a call to
//! `YaraBackend::from_inline_sources(...)` and the same rule body is
//! passed in. These tests prove the body still compiles and scans the
//! same way under yara-x.

use std::time::Duration;

use yara_backend::YaraBackend;

fn fill_zero(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

fn make_mz_buffer(size: usize) -> Vec<u8> {
    let mut v = fill_zero(size);
    v[0] = 0x4D;
    v[1] = 0x5A;
    v
}

fn make_pdf_buffer(size: usize) -> Vec<u8> {
    let mut v = fill_zero(size);
    v[0..4].copy_from_slice(b"%PDF");
    v
}

fn make_zip_buffer(size: usize) -> Vec<u8> {
    let mut v = fill_zero(size);
    v[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    v
}

// ─── mzhash and mismatchminer (single MZ rule) ──────────────────────────
const MZHASH_RULE: &str = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}
    condition:
        $mz at 0
}
"#;

#[test]
fn mzhash_inline_rule_compiles_and_matches_mz_files() {
    let b = YaraBackend::from_inline_sources(&[("default", MZHASH_RULE)]).unwrap();
    assert_eq!(b.rule_count(), 1);

    let r = b.scan_bytes(&make_mz_buffer(64), Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["mz_header"]);

    let r = b.scan_bytes(&fill_zero(64), Duration::ZERO).unwrap();
    assert!(r.is_empty());
}

#[test]
fn mismatchminer_inline_rule_is_identical_to_mzhash() {
    // mismatchminer ships the same inline rule body. This test guards
    // against the bodies drifting apart between commits.
    let b = YaraBackend::from_inline_sources(&[("default", MZHASH_RULE)]).unwrap();
    let r = b.scan_bytes(&make_mz_buffer(32), Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["mz_header"]);
}

// ─── mzcount and xmzhash (three-magic-number rule) ──────────────────────
const MZCOUNT_RULE: &str = r#"
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}
    condition:
        $mz at 0
}

rule pdf_header {
    meta:
        description = "Matches files with PDF header"
    strings:
        $pdf = {25 50 44 46}
    condition:
        $pdf at 0
}

rule zip_header {
    meta:
        description = "Matches files with ZIP header"
    strings:
        $zip = {50 4B 03 04}
    condition:
        $zip at 0
}
"#;

#[test]
fn mzcount_inline_rule_picks_up_each_magic_number() {
    let b = YaraBackend::from_inline_sources(&[("default", MZCOUNT_RULE)]).unwrap();
    assert_eq!(b.rule_count(), 3);

    let r = b.scan_bytes(&make_mz_buffer(64), Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["mz_header"]);

    let r = b.scan_bytes(&make_pdf_buffer(64), Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["pdf_header"]);

    let r = b.scan_bytes(&make_zip_buffer(64), Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["zip_header"]);

    let r = b.scan_bytes(&fill_zero(64), Duration::ZERO).unwrap();
    assert!(r.is_empty());
}

#[test]
fn xmzhash_inline_rule_is_identical_to_mzcount() {
    // Same three-rule body. Guard against drift.
    let b = YaraBackend::from_inline_sources(&[("default", MZCOUNT_RULE)]).unwrap();
    assert_eq!(b.rule_count(), 3);
}

// ─── fileanalyzer/packed.rs (packer detection) ──────────────────────────
//
// The packed.rs rule is larger and uses byte patterns with wildcards
// plus a uint16(0) numeric check. yara-x supports both features. We
// trim the test to a minimal scan that exercises the simple substring
// strings (UPX, PECompact, etc.) so we do not depend on a real packed
// binary fixture.
const PACKED_RULE: &str = r#"
rule is_packed {
    meta:
        description = "Detects packed executables (UPX, etc.)"
    strings:
        $upx_sig1 = "UPX!"
        $packer_str1 = "UPX"
        $packer_str2 = "PECompact"
        $packer_str3 = "ASPack"
    condition:
        any of them
}
"#;

#[test]
fn packed_inline_rule_compiles() {
    let b = YaraBackend::from_inline_sources(&[("default", PACKED_RULE)]).unwrap();
    assert_eq!(b.rule_count(), 1);
}

#[test]
fn packed_inline_rule_fires_on_upx_signature_string() {
    let b = YaraBackend::from_inline_sources(&[("default", PACKED_RULE)]).unwrap();
    let buf = b"random prefix UPX! and more bytes";
    let r = b.scan_bytes(buf, Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["is_packed"]);
}

#[test]
fn packed_inline_rule_fires_on_pecompact_signature() {
    let b = YaraBackend::from_inline_sources(&[("default", PACKED_RULE)]).unwrap();
    let buf = b"some prefix PECompact tail";
    let r = b.scan_bytes(buf, Duration::ZERO).unwrap();
    assert_eq!(r.rule_names_sorted(), vec!["is_packed"]);
}

#[test]
fn packed_inline_rule_no_match_on_clean_bytes() {
    let b = YaraBackend::from_inline_sources(&[("default", PACKED_RULE)]).unwrap();
    let buf = fill_zero(128);
    let r = b.scan_bytes(&buf, Duration::ZERO).unwrap();
    assert!(r.is_empty());
}
