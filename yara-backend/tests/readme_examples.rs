//! Verifies that the code snippets in `README.md` actually compile and run.
//!
//! When the README changes, transcribe the new snippet here and adjust any
//! surrounding setup (temp dirs, fixture files) needed to make it executable.
//! If a snippet drifts away from working code, this test catches it.

use std::fs;
use std::time::Duration;

use tempfile::TempDir;
use yara_backend::YaraBackend;

#[test]
fn readme_quick_start_load_from_dir_compiles_and_runs() {
    // The README example reads from "./yara_rules"; for the test we use a
    // tempdir and a synthetic sample so it stays hermetic.
    let td = TempDir::new().unwrap();
    fs::write(
        td.path().join("mz.yar"),
        "rule mz_header { strings: $mz = { 4D 5A } condition: $mz at 0 }",
    )
    .unwrap();
    let mut sample = vec![0u8; 64];
    sample[0] = 0x4D;
    sample[1] = 0x5A;
    let sample_path = td.path().join("sample.bin");
    fs::write(&sample_path, &sample).unwrap();

    // --- README snippet (rules-dir example) ---
    let backend = YaraBackend::load_from_dir(td.path()).unwrap();
    let report = backend
        .scan_file(&sample_path, Duration::from_secs(5))
        .unwrap();
    let mut matched: Vec<String> = Vec::new();
    for name in report.rule_names_sorted() {
        matched.push(name);
    }
    // --- end snippet ---

    assert_eq!(matched, vec!["mz_header"]);
}

#[test]
fn readme_quick_start_inline_example_compiles_and_runs() {
    // --- README snippet (inline-rules example) ---
    const MZ_RULE: &str = r#"
        rule mz_header {
            strings: $mz = { 4D 5A }
            condition: $mz at 0
        }
    "#;

    let backend = YaraBackend::from_inline_sources(&[("default", MZ_RULE)]).unwrap();
    let mut sample = vec![0u8; 64];
    sample[0] = 0x4D;
    sample[1] = 0x5A;
    let report = backend.scan_bytes(&sample, Duration::ZERO).unwrap();
    assert_eq!(report.rule_names_sorted(), vec!["mz_header"]);
    // --- end snippet ---
}
