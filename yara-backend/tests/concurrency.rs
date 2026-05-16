//! Concurrency tests for YaraBackend.
//!
//! The Arc-backed state means many worker threads can scan the same backend
//! at once; these tests assert that the scan path stays lock free on the
//! read side and that the reload path is safe against contention.

use std::sync::Arc;
use std::time::Duration;

use yara_backend::YaraBackend;

const MZ_RULE: &str = r#"
    rule mz_header {
        strings: $mz = { 4D 5A }
        condition: $mz at 0
    }
"#;

fn make_mz_buffer(size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    v[0] = 0x4D;
    v[1] = 0x5A;
    v
}

#[test]
fn many_threads_scanning_same_backend_get_identical_results() {
    let backend = Arc::new(YaraBackend::from_inline_sources(&[("default", MZ_RULE)]).unwrap());
    let buf = Arc::new(make_mz_buffer(4 * 1024 * 1024));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let b = Arc::clone(&backend);
        let data = Arc::clone(&buf);
        handles.push(std::thread::spawn(move || {
            let r = b.scan_bytes(&data, Duration::ZERO).expect("scan ok");
            r.rule_names_sorted()
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.join().expect("thread joined"));
    }

    let expected = vec!["mz_header".to_string()];
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r, &expected, "thread {i} produced a different result");
    }
}

#[test]
fn concurrent_reload_calls_do_not_deadlock_or_panic() {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join("a.yar"), MZ_RULE).unwrap();
    let backend = Arc::new(YaraBackend::load_from_dir(tmp.path()).unwrap());

    let mut handles = Vec::new();
    for _ in 0..16 {
        let b = Arc::clone(&backend);
        handles.push(std::thread::spawn(move || {
            for _ in 0..32 {
                let _ = b.reload_if_changed();
            }
        }));
    }
    for h in handles {
        h.join().expect("reload thread joined");
    }

    assert_eq!(backend.rule_count(), 1);
}

#[test]
fn readers_and_writer_share_the_backend_without_panicking() {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join("a.yar"), MZ_RULE).unwrap();
    let backend = Arc::new(YaraBackend::load_from_dir(tmp.path()).unwrap());
    let buf = Arc::new(make_mz_buffer(64 * 1024));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let b = Arc::clone(&backend);
        let data = Arc::clone(&buf);
        handles.push(std::thread::spawn(move || {
            for _ in 0..32 {
                let _ = b.scan_bytes(&data, Duration::ZERO);
            }
        }));
    }

    let b = Arc::clone(&backend);
    let dir = tmp.path().to_path_buf();
    handles.push(std::thread::spawn(move || {
        for i in 0..8 {
            let name = format!("extra_{i}.yar");
            let body = format!("rule r_{i} {{ strings: $a = \"marker_{i}\" condition: $a }}");
            std::fs::write(dir.join(&name), body).unwrap();
            let _ = b.reload_if_changed();
        }
    }));

    for h in handles {
        h.join().expect("thread joined");
    }
}
