//! In memory scan benchmarks.
//!
//! Measures `scan_bytes` throughput at 1 KiB, 1 MiB, and 16 MiB buffer
//! sizes against a 10 rule corpus. The numbers feed BASELINE.md.
//!
//! Run with: `cargo bench -p yara-backend --bench scan_mem`

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use yara_backend::YaraBackend;

fn ten_rules() -> String {
    let mut s = String::new();
    for i in 0..10 {
        s.push_str(&format!(
            "rule r_{i} {{ strings: $a = \"missing_marker_{i}\" condition: $a }}\n"
        ));
    }
    s
}

fn lcg_buffer(size: usize) -> Vec<u8> {
    let mut state: u64 = 0xdead_beef_cafe_babe;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

fn bench_scan_mem(c: &mut Criterion) {
    let backend = YaraBackend::from_inline_sources(&[("default", ten_rules().as_str())]).unwrap();

    let mut group = c.benchmark_group("scan_bytes");
    for (label, size) in [
        ("1KiB", 1024usize),
        ("1MiB", 1024 * 1024),
        ("16MiB", 16 * 1024 * 1024),
    ] {
        let buf = lcg_buffer(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(label, |b| {
            b.iter(|| {
                let r = backend
                    .scan_bytes(black_box(&buf), Duration::ZERO)
                    .expect("scan");
                black_box(r.matches.len());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scan_mem);
criterion_main!(benches);
