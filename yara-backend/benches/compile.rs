//! Compile path benchmarks.
//!
//! Measures the time taken to compile 1, 10, and 100 inline rules through
//! the public `from_inline_sources` path. The numbers feed into the
//! crate's BASELINE.md so future PRs can detect performance regressions.
//!
//! Run with: `cargo bench -p yara-backend --bench compile`

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use yara_backend::YaraBackend;

fn make_rules_source(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!(
            "rule r_{i} {{ strings: $s_{i} = \"marker_{i}\" condition: $s_{i} }}\n"
        ));
    }
    s
}

fn bench_compile(c: &mut Criterion) {
    for n in [1usize, 10, 100] {
        let src = make_rules_source(n);
        c.bench_function(&format!("compile_{n}_inline_rules"), |b| {
            b.iter(|| {
                let backend =
                    YaraBackend::from_inline_sources(&[("default", black_box(src.as_str()))])
                        .expect("compile");
                black_box(backend.rule_count());
            });
        });
    }
}

criterion_group!(benches, bench_compile);
criterion_main!(benches);
