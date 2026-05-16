# Performance baseline

Captured numbers from `cargo bench -p yara-backend`, used as the
reference point for future regression checks. Re-run on the same
hardware after any change that touches the compile or scan path.

Re-running:

```
cargo bench -p yara-backend
```

Criterion writes per bench reports to `target/criterion/`.

## Capture environment (2026-05-16)

* OS: WSL2 (Linux 6.6.87.2 microsoft standard)
* Rust: `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`, `rustc 1.95.0 (59807616e 2026-04-14)`
* Build profile: `bench` (release with debug = false)
* yara-x version: 1.16.0

## Compile path

Measured by `benches/compile.rs`. Compiles N inline rules through
`YaraBackend::from_inline_sources` and discards the result.

| Rules | Median |
|------:|-------:|
| 1     | 4.97 ms |
| 10    | 5.56 ms |
| 100   | 9.67 ms |

Rule count scales sub-linearly past the fixed yara-x compiler startup
cost. The first compile dominates the budget.

## Scan path (in memory)

Measured by `benches/scan_mem.rs`. Calls `YaraBackend::scan_bytes`
against a deterministic LCG generated buffer with a 10 rule corpus
that never matches.

| Size  | Median   | Throughput |
|------:|---------:|-----------:|
| 1 KiB | 376 us   | 2.60 MiB/s |
| 1 MiB | 486 us   | 2.01 GiB/s |
| 16 MiB | 2.70 ms | 5.78 GiB/s |

The 1 KiB number reflects scanner setup overhead (a fresh
`yara_x::Scanner` is allocated per call); throughput rises sharply
once the scan kernel can amortise setup against larger inputs.

## Scan path (on disk)

Measured by `benches/scan_file.rs`. Same corpus, same buffer sizes,
but read from a temp file via `YaraBackend::scan_file`.

| Size  | Median   | Throughput |
|------:|---------:|-----------:|
| 1 KiB | 404 us   | 2.42 MiB/s |
| 1 MiB | 575 us   | 1.70 GiB/s |
| 16 MiB | 5.12 ms | 3.05 GiB/s |

yara-x mmaps the file by default. The 16 MiB on disk number is
slower than the 16 MiB in memory number because mmap setup and page
fault costs are real at that size; for our typical sample sizes
(a few MB) the gap is negligible.

## Regression rules

* Any change pushing compile time above 15 ms for 100 inline rules is
  worth a closer look.
* Any change dropping scan throughput below half of these baselines
  at any size is a regression worth blocking.
* Any new bench that produces a number more than 5 percent worse than
  these should justify the cost in the PR description.

These rules are guidance, not gating. Run the suite, eyeball the
delta, write a one liner in the PR if anything moved.
