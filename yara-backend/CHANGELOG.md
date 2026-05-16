# Changelog

All notable changes to this crate will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the crate uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 — Initial release

First public version of the wrapper. Internal to the MalChela workspace
for now; not published to crates.io.

### Added

* `YaraBackend` facade with two constructors. `load_from_dir` walks a
  directory for `.yar` / `.yara` files; `from_inline_sources` compiles
  `(namespace, source)` pairs already in memory.
* `scan_file` and `scan_bytes` paths, both running through a fresh
  short lived yara-x `Scanner` so multi thread workers stay lock free.
* Built in hot reload: every scan checks the rules directory and
  recompiles if anything changed. One bad rule during a reload becomes
  a warning, not a hard fail.
* `Match`, `MatchedString`, `ScanReport` result types. `meta` is a
  `BTreeMap` and `matches` is sorted by `(rule name, namespace, first
  offset)` so two runs of the same scan produce identical reports.
* `Error` enum with `#[non_exhaustive]`, covering load errors, compile
  errors, unsupported modules, timeouts, lock contention, and IO.
* Pre compile audit that refuses rules importing modules yara-x does
  not implement (`magic` today).
* Companion shell script `tools/audit_yara_rules.sh` for CI hooks.
* Three criterion benchmarks: compile, scan_bytes, scan_file.

### Tested

117 tests in the suite:

* 83 unit tests across `error`, `match_types`, `audit`, `compile`,
  `cache`, `scan`, and `backend` modules.
* 6 audit evasion tests: extra whitespace, tabs, escape sequences,
  block and line comments, capitalised module names.
* 1 chaos test: 8 worker threads, 250 random ops each (writes,
  deletes, scans, reloads), no panics or deadlocks.
* 3 concurrency tests covering parallel scans, parallel reloads, and
  mixed reader / writer access from `Arc<YaraBackend>`.
* 5 determinism tests: same input produces identical reports across
  runs; metadata key order is alphabetic; matches are sorted.
* 8 inline rule regression tests, one per MalChela consumer that
  ships an inline rule string today.
* 9 file based load tests against committed fixtures in
  `tests/fixtures/rules/`.
* 2 README example tests: every code snippet in `README.md` is
  transcribed into a real test so doc drift gets caught.
