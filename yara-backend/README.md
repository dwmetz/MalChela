# yara-backend

A small wrapper crate that gives MalChela's analysis tools one place to
load YARA rules and scan files or buffers. Under the hood it uses
[`yara-x`](https://crates.io/crates/yara-x), the pure Rust YARA engine
maintained by VirusTotal.

## Why this exists

MalChela tools used to depend on the `yara` crate, which needs libyara
as a C library. That C dep is the main blocker for a native Windows
build and adds work to every `cargo build` from a clean target.

This crate owns the YARA surface so:

* Each MalChela tool calls one Rust API instead of importing yara directly.
* The choice of engine (`yara-x` today) can change later without touching
  every caller.
* Cross platform builds work without a system libyara install.

## Quick start

Load rules from a directory:

```rust
use std::time::Duration;
use yara_backend::YaraBackend;

let backend = YaraBackend::load_from_dir("./yara_rules")?;
let report = backend.scan_file("sample.bin", Duration::from_secs(5))?;
for name in report.rule_names_sorted() {
    println!("matched: {name}");
}
```

Or compile inline rules (handy for small built in rules a tool ships
alongside its source):

```rust
use std::time::Duration;
use yara_backend::YaraBackend;

const MZ_RULE: &str = r#"
    rule mz_header {
        strings: $mz = { 4D 5A }
        condition: $mz at 0
    }
"#;

let backend = YaraBackend::from_inline_sources(&[("default", MZ_RULE)])?;
let mut sample = vec![0u8; 64];
sample[0] = 0x4D;
sample[1] = 0x5A;
let report = backend.scan_bytes(&sample, Duration::ZERO)?;
assert_eq!(report.rule_names_sorted(), vec!["mz_header"]);
```

`Duration::ZERO` disables the per scan timeout; pass a non zero
Duration to enforce one.

## API at a glance

| Type | What it is |
|------|------------|
| `YaraBackend` | Top level facade. Cheap to clone (Arc backed), safe to share across threads. |
| `ScanReport` | Result of a scan: matches, elapsed time, rules evaluated, compile warnings. |
| `Match` | One matching rule: name, namespace, tags, matched strings, metadata. |
| `MatchedString` | One byte match: pattern id, offset, raw bytes. |
| `Error` | Every failure mode the wrapper can hit. Has `#[non_exhaustive]` so adding new variants later is not a breaking change. |

Helper methods worth knowing:

* `YaraBackend::reload_if_changed()` re-walks the rules directory and
  recompiles if anything changed. Called automatically before every
  scan, so the "drop a `.yar`, instantly available" workflow still
  works.
* `ScanReport::rule_names_sorted()` returns alphabetical, deduplicated
  rule names. This is what the JSON layer reaches for so output stays
  stable across runs.

## Hot reload

If you load from a directory, `scan_file` and `scan_bytes` check the
directory for changes before each scan. A file's `(size, mtime)` makes
the signature; if the signature differs from the cached one, the
backend recompiles. The data on disk is the source of truth.

One bad rule during a reload becomes a warning rather than aborting
the reload. The other rules still compile and scans keep working.
The compile warnings surface on `ScanReport::compile_warnings` so
callers can show them to the operator.

## Thread safety

`YaraBackend` is `Send + Sync`. Wrap it in an `Arc` and hand it to as
many worker threads as you like. Each scan allocates its own short
lived yara-x `Scanner`, so the read path is lock free.

## Trust model and resource caps

The crate is designed for the rule sources MalChela's own tools ship
(inline string constants baked into the binary) and the rule files an
operator drops into `yara_rules/` on a machine they control. Both are
trusted inputs at this layer.

To keep a runaway or adversarial caller from exhausting memory, the
wrapper enforces hard upper bounds checked at the public API boundary:

| Input | Cap | Error variant when exceeded |
|-------|-----|----------------------------|
| Rule source string (inline) | 16 MiB per source | `Error::SourceTooLarge` |
| Rule file on disk (`.yar` / `.yara`) | 16 MiB per file | `Error::SourceTooLarge` |
| Scan buffer (`scan_bytes`) | 256 MiB per call | `Error::ScanInputTooLarge` |
| Scan file (`scan_file`) | 256 MiB per call | `Error::ScanInputTooLarge` |

These limits are generous compared to real YARA corpora (kilobytes to
a few megabytes) and real malware samples (typically under 100 MB).
The caps are constants in `src/compile.rs` and `src/scan.rs`. If a
future caller needs higher limits we will make them configurable
through a builder pattern; for now they are hard coded.

The per scan `yara_x::Scanner` allocation is short lived and not
itself capped. High fan out workloads (many parallel calls from
`par_iter` style worker pools) are supported by design but the
allocation cost is real and is caller visible.

## Engine compatibility

yara-x implements most of YARA but not every libyara module. The
ones currently missing are caught by a pre compile audit:

* `import "magic"` is refused with `Error::UnsupportedModule`. Rules
  using `magic.type()` and friends will not compile.

A companion shell script,
[`tools/audit_yara_rules.sh`](tools/audit_yara_rules.sh), runs the
same check from CI so unsupported rules are caught before cargo even
starts compiling.

## License

MIT (matches the parent MalChela crate). yara-x itself is BSD-3-Clause
and is bundled as a regular crate dependency.
