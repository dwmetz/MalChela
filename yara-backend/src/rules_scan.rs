//! Whole-rules scanning for MalChela's `yara_scan` tool.
//!
//! [`YaraBackend`](crate::YaraBackend) serves tools that load one rules
//! directory (or inline constants) and only need rule names back. A
//! general-purpose scanner, modelled on VirusTotal's `yr scan`, needs more:
//! several rule paths each with an optional namespace, external variables,
//! extra include directories, ignored modules, the rules that did *not*
//! match (`--negate`), and enough detail per pattern match (kind, length,
//! XOR key) to print results the way `yr` does.
//!
//! Every rule file still goes through the same safety checks as the rest of
//! the crate: the 16 MiB source cap and the pre-compile audit (unsupported
//! modules, and condition nesting deep enough to overflow the parser's stack
//! and abort the process). Scans run under `catch_unwind`, so a yara-x panic
//! on hostile input is an error for that file, not a crash.

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use walkdir::WalkDir;
use yara_x::{Compiler, MetaValue, Rules, Scanner, SourceCode};

use crate::audit::audit_rule_source;
use crate::compile::MAX_RULE_SOURCE_BYTES;
use crate::error::{Error, Result};

/// A rules file or directory, with the namespace its rules go into
/// (`default` when `None`, as in `yr`).
#[derive(Debug, Clone)]
pub struct RulesPath {
    pub namespace: Option<String>,
    pub path: PathBuf,
}

/// The value of an external variable defined with `--define`.
#[derive(Debug, Clone, PartialEq)]
pub enum ExternalValue {
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(String),
}

/// Compile-time options.
#[derive(Debug, Clone, Default)]
pub struct CompileConfig {
    /// External variables (`--define VAR=VALUE`).
    pub defines: Vec<(String, ExternalValue)>,
    /// Extra directories searched for `include`d files. The directory of
    /// every rule file is always searched too.
    pub include_dirs: Vec<PathBuf>,
    /// Rules that use these modules are ignored rather than failing.
    pub ignore_modules: Vec<String>,
    /// Skip rule files that fail to compile (reported as warnings) instead
    /// of failing the whole load.
    pub ignore_invalid: bool,
    /// Put each file's rules in a namespace named after its path.
    pub path_as_namespace: bool,
}

/// Rules compiled from one or more [`RulesPath`]s.
pub struct CompiledRules {
    rules: Arc<Rules>,
    /// Engine warnings, plus files skipped under `ignore_invalid`.
    pub warnings: Vec<String>,
    /// Number of rule files compiled.
    pub files: usize,
}

/// Scan-time options.
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Per-file timeout; `Duration::ZERO` disables it.
    pub timeout: Duration,
    /// Cap on matches recorded per pattern (`--max-matches-per-pattern`).
    pub max_matches_per_pattern: Option<usize>,
    /// Collect the rules that did not match (`--negate`).
    pub non_matching: bool,
    /// Record only each rule's identity and tags, not its metadata or
    /// string matches: enough for counts and plain rule lists, and far less
    /// memory when `non_matching` lists thousands of rules per file.
    pub summary_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Text,
    Regexp,
    Hex,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub identifier: String,
    pub kind: PatternKind,
    pub offset: usize,
    pub length: usize,
    pub data: Vec<u8>,
    pub xor_key: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MetaVal {
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct RuleResult {
    pub identifier: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// In definition order; a key may repeat.
    pub meta: Vec<(String, MetaVal)>,
    pub patterns: Vec<PatternMatch>,
}

/// One file's results. Rules are in the order the engine reports them.
#[derive(Debug, Clone, Default)]
pub struct FileScan {
    pub matching: Vec<RuleResult>,
    /// Filled only when [`ScanConfig::non_matching`] is set.
    pub non_matching: Vec<RuleResult>,
}

/// Every `.yar` / `.yara` file under `path` (recursively), sorted; or
/// `path` itself when it is a file, whatever its extension (as in `yr`).
pub fn rule_files(path: &Path) -> Result<Vec<PathBuf>> {
    let md = std::fs::metadata(path).map_err(|e| Error::LoadRules {
        dir: path.to_path_buf(),
        reason: format!("{e}"),
    })?;
    if md.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut out = Vec::new();
    for entry in WalkDir::new(path).follow_links(true) {
        let entry = entry.map_err(|e| Error::LoadRules {
            dir: path.to_path_buf(),
            reason: format!("{e}"),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let ext = p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
        if matches!(ext.as_deref(), Some("yar") | Some("yara")) {
            out.push(p.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

/// Compile every rule file under `paths`.
///
/// Without `ignore_invalid`, any file that fails the audit or the compiler
/// fails the load, with every such failure listed (as `yr` reports all
/// compile errors before exiting).
pub fn compile_paths(paths: &[RulesPath], cfg: &CompileConfig) -> Result<CompiledRules> {
    let mut sets: Vec<(String, Vec<PathBuf>)> = Vec::new();
    for rp in paths {
        let ns = rp.namespace.clone().unwrap_or_else(|| "default".to_string());
        sets.push((ns, rule_files(&rp.path)?));
    }

    let mut compiler = Compiler::new();
    // libyara accepted regex constructs yara-x rejects by default; see
    // compile.rs. A rule that compiles here but not under `yr` is the safe
    // direction of difference.
    compiler.relaxed_re_syntax(true);
    compiler.enable_includes(true);
    for m in &cfg.ignore_modules {
        compiler.ignore_module(m.as_str());
    }
    let mut include_dirs: Vec<PathBuf> = cfg.include_dirs.clone();
    for (_, files) in &sets {
        include_dirs.extend(files.iter().filter_map(|f| f.parent().map(Path::to_path_buf)));
    }
    include_dirs.sort();
    include_dirs.dedup();
    for d in &include_dirs {
        compiler.add_include_dir(d);
    }
    for (name, value) in &cfg.defines {
        let r = match value {
            ExternalValue::Integer(i) => compiler.define_global(name, *i),
            ExternalValue::Float(f) => compiler.define_global(name, *f),
            ExternalValue::Bool(b) => compiler.define_global(name, *b),
            ExternalValue::String(s) => compiler.define_global(name, s.as_str()),
        };
        if let Err(e) = r {
            return Err(Error::CompileFailed { path: PathBuf::from(format!("--define {name}")), msg: e.to_string() });
        }
    }

    let mut warnings = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut compiled = 0usize;
    for (ns, files) in &sets {
        compiler.new_namespace(ns);
        for file in files {
            let problem = (|| -> std::result::Result<String, String> {
                let len = std::fs::metadata(file).map_err(|e| format!("could not stat: {e}"))?.len();
                if len > MAX_RULE_SOURCE_BYTES {
                    return Err(format!("{len} bytes exceeds the {MAX_RULE_SOURCE_BYTES}-byte rule source limit"));
                }
                let src = std::fs::read_to_string(file).map_err(|e| format!("could not read: {e}"))?;
                audit_rule_source(file, &src).map_err(|e| e.to_string())?;
                Ok(src)
            })();
            let src = match problem {
                Ok(s) => s,
                Err(msg) => {
                    let line = format!("{}: {msg}", file.display());
                    if cfg.ignore_invalid { warnings.push(line) } else { errors.push(line) }
                    continue;
                }
            };
            if cfg.path_as_namespace {
                compiler.new_namespace(&file.to_string_lossy());
            }
            let origin = file.to_string_lossy().to_string();
            match compiler.add_source(SourceCode::from(src.as_str()).with_origin(&origin)) {
                Ok(_) => compiled += 1,
                Err(e) => {
                    let line = format!("{e}");
                    if cfg.ignore_invalid { warnings.push(line) } else { errors.push(line) }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(Error::CompileFailed {
            path: paths.first().map(|p| p.path.clone()).unwrap_or_default(),
            msg: errors.join("\n"),
        });
    }
    warnings.extend(compiler.warnings().iter().map(|w| w.to_string()));
    Ok(CompiledRules { rules: Arc::new(compiler.build()), warnings, files: compiled })
}

impl CompiledRules {
    pub fn rule_count(&self) -> usize {
        self.rules.iter().count()
    }

    /// Scan one file. Safe to call from several threads at once: each call
    /// gets its own scanner.
    pub fn scan_file(&self, path: &Path, cfg: &ScanConfig) -> Result<FileScan> {
        let target = path.display().to_string();
        let rules = self.rules.clone();
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut scanner = Scanner::new(rules.as_ref());
            if !cfg.timeout.is_zero() {
                scanner.set_timeout(cfg.timeout);
            }
            if let Some(n) = cfg.max_matches_per_pattern {
                scanner.max_matches_per_pattern(n);
            }
            scanner.scan_file(path).map(|results| FileScan {
                matching: results.matching_rules().map(|r| rule_result(&r, !cfg.summary_only)).collect(),
                non_matching: if cfg.non_matching {
                    results.non_matching_rules().map(|r| rule_result(&r, !cfg.summary_only)).collect()
                } else {
                    Vec::new()
                },
            })
        }))
        .map_err(|_| Error::ScanFailed { target: target.clone(), reason: "internal panic in yara-x".into() })?;
        outcome.map_err(|e| match e {
            yara_x::ScanError::Timeout => Error::Timeout { target, elapsed: cfg.timeout },
            other => Error::ScanFailed { target, reason: other.to_string() },
        })
    }
}

fn rule_result(rule: &yara_x::Rule<'_, '_>, details: bool) -> RuleResult {
    if !details {
        return RuleResult {
            identifier: rule.identifier().to_string(),
            namespace: rule.namespace().to_string(),
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            meta: Vec::new(),
            patterns: Vec::new(),
        };
    }
    RuleResult {
        identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
        meta: rule
            .metadata()
            .map(|(k, v)| {
                let v = match v {
                    MetaValue::Integer(i) => MetaVal::Integer(i),
                    MetaValue::Float(f) => MetaVal::Float(f),
                    MetaValue::Bool(b) => MetaVal::Bool(b),
                    MetaValue::String(s) => MetaVal::String(s.to_string()),
                    MetaValue::Bytes(b) => MetaVal::Bytes(b.to_vec()),
                };
                (k.to_string(), v)
            })
            .collect(),
        patterns: rule
            .patterns()
            .flat_map(|p| {
                let identifier = p.identifier().to_string();
                let kind = match p.kind() {
                    yara_x::PatternKind::Text => PatternKind::Text,
                    yara_x::PatternKind::Regexp => PatternKind::Regexp,
                    yara_x::PatternKind::Hex => PatternKind::Hex,
                };
                p.matches()
                    .map(|m| PatternMatch {
                        identifier: identifier.clone(),
                        kind,
                        offset: m.range().start,
                        length: m.range().len(),
                        data: m.data().to_vec(),
                        xor_key: m.xor_key(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap().write_all(body.as_bytes()).unwrap();
        p
    }

    const RULES: &str = r#"
rule mz : pe exe { meta: author = "t" score = 5 strings: $a = "MZ" condition: $a at 0 }
rule hexy { strings: $h = { 41 42 43 } condition: $h }
rule never { strings: $n = "nope-not-here" condition: $n }
rule ext_var { condition: min_size > 0 and filesize >= min_size }
"#;

    #[test]
    fn compiles_scans_and_reports_details() {
        let d = tempfile::tempdir().unwrap();
        let rules = write(d.path(), "r.yar", RULES);
        let target = write(d.path(), "t.bin", "MZ..ABC");
        let cfg = CompileConfig {
            defines: vec![("min_size".into(), ExternalValue::Integer(1))],
            ..Default::default()
        };
        let c = compile_paths(&[RulesPath { namespace: Some("ns1".into()), path: rules }], &cfg).unwrap();
        assert_eq!(c.rule_count(), 4);
        let r = c.scan_file(&target, &ScanConfig { non_matching: true, ..Default::default() }).unwrap();
        let names: Vec<_> = r.matching.iter().map(|m| m.identifier.as_str()).collect();
        assert_eq!(names, ["mz", "hexy", "ext_var"]);
        assert_eq!(r.non_matching.len(), 1);
        let mz = &r.matching[0];
        assert_eq!(mz.namespace, "ns1");
        assert_eq!(mz.tags, ["pe", "exe"]);
        assert_eq!(mz.meta[0], ("author".into(), MetaVal::String("t".into())));
        assert_eq!(mz.meta[1], ("score".into(), MetaVal::Integer(5)));
        assert_eq!((mz.patterns[0].offset, mz.patterns[0].length), (0, 2));
        assert_eq!(r.matching[1].patterns[0].kind, PatternKind::Hex);
    }

    #[test]
    fn invalid_rules_fail_unless_ignored() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "good.yar", "rule g { condition: true }");
        write(d.path(), "bad.yar", "rule b { condition: nope( }");
        write(d.path(), "deep.yara", &format!("rule n {{ condition: {}true{} }}", "(".repeat(300), ")".repeat(300)));
        let paths = [RulesPath { namespace: None, path: d.path().to_path_buf() }];
        let err = compile_paths(&paths, &CompileConfig::default()).err().unwrap().to_string();
        assert!(err.contains("bad.yar") && err.contains("deep.yara"), "{err}");
        let c = compile_paths(&paths, &CompileConfig { ignore_invalid: true, ..Default::default() }).unwrap();
        assert_eq!((c.rule_count(), c.files), (1, 1));
        let skipped: Vec<_> = c.warnings.iter().filter(|w| w.contains("bad.yar") || w.contains("deep.yara")).collect();
        assert_eq!(skipped.len(), 2, "{:#?}", c.warnings);
    }
}
