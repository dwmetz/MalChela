//! yara_scan — scan files with YARA rules using MalChela's embedded YARA-X
//! engine.
//!
//! The command line follows VirusTotal's `yr scan` (yara-x-cli 1.21): the
//! same positional arguments, the same flag names, and the same text, NDJSON,
//! and JSON output, so a command written for one runs on the other. Options
//! `yr` has that this tool does not are rejected by name with a pointer to
//! `yr` instead of being silently ignored. The MalChela additions (`--case`
//! and `--save`) are long-only, because `yr` already uses `-o`, `-t`, and `-m`.
//!
//! Never executes anything it scans.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use serde::Serialize;
use yara_backend::rules_scan::{
    compile_paths, CompileConfig, ExternalValue, FileScan, MetaVal, PatternKind, RuleResult,
    RulesPath, ScanConfig,
};

const TOOL: &str = "yara_scan";

/// Options `yr scan` has that yara_scan does not. Each is accepted by the
/// parser only so it can be refused with a clear message.
const UNSUPPORTED: &[(&str, &str)] = &[
    ("compiled_rules", "--compiled-rules (-C)"),
    ("module_data", "--module-data (-x)"),
    ("profiling", "--profiling"),
    ("cpu_limit", "--cpu-limit"),
    ("fast_scan", "--fast-scan (-f)"),
    ("no_mmap", "--no-mmap"),
];

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Ndjson,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum SaveFormat {
    Md,
    Txt,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "yara_scan",
    version,
    about = "Scan a file or directory with YARA rules (embedded YARA-X engine; flags follow `yr scan`)",
    after_help = "Supports the common `yr scan` options. For compiled rules, module data, profiling, \
fast-scan, or anything else not listed, use VirusTotal's `yr` (see docs/tools/yara-x.md).\n\n\
MalChela additions: --case NAME routes saved reports to the case; --save[=md|txt|json] writes a report."
)]
struct Cli {
    /// [NAMESPACE:]RULES_PATH ... TARGET_PATH. One or more YARA source files or
    /// directories (optionally prefixed with a namespace), then the file or
    /// directory to scan.
    #[arg(value_name = "[NAMESPACE:]RULES_PATH... TARGET_PATH", num_args = 1.., required = true)]
    paths: Vec<String>,

    /// Print only the number of matches per file
    #[arg(short = 'c', long = "count")]
    count: bool,
    /// Define external variable (VAR=VALUE; VALUE is an integer, float, bool, or "quoted string")
    #[arg(short = 'd', long = "define", value_name = "VAR=VALUE", value_parser = parse_define)]
    define: Vec<(String, ExternalValue)>,
    /// Disable printing console log messages (accepted for compatibility; console.log output is never printed)
    #[arg(long = "disable-console-logs")]
    disable_console_logs: bool,
    /// Disable warnings
    #[arg(short = 'w', long = "disable-warnings", value_name = "WARNING_ID", num_args = 0.., require_equals = true, value_delimiter = ',', default_missing_value = "all")]
    disable_warnings: Vec<String>,
    /// Ignore rules that fail to compile and continue with the valid ones
    #[arg(long = "ignore-invalid-rules")]
    ignore_invalid_rules: bool,
    /// Ignore rules that use the specified module
    #[arg(short = 'I', long = "ignore-module", value_name = "MODULE")]
    ignore_module: Vec<String>,
    /// Directory in which to search for included files
    #[arg(long = "include-dir", value_name = "PATH")]
    include_dir: Vec<PathBuf>,
    /// Maximum number of matches per pattern
    #[arg(long = "max-matches-per-pattern", value_name = "MATCHES")]
    max_matches_per_pattern: Option<usize>,
    /// Print non-satisfied rules only
    #[arg(short = 'n', long = "negate")]
    negate: bool,
    /// Output format for results
    #[arg(short = 'o', long = "output-format", value_name = "FORMAT", value_enum, default_value = "text")]
    output_format: OutputFormat,
    /// Use file path as rule namespace
    #[arg(long = "path-as-namespace")]
    path_as_namespace: bool,
    /// Print rule metadata
    #[arg(short = 'm', long = "print-meta")]
    print_meta: bool,
    /// Print rule namespace
    #[arg(short = 'e', long = "print-namespace")]
    print_namespace: bool,
    /// Print matching patterns, optionally limited to N characters (default 120)
    #[arg(short = 's', long = "print-strings", value_name = "N", num_args = 0..=1, require_equals = true, default_missing_value = "120")]
    print_strings: Option<usize>,
    /// Print rule tags
    #[arg(short = 'g', long = "print-tags")]
    print_tags: bool,
    /// Scan directories recursively, optionally limited to MAX_DEPTH levels (-r=3)
    #[arg(short = 'r', long = "recursive", value_name = "MAX_DEPTH", num_args = 0..=1, require_equals = true, default_missing_value = "1000")]
    recursive: Option<usize>,
    /// Use a more relaxed syntax check while parsing regular expressions (always on here)
    #[arg(long = "relaxed-re-syntax")]
    relaxed_re_syntax: bool,
    /// TARGET_PATH is a file containing the paths to be scanned
    #[arg(long = "scan-list")]
    scan_list: bool,
    /// Skip files larger than the given size (bytes)
    #[arg(short = 'z', long = "skip-larger", value_name = "FILE_SIZE")]
    skip_larger: Option<u64>,
    /// Print only rules tagged as TAG
    #[arg(short = 't', long = "tag", value_name = "TAG")]
    tag: Option<String>,
    /// Use the given number of threads
    #[arg(short = 'p', long = "threads", value_name = "NUM_THREADS", value_parser = clap::value_parser!(u8).range(1..))]
    threads: Option<u8>,
    /// Abort scanning after the given number of seconds
    #[arg(short = 'a', long = "timeout", value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
    timeout: Option<u64>,

    /// MalChela: route saved reports to this case
    #[arg(long = "case", value_name = "CASE")]
    case: Option<String>,
    /// MalChela: save a report (md by default, or --save=txt / --save=json)
    #[arg(long = "save", value_name = "FORMAT", value_enum, num_args = 0..=1, require_equals = true, default_missing_value = "md")]
    save: Option<SaveFormat>,

    // `yr` options this tool does not implement: parsed only to refuse them.
    #[arg(short = 'C', long = "compiled-rules", hide = true)]
    compiled_rules: bool,
    #[arg(short = 'x', long = "module-data", hide = true)]
    module_data: Vec<String>,
    #[arg(long = "profiling", hide = true)]
    profiling: bool,
    #[arg(long = "cpu-limit", hide = true)]
    cpu_limit: Option<String>,
    #[arg(short = 'f', long = "fast-scan", hide = true)]
    fast_scan: bool,
    #[arg(long = "no-mmap", hide = true)]
    no_mmap: bool,
}

/// `yr`'s --define syntax: VALUE is parsed as JSON, so strings are quoted.
fn parse_define(s: &str) -> Result<(String, ExternalValue), String> {
    let (var, value) = s
        .split_once('=')
        .ok_or_else(|| format!("the equal sign is missing, use the syntax VAR=VALUE (example: {s}=10)"))?;
    let v: serde_json::Value =
        serde_json::from_str(value).map_err(|_| format!("`{value}` is not a valid value, did you mean \\\"{value}\\\"?"))?;
    let ev = match v {
        serde_json::Value::Bool(b) => ExternalValue::Bool(b),
        serde_json::Value::String(s) => ExternalValue::String(s),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => ExternalValue::Integer(i),
            None => ExternalValue::Float(n.as_f64().unwrap_or_default()),
        },
        _ => return Err(format!("`{value}` is not a valid value: use an integer, float, bool, or \"string\"")),
    };
    Ok((var.to_string(), ev))
}

/// `[NAMESPACE:]PATH`, as `yr` parses it. On Windows a one-letter prefix is a
/// drive letter, not a namespace.
fn parse_rules_path(s: &str) -> RulesPath {
    if let Some((ns, path)) = s.split_once(':') {
        if !(cfg!(windows) && ns.len() == 1) && !ns.is_empty() && !path.is_empty() {
            return RulesPath { namespace: Some(ns.to_string()), path: PathBuf::from(path) };
        }
    }
    RulesPath { namespace: None, path: PathBuf::from(s) }
}

fn targets(cli: &Cli, target: &Path) -> Result<Vec<PathBuf>, String> {
    if cli.scan_list {
        let list = std::fs::read_to_string(target).map_err(|e| format!("can not read `{}`: {e}", target.display()))?;
        return Ok(list.lines().map(str::trim).filter(|l| !l.is_empty()).map(PathBuf::from).collect());
    }
    let md = std::fs::metadata(target).map_err(|e| format!("`{}`: {e}", target.display()))?;
    if md.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    let depth = cli.recursive.unwrap_or(0);
    let mut out: Vec<PathBuf> = walkdir::WalkDir::new(target)
        .min_depth(1)
        .max_depth(depth.saturating_add(1))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    out.sort();
    Ok(out)
}

struct FileOutcome {
    path: PathBuf,
    rules: Vec<RuleResult>,
}

fn escape(data: &[u8], limit: usize) -> String {
    data.iter().take(limit).flat_map(|b| b.escape_ascii()).map(|c| c as char).collect()
}

fn more_bytes(len: usize, limit: usize) -> String {
    match len.saturating_sub(limit) {
        0 => String::new(),
        n => format!(" ... {n} more bytes"),
    }
}

/// One rule in `yr`'s text format: `[ns:]rule [tags] [meta] path`, then one
/// `0xOFFSET:LEN:$id: data` line per match with -s.
fn text_rule(cli: &Cli, r: &RuleResult, path: &Path) -> String {
    let mut msg = if cli.print_namespace { format!("{}:{}", r.namespace, r.identifier) } else { r.identifier.clone() };
    if cli.print_tags && !r.tags.is_empty() {
        msg.push_str(&format!(" [{}]", r.tags.join(",")));
    }
    if cli.print_meta && !r.meta.is_empty() {
        let parts: Vec<String> = r
            .meta
            .iter()
            .map(|(k, v)| match v {
                MetaVal::Integer(i) => format!("{k}={i}"),
                MetaVal::Float(f) => format!("{k}={f}"),
                MetaVal::Bool(b) => format!("{k}={b}"),
                MetaVal::String(s) => format!("{k}=\"{s}\""),
                MetaVal::Bytes(b) => format!("{k}=\"{}\"", b.escape_ascii()),
            })
            .collect();
        msg.push_str(&format!(" [{}]", parts.join(",")));
    }
    msg.push(' ');
    msg.push_str(&path.display().to_string());
    if let Some(limit) = cli.print_strings {
        for p in &r.patterns {
            msg.push_str(&format!("\n{:#x}:{}:{}", p.offset, p.length, p.identifier));
            match p.xor_key {
                Some(k) => {
                    let plain: Vec<u8> = p.data.iter().take(limit).map(|b| b ^ k).collect();
                    msg.push_str(&format!(" xor({k:#x},{}): ", escape(&plain, limit)));
                }
                None => msg.push_str(": "),
            }
            let data = &p.data[..p.data.len().min(limit)];
            match p.kind {
                PatternKind::Hex => {
                    msg.push_str(&data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
                }
                _ => msg.push_str(&escape(data, limit)),
            }
            msg.push_str(&more_bytes(p.data.len(), limit));
        }
    }
    msg
}

fn meta_json(v: &MetaVal) -> serde_json::Value {
    match v {
        MetaVal::Integer(i) => (*i).into(),
        MetaVal::Float(f) => serde_json::Number::from_f64(*f).map(Into::into).unwrap_or(serde_json::Value::Null),
        MetaVal::Bool(b) => (*b).into(),
        MetaVal::String(s) => s.clone().into(),
        MetaVal::Bytes(b) => String::from_utf8_lossy(b).into_owned().into(),
    }
}

#[derive(Serialize)]
struct PatternJson {
    identifier: String,
    offset: usize,
    r#match: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    xor_key: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<String>,
}

fn patterns_json(r: &RuleResult, limit: usize) -> Vec<PatternJson> {
    r.patterns
        .iter()
        .map(|p| PatternJson {
            identifier: p.identifier.clone(),
            offset: p.offset,
            r#match: format!("{}{}", escape(&p.data, limit), more_bytes(p.data.len(), limit)),
            xor_key: p.xor_key,
            plaintext: p.xor_key.map(|k| escape(&p.data.iter().take(limit).map(|b| b ^ k).collect::<Vec<_>>(), limit)),
        })
        .collect()
}

/// `yr -o ndjson`: one object per file, meta as [key, value] pairs.
fn ndjson_line(cli: &Cli, f: &FileOutcome) -> String {
    let path = f.path.display().to_string();
    if cli.count {
        return serde_json::json!({ "path": path, "count": f.rules.len() }).to_string();
    }
    let rules: Vec<serde_json::Value> = f
        .rules
        .iter()
        .map(|r| {
            let mut o = serde_json::Map::new();
            o.insert("identifier".into(), r.identifier.clone().into());
            if cli.print_namespace {
                o.insert("namespace".into(), r.namespace.clone().into());
            }
            if cli.print_meta {
                let pairs: Vec<serde_json::Value> =
                    r.meta.iter().map(|(k, v)| serde_json::json!([k, meta_json(v)])).collect();
                o.insert("meta".into(), pairs.into());
            }
            if cli.print_tags {
                o.insert("tags".into(), r.tags.clone().into());
            }
            if let Some(limit) = cli.print_strings {
                o.insert("strings".into(), serde_json::to_value(patterns_json(r, limit)).unwrap());
            }
            serde_json::Value::Object(o)
        })
        .collect();
    serde_json::json!({ "path": path, "rules": rules }).to_string()
}

/// `yr -o json` match objects for one file, meta grouped by key.
fn json_matches_for(cli: &Cli, f: &FileOutcome) -> Vec<serde_json::Value> {
    let file = std::fs::canonicalize(&f.path).map(|p| p.display().to_string()).unwrap_or_default();
    f.rules
        .iter()
        .map(|r| {
            let mut o = serde_json::Map::new();
            o.insert("rule".into(), r.identifier.clone().into());
            o.insert("file".into(), file.clone().into());
            if cli.print_meta {
                let mut grouped: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
                for (k, v) in &r.meta {
                    grouped.entry(k.clone()).or_default().push(meta_json(v));
                }
                let m: serde_json::Map<String, serde_json::Value> = grouped
                    .into_iter()
                    .map(|(k, mut v)| (k, if v.len() == 1 { v.pop().unwrap() } else { v.into() }))
                    .collect();
                o.insert("meta".into(), m.into());
            }
            if cli.print_tags {
                o.insert("tags".into(), r.tags.clone().into());
            }
            if let Some(limit) = cli.print_strings {
                o.insert("strings".into(), serde_json::to_value(patterns_json(r, limit)).unwrap());
            }
            serde_json::Value::Object(o)
        })
        .collect()
}

/// `yr -o json`: one document for the whole run.
fn json_document(matches: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({ "version": format!("MalChela yara_scan {}", env!("CARGO_PKG_VERSION")), "matches": matches })
}

/// `yr`'s text output for one file.
fn file_text(cli: &Cli, f: &FileOutcome) -> String {
    if cli.count {
        return format!("{}: {}\n", f.path.display(), f.rules.len());
    }
    let mut t = String::new();
    for r in &f.rules {
        t.push_str(&text_rule(cli, r, &f.path));
        t.push('\n');
    }
    t
}

/// What the Markdown report keeps of a file: non-satisfied rules (`-n`) by
/// name only, and at most 50 string matches per matching rule.
fn compact(mut f: FileOutcome, negate: bool) -> FileOutcome {
    for r in &mut f.rules {
        if negate {
            r.meta.clear();
            r.patterns.clear();
        } else {
            r.patterns.truncate(51);
        }
    }
    f
}

fn markdown_report(cli: &Cli, rules_paths: &[RulesPath], target: &Path, files: &[FileOutcome], scanned: usize, errors: &[String], rule_count: usize) -> String {
    let cell = |s: &str| s.replace('|', "\\|").replace(['\n', '\r'], " ");
    // Paths relative to the target folder; the header names the target.
    let rel = |p: &Path| -> String {
        match p.strip_prefix(target) {
            Ok(r) if !r.as_os_str().is_empty() => r.display().to_string(),
            _ => p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.display().to_string()),
        }
    };
    let mut md = String::new();
    md.push_str("# YARA Scan Report\n\n");
    md.push_str(&format!("**Generated:** {}  \n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
    md.push_str(&format!("**Target:** `{}`  \n", target.display()));
    let rp: Vec<String> = rules_paths
        .iter()
        .map(|r| match &r.namespace { Some(ns) => format!("`{ns}:{}`", r.path.display()), None => format!("`{}`", r.path.display()) })
        .collect();
    md.push_str(&format!("**Rules:** {} ({rule_count} rules)  \n", rp.join(", ")));
    md.push_str(&format!("**Engine:** embedded YARA-X (MalChela yara_scan {})  \n", env!("CARGO_PKG_VERSION")));
    let label = if cli.negate { "with non-satisfied rules" } else { "matched" };
    md.push_str(&format!("**Files scanned:** {scanned}, {} {label}  \n\n", files.len()));
    if files.is_empty() {
        md.push_str(if cli.negate { "_Every rule was satisfied in every file._\n" } else { "_No rules matched._\n" });
    } else {
        md.push_str("| File | Rule | Namespace | Tags | Matches |\n|---|---|---|---|---|\n");
        for f in files {
            for r in &f.rules {
                md.push_str(&format!(
                    "| `{}` | {} | {} | {} | {} |\n",
                    cell(&rel(&f.path)),
                    cell(&r.identifier),
                    cell(&r.namespace),
                    cell(&r.tags.join(", ")),
                    r.patterns.len()
                ));
            }
        }
        md.push_str("\n## Details\n\n");
        let limit = cli.print_strings.unwrap_or(120);
        for f in files {
            md.push_str(&format!("### `{}`\n\n", rel(&f.path)));
            for r in &f.rules {
                md.push_str(&format!("**{}:{}**", r.namespace, r.identifier));
                if !r.tags.is_empty() {
                    md.push_str(&format!(" [{}]", r.tags.join(", ")));
                }
                md.push('\n');
                if !r.meta.is_empty() {
                    md.push('\n');
                    for (k, v) in &r.meta {
                        md.push_str(&format!("- {k}: {}\n", meta_json(v)));
                    }
                }
                if !r.patterns.is_empty() {
                    md.push_str("\n| Offset | Length | Pattern | Data |\n|---|---|---|---|\n");
                    for p in r.patterns.iter().take(50) {
                        let data = match p.kind {
                            PatternKind::Hex => p.data.iter().take(limit).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                            _ => escape(&p.data, limit),
                        };
                        md.push_str(&format!("| {:#x} | {} | `{}` | `{}{}` |\n", p.offset, p.length, cell(&p.identifier), cell(&data).replace('`', "'"), more_bytes(p.data.len(), limit)));
                    }
                    if r.patterns.len() > 50 {
                        md.push_str("\n_More matches not shown; rerun with -s for the full list._\n");
                    }
                }
                md.push('\n');
            }
        }
    }
    if !errors.is_empty() {
        md.push_str("\n## Errors\n\n");
        for e in errors {
            md.push_str(&format!("- {}\n", cell(e)));
        }
    }
    md
}

fn save_report(cli: &Cli, fmt: SaveFormat, body: &str, target: &Path) {
    let root = common_config::find_workspace_root().unwrap_or_else(|| PathBuf::from("."));
    let dir = match &cli.case {
        Some(c) => root.join("saved_output").join("cases").join(c).join(TOOL),
        None => root.join("saved_output").join(TOOL),
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("error: could not create {}: {e}", dir.display());
        return;
    }
    let ext = match fmt { SaveFormat::Md => "md", SaveFormat::Txt => "txt", SaveFormat::Json => "json" };
    let stem = target.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "scan".into());
    let stem: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    let path = dir.join(format!("{stem}_{}.{ext}", chrono::Local::now().format("%Y%m%d_%H%M%S")));
    match std::fs::write(&path, body) {
        Ok(_) => {
            eprintln!("Report saved to: {}", path.display());
            if let Some(c) = &cli.case {
                common_config::register_case_output(TOOL, c, &target.display().to_string(), &path);
            }
        }
        Err(e) => eprintln!("error: could not write {}: {e}", path.display()),
    }
}

fn run(cli: Cli) -> Result<bool, String> {
    let used: Vec<&str> = UNSUPPORTED
        .iter()
        .filter(|(field, _)| match *field {
            "compiled_rules" => cli.compiled_rules,
            "module_data" => !cli.module_data.is_empty(),
            "profiling" => cli.profiling,
            "cpu_limit" => cli.cpu_limit.is_some(),
            "fast_scan" => cli.fast_scan,
            "no_mmap" => cli.no_mmap,
            _ => false,
        })
        .map(|(_, flag)| *flag)
        .collect();
    if !used.is_empty() {
        return Err(format!(
            "{} not supported by yara_scan. Use VirusTotal's `yr scan`, which takes the same arguments (see docs/tools/yara-x.md).",
            used.join(", ")
        ));
    }

    if cli.paths.len() < 2 {
        return Err("give at least one RULES_PATH and a TARGET_PATH".into());
    }
    let (target, rules) = cli.paths.split_last().expect("checked above");
    let target = PathBuf::from(target);
    let rules_paths: Vec<RulesPath> = rules.iter().map(|s| parse_rules_path(s)).collect();
    for rp in &rules_paths {
        if !rp.path.exists() {
            return Err(format!("rules path not found: {}", rp.path.display()));
        }
    }

    let compiled = compile_paths(
        &rules_paths,
        &CompileConfig {
            defines: cli.define.clone(),
            include_dirs: cli.include_dir.clone(),
            ignore_modules: cli.ignore_module.clone(),
            ignore_invalid: cli.ignore_invalid_rules,
            path_as_namespace: cli.path_as_namespace,
        },
    )
    .map_err(|e| e.to_string())?;
    let show_warnings = cli.disable_warnings.is_empty();
    if show_warnings {
        for w in &compiled.warnings {
            eprintln!("{w}");
        }
    }

    let files = targets(&cli, &target)?;
    let scan_cfg = ScanConfig {
        timeout: Duration::from_secs(cli.timeout.unwrap_or(0)),
        max_matches_per_pattern: cli.max_matches_per_pattern,
        non_matching: cli.negate,
        // Metadata and string data are only needed when something prints
        // them: -m, -s, or a Markdown report of matching rules.
        summary_only: cli.count
            || (!cli.print_meta
                && cli.print_strings.is_none()
                && (cli.negate || cli.save != Some(SaveFormat::Md))),
    };
    let scan_one = |path: &PathBuf| -> (PathBuf, Option<Result<FileScan, String>>) {
        if let Some(limit) = cli.skip_larger {
            if std::fs::metadata(path).map(|m| m.len() > limit).unwrap_or(false) {
                return (path.clone(), None);
            }
        }
        (path.clone(), Some(compiled.scan_file(path, &scan_cfg).map_err(|e| e.to_string())))
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cli.threads.map(usize::from).unwrap_or(0))
        .build()
        .map_err(|e| e.to_string())?;

    // The file list is sorted, so scanning it in batches and printing each
    // batch in order keeps the output sorted by path while holding only one
    // batch of results at a time. (Collecting everything first ran out of
    // memory on `--negate` over a large rule set: every non-satisfied rule,
    // with its metadata, for every file.)
    let batch = pool.current_num_threads().max(1) * 8;
    let want_json = cli.output_format == OutputFormat::Json || cli.save == Some(SaveFormat::Json);
    let mut out = std::io::stdout().lock();
    let mut json_matches: Vec<serde_json::Value> = Vec::new();
    let mut report_files: Vec<FileOutcome> = Vec::new();
    let mut report_text = String::new();
    let mut errors = Vec::new();
    let mut scanned = 0usize;
    let mut any = false;
    for chunk in files.chunks(batch) {
        let results: Vec<(PathBuf, Option<Result<FileScan, String>>)> =
            pool.install(|| chunk.par_iter().map(scan_one).collect());
        for (path, r) in results {
            let Some(r) = r else { continue };
            scanned += 1;
            let fs = match r {
                Ok(fs) => fs,
                Err(e) => {
                    let msg = format!("error: scanning {}: {e}", path.display());
                    eprintln!("{msg}");
                    errors.push(msg);
                    continue;
                }
            };
            let rules: Vec<RuleResult> = if cli.negate { fs.non_matching } else { fs.matching }
                .into_iter()
                .filter(|r| cli.tag.as_ref().map_or(true, |t| r.tags.iter().any(|x| x == t)))
                .collect();
            if rules.is_empty() {
                continue;
            }
            any = true;
            let f = FileOutcome { path, rules };
            let text = match cli.output_format {
                OutputFormat::Text => {
                    let t = file_text(&cli, &f);
                    let _ = out.write_all(t.as_bytes());
                    Some(t)
                }
                OutputFormat::Ndjson => {
                    let _ = writeln!(out, "{}", ndjson_line(&cli, &f));
                    None
                }
                OutputFormat::Json => None,
            };
            if want_json {
                json_matches.extend(json_matches_for(&cli, &f));
            }
            match cli.save {
                Some(SaveFormat::Txt) => report_text.push_str(&text.unwrap_or_else(|| file_text(&cli, &f))),
                Some(SaveFormat::Md) => report_files.push(compact(f, cli.negate)),
                _ => {}
            }
        }
    }
    if cli.output_format == OutputFormat::Json {
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&json_document(json_matches.clone())).unwrap());
    }

    if let Some(fmt) = cli.save {
        let body = match fmt {
            SaveFormat::Md => markdown_report(&cli, &rules_paths, &target, &report_files, scanned, &errors, compiled.rule_count()),
            SaveFormat::Json => serde_json::to_string_pretty(&json_document(json_matches)).unwrap(),
            SaveFormat::Txt => report_text,
        };
        save_report(&cli, fmt, &body, &target);
    }
    Ok(any)
}

fn main() {
    let cli = Cli::parse();
    if let Some(c) = &cli.case {
        common_config::ensure_case_json(c);
    }
    match run(cli) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn define_values_parse_like_yr() {
        assert_eq!(parse_define("a=1").unwrap().1, ExternalValue::Integer(1));
        assert_eq!(parse_define("a=3.5").unwrap().1, ExternalValue::Float(3.5));
        assert_eq!(parse_define("a=true").unwrap().1, ExternalValue::Bool(true));
        assert_eq!(parse_define("a=\"x\"").unwrap().1, ExternalValue::String("x".into()));
        assert!(parse_define("a=foo").is_err());
        assert!(parse_define("a").is_err());
    }

    #[test]
    fn namespace_prefix() {
        let r = parse_rules_path("mal:rules/");
        assert_eq!(r.namespace.as_deref(), Some("mal"));
        assert_eq!(r.path, PathBuf::from("rules/"));
        assert!(parse_rules_path("rules.yar").namespace.is_none());
    }

    #[test]
    fn recursive_and_strings_need_equals() {
        // `-r rules.yar target` must not read rules.yar as a depth.
        let cli = Cli::try_parse_from(["yara_scan", "-r", "rules.yar", "target"]).unwrap();
        assert_eq!(cli.recursive, Some(1000));
        assert_eq!(cli.paths, ["rules.yar", "target"]);
        let cli = Cli::try_parse_from(["yara_scan", "-r=2", "-s=10", "r.yar", "t"]).unwrap();
        assert_eq!((cli.recursive, cli.print_strings), (Some(2), Some(10)));
        let cli = Cli::try_parse_from(["yara_scan", "--save", "r.yar", "t"]).unwrap();
        assert_eq!(cli.save, Some(SaveFormat::Md));
        // Paths may sit on either side of the options, as with `yr`.
        let cli = Cli::try_parse_from(["yara_scan", "r.yar", "-s", "t"]).unwrap();
        assert_eq!(cli.paths, ["r.yar", "t"]);
        let cli = Cli::try_parse_from(["yara_scan", "-s", "r.yar"]).unwrap();
        assert!(run(cli).unwrap_err().contains("TARGET_PATH"));
    }

    #[test]
    fn unsupported_yr_flags_are_refused() {
        let cli = Cli::try_parse_from(["yara_scan", "-C", "r.yarc", "t"]).unwrap();
        let err = run(cli).unwrap_err();
        assert!(err.contains("--compiled-rules") && err.contains("yr"), "{err}");
    }

    #[test]
    fn text_output_matches_yr_format() {
        let d = tempfile::tempdir().unwrap();
        let rules = d.path().join("r.yar");
        std::fs::write(&rules, r#"rule mz : pe { meta: author = "t" strings: $a = "MZ" $h = { 90 90 } condition: $a at 0 and $h }"#).unwrap();
        let target = d.path().join("t.bin");
        std::fs::write(&target, b"MZ\x90\x90").unwrap();
        let compiled = compile_paths(&[parse_rules_path(rules.to_str().unwrap())], &CompileConfig::default()).unwrap();
        let fs = compiled.scan_file(&target, &ScanConfig::default()).unwrap();
        let cli = Cli::try_parse_from(["yara_scan", "-g", "-m", "-s", "r", "t"]).unwrap();
        let line = text_rule(&cli, &fs.matching[0], Path::new("t.bin"));
        assert_eq!(line, "mz [pe] [author=\"t\"] t.bin\n0x0:2:$a: MZ\n0x2:2:$h: 90 90");
    }
}
