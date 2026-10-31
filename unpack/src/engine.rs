//! Recursive unpack driver: detect -> handle -> recurse into recovered
//! payloads, with depth, dedup-by-SHA256, and total-output limits.

use crate::binfmt::{self, BinInfo, Format};
use crate::detect::{self, Handler, Kind, Verdict};
use crate::external;
use crate::util::{file_stem, sha256_hex, unique_path, walk_files, Budget};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Options {
    pub out_dir: PathBuf,
    pub max_depth: u32,
    pub max_output: u64,
    pub use_external: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionSummary {
    pub name: String,
    pub raw_size: u64,
    pub entropy: f64,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub handler: String,
    pub status: String, // ok | partial | failed | skipped
    pub message: String,
    /// Every file written by this action.
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub path: String,
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub format: Format,
    pub format_label: String,
    pub entropy: f64,
    pub depth: u32,
    /// How this node was produced from its parent (None for the input).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<(u64, u64)>,
    pub sections: Vec<SectionSummary>,
    pub verdicts: Vec<Verdict>,
    pub actions: Vec<Action>,
    pub children: Vec<Node>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

struct Ctx {
    opts: Options,
    budget: Budget,
    seen: HashSet<String>,
    nodes: usize,
}

const MAX_NODES: usize = 200;
const EXT_TIMEOUT: Duration = Duration::from_secs(180);

pub struct RunOutput {
    pub root: Node,
    pub bytes_written: u64,
}

pub fn run(input: &Path, opts: Options) -> Result<RunOutput, String> {
    let bytes = std::fs::read(input).map_err(|e| format!("cannot read {}: {}", input.display(), e))?;
    std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("cannot create {}: {}", opts.out_dir.display(), e))?;
    let budget = Budget::new(opts.max_output);
    let mut ctx = Ctx { opts, budget, seen: HashSet::new(), nodes: 0 };
    let root = process(input, &bytes, 0, None, &mut ctx);
    let used = ctx.budget.used();
    // Drop an empty output directory: nothing was recovered.
    if std::fs::read_dir(&ctx.opts.out_dir).map(|mut d| d.next().is_none()).unwrap_or(false) {
        let _ = std::fs::remove_dir(&ctx.opts.out_dir);
    }
    Ok(RunOutput { root, bytes_written: used })
}

fn summarize_sections(info: &BinInfo) -> Vec<SectionSummary> {
    info.sections
        .iter()
        .map(|s| SectionSummary {
            name: if s.name.is_empty() { "<unnamed>".into() } else { s.name.clone() },
            raw_size: s.raw_size,
            entropy: (s.entropy * 100.0).round() / 100.0,
            flags: format!("{}{}", if s.exec { "X" } else { "-" }, if s.write { "W" } else { "-" }),
        })
        .collect()
}

/// The node's format label. binfmt only knows executables and archives, so
/// fill in the two kinds of payload Unpack itself recovers that it would
/// otherwise call "Unknown": Python bytecode and plain-text reports.
fn format_label(bytes: &[u8], info: &BinInfo) -> String {
    if !matches!(info.format, Format::Unknown) {
        return info.label();
    }
    if let Some((maj, min)) = crate::pyc::identify(bytes) {
        return format!("Python {maj}.{min} bytecode");
    }
    let head = &bytes[..bytes.len().min(8192)];
    let texty = head.iter().filter(|&&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e) || b >= 0x80).count();
    if !head.is_empty() && !head.contains(&0) && texty * 100 >= head.len() * 95 && std::str::from_utf8(head).map_or_else(|e| e.error_len().is_none(), |_| true) {
        return "Text".to_string();
    }
    info.label()
}

fn shallow(path: &Path, bytes: &[u8], depth: u32, source: Option<String>, note: &str) -> Node {
    let info = binfmt::parse(bytes);
    Node {
        path: path.display().to_string(),
        name: path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        sha256: sha256_hex(bytes),
        size: bytes.len() as u64,
        format: info.format,
        format_label: format_label(bytes, &info),
        entropy: (binfmt::entropy(bytes) * 100.0).round() / 100.0,
        depth,
        source,
        overlay: None,
        sections: vec![],
        verdicts: vec![],
        actions: vec![],
        children: vec![],
        note: Some(note.to_string()),
    }
}

/// A file a handler produced, plus whether it deserves its own analysis pass.
struct Out {
    path: PathBuf,
    recurse: bool,
    source: String,
}

fn process(path: &Path, bytes: &[u8], depth: u32, source: Option<String>, ctx: &mut Ctx) -> Node {
    ctx.nodes += 1;
    let sha = sha256_hex(bytes);
    ctx.seen.insert(sha.clone());
    let info = binfmt::parse(bytes);
    let verdicts = detect::detect(bytes, &info);
    let mut node = Node {
        path: path.display().to_string(),
        name: path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        sha256: sha,
        size: bytes.len() as u64,
        format: info.format,
        format_label: format_label(bytes, &info),
        entropy: (binfmt::entropy(bytes) * 100.0).round() / 100.0,
        depth,
        source,
        overlay: info.overlay_offset.map(|o| (o, info.overlay_size(bytes.len() as u64))).filter(|&(_, s)| s > 0),
        sections: summarize_sections(&info),
        verdicts: verdicts.clone(),
        actions: vec![],
        children: vec![],
        note: None,
    };

    let stem = file_stem(path);
    let mut outs: Vec<Out> = Vec::new();
    for v in &verdicts {
        let Some(h) = &v.handler else { continue };
        if ctx.budget.exhausted() {
            node.actions.push(Action {
                handler: handler_name(h),
                status: "skipped".into(),
                message: "output budget exhausted (--max-output)".into(),
                outputs: vec![],
            });
            continue;
        }
        let (action, produced) = run_handler(h, v, path, bytes, &info, &stem, ctx);
        node.actions.push(action);
        outs.extend(produced);
    }

    for o in outs {
        let Ok(child_bytes) = std::fs::read(&o.path) else { continue };
        let child_sha = sha256_hex(&child_bytes);
        if ctx.seen.contains(&child_sha) {
            node.children.push(shallow(&o.path, &child_bytes, depth + 1, Some(o.source), "duplicate of a file already analysed in this run"));
            continue;
        }
        if !o.recurse {
            continue; // listed in the action's outputs; not a payload worth a layer
        }
        if depth + 1 > ctx.opts.max_depth || ctx.nodes >= MAX_NODES {
            ctx.seen.insert(child_sha);
            node.children.push(shallow(&o.path, &child_bytes, depth + 1, Some(o.source), "not analysed further (--max-depth reached)"));
            continue;
        }
        let child = process(&o.path, &child_bytes, depth + 1, Some(o.source), ctx);
        node.children.push(child);
    }
    node
}

fn handler_name(h: &Handler) -> String {
    match h {
        Handler::Upx { .. } => "upx".into(),
        Handler::FatSplit => "fat_split".into(),
        Handler::PyInstaller { .. } => "pyinstaller".into(),
        Handler::Pyc => "pyc".into(),
        Handler::Nsis => "nsis (7-Zip)".into(),
        Handler::Inno => "innoextract".into(),
        Handler::DotnetResources => "dotnet_resources".into(),
        Handler::Carve { .. } => "carve".into(),
    }
}

fn write_out(ctx: &mut Ctx, name: &str, data: &[u8]) -> Result<PathBuf, String> {
    if (data.len() as u64) > ctx.budget.remaining() {
        return Err("output budget exhausted (--max-output)".into());
    }
    let p = unique_path(&ctx.opts.out_dir, name);
    std::fs::write(&p, data).map_err(|e| e.to_string())?;
    ctx.budget.spend(data.len() as u64);
    Ok(p)
}

fn ok(h: &str, msg: String, outs: &[PathBuf]) -> Action {
    Action { handler: h.into(), status: "ok".into(), message: msg, outputs: outs.iter().map(|p| p.display().to_string()).collect() }
}
fn fail(h: &str, status: &str, msg: String) -> Action {
    Action { handler: h.into(), status: status.into(), message: msg, outputs: vec![] }
}

fn run_handler(h: &Handler, v: &Verdict, path: &Path, bytes: &[u8], info: &BinInfo, stem: &str, ctx: &mut Ctx) -> (Action, Vec<Out>) {
    let ext = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    match h {
        Handler::Upx { tampered } => handle_upx(*tampered, bytes, info, stem, &ext, ctx),
        Handler::FatSplit => {
            let mut outs = Vec::new();
            let mut written = Vec::new();
            for s in &info.fat_slices {
                let (o, sz) = (s.offset as usize, s.size as usize);
                let Some(slice) = bytes.get(o..o.saturating_add(sz)) else { continue };
                match write_out(ctx, &format!("{}_{}", stem, s.arch), slice) {
                    Ok(p) => {
                        written.push(p.clone());
                        outs.push(Out { path: p, recurse: true, source: format!("fat slice {}", s.arch) });
                    }
                    Err(e) => return (fail("fat_split", "partial", e), outs),
                }
            }
            (ok("fat_split", format!("split {} architecture slice(s)", written.len()), &written), outs)
        }
        Handler::PyInstaller { cookie_offset } => {
            let dir = unique_path(&ctx.opts.out_dir, &format!("{}_pyinstaller", stem));
            match crate::pyinstaller::extract(bytes, *cookie_offset as usize, &dir, &mut ctx.budget) {
                Ok(x) => {
                    let primary: Vec<_> = x.entries.iter().filter(|e| e.primary).collect();
                    let mut msg = format!(
                        "extracted {} entries (Python {}) to {}; entry script(s): {}",
                        x.entries.len(),
                        x.pyver,
                        dir.display(),
                        if primary.is_empty() { "none identified".to_string() } else { primary.iter().map(|e| e.name.clone()).collect::<Vec<_>>().join(", ") }
                    );
                    if !x.skipped.is_empty() {
                        msg.push_str(&format!("; {} skipped", x.skipped.len()));
                    }
                    let all: Vec<PathBuf> = x.entries.iter().map(|e| e.path.clone()).collect();
                    let outs = x
                        .entries
                        .iter()
                        .filter(|e| e.primary)
                        .map(|e| Out { path: e.path.clone(), recurse: true, source: "PyInstaller entry script".into() })
                        .collect();
                    (Action { status: if x.skipped.is_empty() { "ok".into() } else { "partial".into() }, ..ok("pyinstaller", msg, &all) }, outs)
                }
                Err(e) => (fail("pyinstaller", "failed", e), vec![]),
            }
        }
        Handler::Pyc => handle_pyc(bytes, path, stem, ctx),
        Handler::DotnetResources => {
            let dir = unique_path(&ctx.opts.out_dir, &format!("{}_resources", stem));
            match crate::dotnet::extract(bytes, info, &dir, &mut ctx.budget) {
                Ok(x) if x.resources.is_empty() && x.skipped.is_empty() => {
                    let _ = std::fs::remove_dir(&dir);
                    (fail("dotnet_resources", "ok", "no embedded managed resources".into()), vec![])
                }
                Ok(x) => {
                    let names: Vec<String> = x.resources.iter().map(|r| match &r.note {
                        Some(n) => format!("{} [{}]", r.name, n),
                        None => r.name.clone(),
                    }).collect();
                    let mut msg = format!("extracted {} resource(s): {}", x.resources.len(), names.join(", "));
                    if !x.skipped.is_empty() {
                        msg.push_str(&format!("; skipped: {}", x.skipped.join("; ")));
                    }
                    let all: Vec<PathBuf> = x.resources.iter().map(|r| r.path.clone()).collect();
                    let outs = x
                        .resources
                        .iter()
                        .map(|r| Out {
                            path: r.path.clone(),
                            // Only executables become layers; benign assemblies
                            // carry plenty of non-code resources (icons, sounds).
                            recurse: r.primary,
                            source: format!(".NET resource {}", r.name),
                        })
                        .collect();
                    (ok("dotnet_resources", msg, &all), outs)
                }
                Err(e) => (fail("dotnet_resources", "failed", e), vec![]),
            }
        }
        Handler::Carve { offset, size, what } => {
            let (o, sz) = (*offset as usize, *size as usize);
            let Some(data) = bytes.get(o..o.saturating_add(sz).min(bytes.len())) else {
                return (fail("carve", "failed", "region out of bounds".into()), vec![]);
            };
            let ext = detect::sniff_magic(data).map(|(_, e)| e).unwrap_or("bin");
            match write_out(ctx, &format!("{}_carved_{:x}.{}", stem, offset, ext), data) {
                Ok(p) => {
                    let recurse = binfmt::identify(data).is_executable() || v.kind == Kind::Embedded;
                    let a = ok("carve", format!("carved {} ({} bytes at {:#x})", what, data.len(), offset), std::slice::from_ref(&p));
                    (a, vec![Out { path: p, recurse, source: format!("carved {} at {:#x}", what, offset) }])
                }
                Err(e) => (fail("carve", "failed", e), vec![]),
            }
        }
        Handler::Nsis => external_extract(&external::SEVENZIP, "nsis (7-Zip)", path, stem, "nsis", ctx, |bin, src, dir| {
            let o = format!("-o{}", dir.display());
            external::run(bin, &["x".as_ref(), "-y".as_ref(), "-bd".as_ref(), o.as_ref(), src.as_os_str()], EXT_TIMEOUT)
        }),
        Handler::Inno => external_extract(&external::INNOEXTRACT, "innoextract", path, stem, "inno", ctx, |bin, src, dir| {
            external::run(bin, &["-e".as_ref(), "-q".as_ref(), "-d".as_ref(), dir.as_os_str(), src.as_os_str()], EXT_TIMEOUT)
        }),
    }
}

/// Python bytecode: write the strings report (a payload, so Analyze runs
/// mStrings on it) and every peeled obfuscation layer (kept as outputs only).
fn handle_pyc(bytes: &[u8], path: &Path, stem: &str, ctx: &mut Ctx) -> (Action, Vec<Out>) {
    let peeled = match crate::pyc::peel(bytes) {
        Ok(p) => p,
        Err(e) => return (fail("pyc", "failed", e), vec![]),
    };
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut written = Vec::new();
    for (i, l) in peeled.layers.iter().enumerate() {
        // Saved as .txt / .marshal so nothing is runnable by double-click.
        let (fname, data): (String, &[u8]) = match &l.data {
            crate::pyc::LayerData::Source(s) => (format!("{}_layer{}_source.py.txt", stem, i + 2), s.as_bytes()),
            crate::pyc::LayerData::Marshal(m) => (format!("{}_layer{}.marshal", stem, i + 2), m.as_slice()),
        };
        match write_out(ctx, &fname, data) {
            Ok(p) => written.push(p),
            Err(e) => return (fail("pyc", "partial", e), vec![]),
        }
    }
    let report = crate::pyc::strings_report(&peeled, &name);
    let strings_path = match write_out(ctx, &format!("{}_pyc_strings.txt", stem), report.as_bytes()) {
        Ok(p) => p,
        Err(e) => return (fail("pyc", "partial", e), vec![]),
    };
    written.push(strings_path.clone());
    let funcs = crate::pyc::walk(&peeled.inner).len();
    let msg = if peeled.layers.is_empty() {
        format!("Python {}.{}: extracted strings from {} code object(s)", peeled.version.0, peeled.version.1, funcs)
    } else {
        format!(
            "Python {}.{}: peeled {} obfuscation layer(s) ({}); extracted strings from {} code object(s) in the innermost layer{}",
            peeled.version.0,
            peeled.version.1,
            peeled.layers.len(),
            peeled.layers.iter().map(|l| l.how.as_str()).collect::<Vec<_>>().join(" -> "),
            funcs,
            peeled.error.as_ref().map(|e| format!("; {e}")).unwrap_or_default()
        )
    };
    let source = if peeled.layers.is_empty() { "Python bytecode strings" } else { "deobfuscated Python bytecode strings" };
    (ok("pyc", msg, &written), vec![Out { path: strings_path, recurse: true, source: source.into() }])
}

fn handle_upx(tampered: bool, bytes: &[u8], info: &BinInfo, stem: &str, ext: &str, ctx: &mut Ctx) -> (Action, Vec<Out>) {
    if !ctx.opts.use_external {
        return (fail("upx", "skipped", "external helpers disabled (--no-external)".into()), vec![]);
    }
    let Some(upx) = external::find(&external::UPX) else {
        return (
            fail("upx", "skipped", format!("UPX detected but the `upx` binary was not found — install it ({}) or set MALCHELA_UPX", external::UPX.install_hint)),
            vec![],
        );
    };
    let mut work = bytes.to_vec();
    let mut notes = Vec::new();
    if tampered {
        let rep = crate::upx::repair(&mut work, info);
        notes.extend(rep.notes);
    }
    let work_path = unique_path(&ctx.opts.out_dir, &format!(".{}.upxwork", stem));
    if let Err(e) = std::fs::write(&work_path, &work) {
        return (fail("upx", "failed", format!("cannot write working copy: {}", e)), vec![]);
    }
    let dest = unique_path(&ctx.opts.out_dir, &format!("{}_upx{}", stem, ext));
    let res = external::run(&upx, &["-d".as_ref(), "-q".as_ref(), "-o".as_ref(), dest.as_os_str(), work_path.as_os_str()], EXT_TIMEOUT);
    let _ = std::fs::remove_file(&work_path);

    let repair_txt = if notes.is_empty() { String::new() } else { format!(" Repairs: {}.", notes.join("; ")) };
    if res.ok && dest.is_file() {
        let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        ctx.budget.spend(size);
        let a = ok("upx", format!("decompressed with {} ({} bytes).{}", upx.display(), size, repair_txt), std::slice::from_ref(&dest));
        (a, vec![Out { path: dest, recurse: true, source: if tampered { "upx -d (after header repair)".into() } else { "upx -d".into() } }])
    } else {
        let _ = std::fs::remove_file(&dest);
        let last = res.output.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
        (fail("upx", "failed", format!("upx -d failed: {}.{}", if last.is_empty() { "no output".to_string() } else { last }, repair_txt)), vec![])
    }
}

fn external_extract(
    spec: &external::ToolSpec,
    label: &str,
    path: &Path,
    stem: &str,
    suffix: &str,
    ctx: &mut Ctx,
    invoke: impl Fn(&Path, &Path, &Path) -> external::RunResult,
) -> (Action, Vec<Out>) {
    if !ctx.opts.use_external {
        return (fail(label, "skipped", "external helpers disabled (--no-external)".into()), vec![]);
    }
    let Some(bin) = external::find(spec) else {
        return (fail(label, "skipped", format!("`{}` not found — install it ({}) to extract this installer", spec.key, spec.install_hint)), vec![]);
    };
    let dir = unique_path(&ctx.opts.out_dir, &format!("{}_{}", stem, suffix));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return (fail(label, "failed", e.to_string()), vec![]);
    }
    let res = invoke(&bin, path, &dir);
    let mut files = Vec::new();
    walk_files(&dir, &mut files, 5000);
    // Containment check: anything that resolved outside `dir` is discarded.
    let canon = dir.canonicalize().unwrap_or(dir.clone());
    files.retain(|f| f.canonicalize().map(|c| c.starts_with(&canon)).unwrap_or(false));
    let total: u64 = files.iter().filter_map(|f| std::fs::metadata(f).ok()).map(|m| m.len()).sum();
    ctx.budget.spend(total);
    if files.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
        let last = res.output.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("no output").trim().to_string();
        return (fail(label, "failed", format!("{} extracted nothing: {}", spec.key, last)), vec![]);
    }
    let outs: Vec<Out> = files
        .iter()
        .filter(|f| {
            let head = read_head(f, 4096);
            binfmt::identify(&head).is_executable() || f.extension().map(|e| e.eq_ignore_ascii_case("nsi") || e.eq_ignore_ascii_case("iss")).unwrap_or(false)
        })
        .map(|f| Out { path: f.clone(), recurse: true, source: format!("extracted by {}", spec.key) })
        .collect();
    let status = if res.ok { "ok" } else { "partial" };
    let msg = format!("{} extracted {} file(s) ({} bytes) to {}; {} executable/script payload(s)", spec.key, files.len(), total, dir.display(), outs.len());
    (Action { status: status.into(), ..ok(label, msg, &files) }, outs)
}

fn read_head(p: &Path, n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    match std::fs::File::open(p).and_then(|mut f| f.read(&mut buf)) {
        Ok(k) => {
            buf.truncate(k);
            buf
        }
        Err(_) => vec![],
    }
}

// ── Tree queries used by the reporters ──────────────────────────────────────

pub fn walk<'a>(n: &'a Node, f: &mut impl FnMut(&'a Node)) {
    f(n);
    for c in &n.children {
        walk(c, f);
    }
}

/// Recovered payloads: every descendant node that was produced by a handler
/// and is not a duplicate.
pub fn payloads(root: &Node) -> Vec<&Node> {
    let mut v = Vec::new();
    walk(root, &mut |n| {
        if n.depth > 0 && n.note.as_deref() != Some("duplicate of a file already analysed in this run") {
            v.push(n);
        }
    });
    v
}

/// Anything worth reporting: a non-informational verdict anywhere in the
/// tree, or a recovered payload.
pub fn significant(root: &Node) -> bool {
    let mut found = false;
    walk(root, &mut |n| {
        if n.verdicts.iter().any(|v| v.kind != Kind::Info) {
            found = true;
        }
    });
    found || !payloads(root).is_empty()
}

pub fn packing_found(root: &Node) -> bool {
    let mut found = false;
    walk(root, &mut |n| {
        // An obfuscated .pyc is encoding, not packing (T1027.013 below).
        if n.verdicts.iter().any(|v| v.kind.is_packing() && v.id != "python_obfuscated") {
            found = true;
        }
    });
    found
}

/// Encrypted/encoded payload layers (T1027.013), e.g. an obfuscated .pyc.
pub fn encoded_found(root: &Node) -> bool {
    let mut found = false;
    walk(root, &mut |n| {
        if n.verdicts.iter().any(|v| v.id == "python_obfuscated") {
            found = true;
        }
    });
    found
}

pub fn embedded_found(root: &Node) -> bool {
    let mut found = false;
    walk(root, &mut |n| {
        if n.verdicts.iter().any(|v| matches!(v.kind, Kind::Embedded | Kind::Installer | Kind::Bundler)) {
            found = true;
        }
    });
    found
}
