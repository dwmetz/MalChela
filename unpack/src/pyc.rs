//! Python bytecode (.pyc): static string extraction and obfuscator peeling.
//!
//! Python stealers ship as PyInstaller bundles whose entry script is a .pyc,
//! often wrapped in obfuscation layers (BlankOBF-style: an xz or zlib blob in
//! the module constants, Python source holding base64 split into rot13'd and
//! reversed pieces, and finally a marshalled code object). None of that is
//! visible to a strings pass over the .pyc itself.
//!
//! This module parses CPython's marshal format directly — it never imports,
//! compiles, unmarshals, or runs anything in a Python interpreter — so the
//! payload's own string constants, names, and function names can be written
//! out as text for mStrings.
//!
//! Supported: CPython 3.7–3.14 code objects (the layouts PyInstaller ships).

use base64::Engine as _;
use std::collections::{BTreeSet, HashMap};
use std::io::Read;

/// pyc header length for 3.7+ (magic, flags, mtime/hash, size).
pub const HEADER_LEN: usize = 16;
const MAX_DEPTH: usize = 256;
const MAX_OBJECTS: usize = 2_000_000;
const MAX_LAYERS: usize = 8;
/// Largest decompressed layer we'll hold (a guard against decompression bombs).
const MAX_LAYER_BYTES: usize = 64 * 1024 * 1024;

/// (major, minor) for a pyc magic number, 3.7–3.14.
pub fn version_for_magic(magic: u16) -> Option<(u8, u8)> {
    Some(match magic {
        3390..=3399 => (3, 7),
        3400..=3419 => (3, 8),
        3420..=3429 => (3, 9),
        3430..=3449 => (3, 10),
        3450..=3499 => (3, 11),
        3500..=3549 => (3, 12),
        3550..=3599 => (3, 13),
        3600..=3649 => (3, 14),
        _ => return None,
    })
}

/// The Python version of a .pyc file, if `b` is one we can parse.
pub fn identify(b: &[u8]) -> Option<(u8, u8)> {
    if b.len() < HEADER_LEN + 1 || &b[2..4] != b"\r\n" {
        return None;
    }
    let v = version_for_magic(u16::from_le_bytes([b[0], b[1]]))?;
    // The body must start with a code object (possibly flagged for refs).
    if b[HEADER_LEN] & 0x7f != b'c' {
        return None;
    }
    Some(v)
}

// ── marshal ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Obj {
    Null,
    None,
    Bool(bool),
    Int(i64),
    Float,
    Str(String),
    Bytes(Vec<u8>),
    Seq(Vec<Obj>),
    Code(Box<Code>),
    Other,
}

#[derive(Debug, Clone, Default)]
pub struct Code {
    pub name: String,
    pub qualname: String,
    pub filename: String,
    pub consts: Vec<Obj>,
    pub names: Vec<String>,
    pub varnames: Vec<String>,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    ver: (u8, u8),
    refs: Vec<Obj>,
    objects: usize,
}

type R<T> = Result<T, String>;

impl<'a> Reader<'a> {
    fn new(b: &'a [u8], ver: (u8, u8)) -> Self {
        Reader { b, pos: 0, ver, refs: Vec::new(), objects: 0 }
    }
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("truncated marshal data")?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }
    fn i32(&mut self) -> R<i32> {
        let s = self.take(4)?;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// A byte length or element count; each element takes at least one byte,
    /// so anything longer than the remaining input is corrupt.
    fn len32(&mut self) -> R<usize> {
        let n = self.i32()?;
        let left = self.b.len().saturating_sub(self.pos);
        if n < 0 || n as usize > left {
            return Err(format!("bad marshal length {n}"));
        }
        Ok(n as usize)
    }

    fn object(&mut self, depth: usize) -> R<Obj> {
        if depth > MAX_DEPTH {
            return Err("marshal nesting too deep".into());
        }
        self.objects += 1;
        if self.objects > MAX_OBJECTS {
            return Err("too many marshal objects".into());
        }
        let code = self.u8()?;
        let flag = code & 0x80 != 0;
        let t = code & 0x7f;
        // Containers reserve their ref slot before their children (as CPython
        // does), so refs made inside them get the right indices.
        let slot = if flag && matches!(t, b'(' | b')' | b'[' | b'{' | b'<' | b'>' | b'c' | b':') {
            self.refs.push(Obj::Other);
            Some(self.refs.len() - 1)
        } else {
            None
        };
        let o = match t {
            b'0' => Obj::Null,
            b'N' => Obj::None,
            b'F' => Obj::Bool(false),
            b'T' => Obj::Bool(true),
            b'S' | b'.' => Obj::Other,
            b'i' => Obj::Int(self.i32()? as i64),
            b'I' => {
                let s = self.take(8)?;
                Obj::Int(i64::from_le_bytes(s.try_into().unwrap()))
            }
            b'l' => {
                let n = self.i32()?;
                let digits = n.unsigned_abs() as usize;
                self.take(digits.checked_mul(2).ok_or("bad long")?)?;
                Obj::Other
            }
            b'g' => {
                self.take(8)?;
                Obj::Float
            }
            b'y' => {
                self.take(16)?;
                Obj::Float
            }
            b'f' => {
                let n = self.u8()? as usize;
                self.take(n)?;
                Obj::Float
            }
            b'x' => {
                for _ in 0..2 {
                    let n = self.u8()? as usize;
                    self.take(n)?;
                }
                Obj::Float
            }
            b's' => {
                let n = self.len32()?;
                Obj::Bytes(self.take(n)?.to_vec())
            }
            b'u' | b't' | b'a' | b'A' => {
                let n = self.len32()?;
                Obj::Str(String::from_utf8_lossy(self.take(n)?).into_owned())
            }
            b'z' | b'Z' => {
                let n = self.u8()? as usize;
                Obj::Str(String::from_utf8_lossy(self.take(n)?).into_owned())
            }
            b'(' | b'[' | b'<' | b'>' => {
                let n = self.len32()?;
                let mut v = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    v.push(self.object(depth + 1)?);
                }
                Obj::Seq(v)
            }
            b')' => {
                let n = self.u8()? as usize;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.object(depth + 1)?);
                }
                Obj::Seq(v)
            }
            b'{' => {
                let mut v = Vec::new();
                loop {
                    let k = self.object(depth + 1)?;
                    if matches!(k, Obj::Null) {
                        break;
                    }
                    v.push(k);
                    v.push(self.object(depth + 1)?);
                }
                Obj::Seq(v)
            }
            b'r' => {
                let i = self.i32()?;
                return self.refs.get(i as usize).cloned().ok_or(format!("bad marshal ref {i}"));
            }
            // 3.14+: a slice constant (start, stop, step).
            b':' => {
                for _ in 0..3 {
                    self.object(depth + 1)?;
                }
                Obj::Other
            }
            b'c' => Obj::Code(Box::new(self.code(depth)?)),
            other => return Err(format!("unsupported marshal type {:?} at {:#x}", other as char, self.pos - 1)),
        };
        match slot {
            Some(i) => self.refs[i] = o.clone(),
            None if flag => self.refs.push(o.clone()),
            None => {}
        }
        Ok(o)
    }

    fn code(&mut self, depth: usize) -> R<Code> {
        let v311 = self.ver >= (3, 11);
        // argcount, posonlyargcount (3.8+), kwonlyargcount, nlocals (<3.11), stacksize, flags
        let ints = if self.ver == (3, 7) || v311 { 5 } else { 6 };
        for _ in 0..ints {
            self.i32()?;
        }
        self.object(depth + 1)?; // bytecode
        let consts = seq(self.object(depth + 1)?);
        let names = strs(self.object(depth + 1)?);
        let varnames = strs(self.object(depth + 1)?); // co_varnames / co_localsplusnames
        self.object(depth + 1)?; // freevars (<3.11) / co_localspluskinds (3.11+)
        if !v311 {
            self.object(depth + 1)?; // cellvars
        }
        let filename = string(self.object(depth + 1)?);
        let name = string(self.object(depth + 1)?);
        let qualname = if v311 { string(self.object(depth + 1)?) } else { name.clone() };
        self.i32()?; // firstlineno
        self.object(depth + 1)?; // lnotab / linetable
        if v311 {
            self.object(depth + 1)?; // exceptiontable
        }
        Ok(Code { name, qualname, filename, consts, names, varnames })
    }
}

fn seq(o: Obj) -> Vec<Obj> {
    match o {
        Obj::Seq(v) => v,
        _ => vec![],
    }
}
fn string(o: Obj) -> String {
    match o {
        Obj::Str(s) => s,
        Obj::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
        _ => String::new(),
    }
}
fn strs(o: Obj) -> Vec<String> {
    seq(o).into_iter().map(string).collect()
}

/// Parse a marshalled code object (no pyc header).
pub fn parse_code(b: &[u8], ver: (u8, u8)) -> R<Code> {
    let mut r = Reader::new(b, ver);
    match r.object(0)? {
        Obj::Code(c) => Ok(*c),
        _ => Err("marshal data is not a code object".into()),
    }
}

/// Every code object reachable from `c` (module first), depth-first.
pub fn walk(c: &Code) -> Vec<&Code> {
    fn go<'a>(c: &'a Code, out: &mut Vec<&'a Code>) {
        out.push(c);
        for k in &c.consts {
            visit(k, out);
        }
    }
    fn visit<'a>(o: &'a Obj, out: &mut Vec<&'a Code>) {
        match o {
            Obj::Code(c) => go(c, out),
            Obj::Seq(v) => v.iter().for_each(|x| visit(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    go(c, &mut out);
    out
}

// ── Strings ─────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Strings {
    pub functions: Vec<String>,
    pub names: BTreeSet<String>,
    pub constants: BTreeSet<String>,
    /// Tuple constants of 5+ strings, in their original order (a list
    /// literal compiles to one). Kept together so a list — a stealer's
    /// blocklist of sandbox IPs, a set of browser paths — stays a list.
    pub lists: Vec<Vec<String>>,
}

const STRING_LIST_MIN: usize = 5;

fn printable_ratio(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    b.iter().filter(|&&c| (0x20..0x7f).contains(&c) || matches!(c, b'\n' | b'\t' | b'\r')).count() as f64 / b.len() as f64
}

fn collect_obj(o: &Obj, s: &mut Strings) {
    match o {
        Obj::Str(x) if x.chars().count() >= 3 => {
            s.constants.insert(x.clone());
        }
        Obj::Bytes(b) if b.len() >= 4 && printable_ratio(b) > 0.95 => {
            s.constants.insert(String::from_utf8_lossy(b).into_owned());
        }
        // Obfuscators hide names as tuples of byte values: (98, 97, 115, ...).
        Obj::Seq(v) if v.len() >= 3 && v.iter().all(|x| matches!(x, Obj::Int(n) if (0x20..0x7f).contains(n))) => {
            let t: String = v.iter().map(|x| if let Obj::Int(n) = x { *n as u8 as char } else { ' ' }).collect();
            if let Some(d) = b64(&t).filter(|d| printable_ratio(d) > 0.95) {
                s.constants.insert(String::from_utf8_lossy(&d).into_owned());
            }
            s.constants.insert(t);
        }
        Obj::Seq(v) if v.len() >= STRING_LIST_MIN && v.iter().all(|x| matches!(x, Obj::Str(_))) => {
            let items: Vec<String> = v.iter().filter_map(|x| if let Obj::Str(t) = x { Some(t.clone()) } else { None }).collect();
            if !s.lists.contains(&items) {
                s.lists.push(items);
            }
        }
        Obj::Seq(v) => v.iter().for_each(|x| collect_obj(x, s)),
        _ => {}
    }
}

pub fn strings(c: &Code) -> Strings {
    let mut s = Strings::default();
    for code in walk(c) {
        let q = if code.qualname.is_empty() { &code.name } else { &code.qualname };
        s.functions.push(q.clone());
        for n in code.names.iter().chain(code.varnames.iter()) {
            if n.len() >= 2 {
                s.names.insert(n.clone());
            }
        }
        for k in &code.consts {
            collect_obj(k, &mut s);
        }
    }
    s
}

// ── Obfuscation layers ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum LayerData {
    Source(String),
    Marshal(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Layer {
    /// How this layer was reached from the previous one, e.g. "xz" or
    /// "rot13 of the first piece, concatenated 4 pieces (some reversed) + base64".
    pub how: String,
    pub data: LayerData,
}

fn bounded(out: Vec<u8>) -> Option<Vec<u8>> {
    (out.len() <= MAX_LAYER_BYTES).then_some(out)
}
fn decompress_xz(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(b), &mut out).ok()?;
    bounded(out)
}
fn decompress_lzma(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    lzma_rs::lzma_decompress(&mut std::io::Cursor::new(b), &mut out).ok()?;
    bounded(out)
}
fn decompress_zlib(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(b).take(MAX_LAYER_BYTES as u64 + 1).read_to_end(&mut out).ok()?;
    bounded(out)
}
fn decompress_gzip(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(b).take(MAX_LAYER_BYTES as u64 + 1).read_to_end(&mut out).ok()?;
    bounded(out)
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if t.len() < 4 || !t.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_')) {
        return None;
    }
    let body = t.trim_end_matches('=');
    let padded = format!("{}{}", body, "=".repeat((4 - body.len() % 4) % 4));
    base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded))
        .ok()
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

fn looks_compressed(d: &[u8], kind: &str) -> bool {
    match kind {
        "xz" => d.starts_with(b"\xfd7zXZ\x00"),
        "zlib" => d.len() > 2 && d[0] == 0x78 && matches!(d[1], 0x01 | 0x5e | 0x9c | 0xda),
        "gzip" => d.starts_with(b"\x1f\x8b\x08"),
        "lzma" => d.len() > 13 && d[0] == 0x5d && d[1] == 0 && d[2] == 0,
        _ => false,
    }
}

fn looks_like_python(s: &str) -> bool {
    let markers = ["import ", "exec(", "eval(", "def ", "lambda", "__import__", "marshal", "base64", "=\"", "='"];
    markers.iter().filter(|m| s.contains(*m)).count() >= 2
}

/// What a decoded blob turned out to be, decompressing first if needed.
fn classify(data: Vec<u8>, how: String, depth: u8) -> Option<Layer> {
    if data.len() < 8 || depth > 4 {
        return None;
    }
    if data[0] & 0x7f == b'c' && data.len() > 32 {
        return Some(Layer { how, data: LayerData::Marshal(data) });
    }
    // A full pyc (header included) inside a layer.
    if data.len() > HEADER_LEN + 32 && &data[2..4] == b"\r\n" && data[HEADER_LEN] & 0x7f == b'c' {
        return Some(Layer { how: format!("{how} (pyc)"), data: LayerData::Marshal(data[HEADER_LEN..].to_vec()) });
    }
    type Decomp = fn(&[u8]) -> Option<Vec<u8>>;
    let decomps: [(&str, Decomp); 4] = [("xz", decompress_xz), ("zlib", decompress_zlib), ("gzip", decompress_gzip), ("lzma", decompress_lzma)];
    for (name, f) in decomps {
        if looks_compressed(&data, name) {
            if let Some(d) = f(&data) {
                let how = if how.is_empty() { name.to_string() } else { format!("{how} + {name}") };
                return classify(d, how, depth + 1);
            }
        }
    }
    if printable_ratio(&data[..data.len().min(4096)]) > 0.97 {
        if let Ok(s) = String::from_utf8(data) {
            if looks_like_python(&s) {
                return Some(Layer { how, data: LayerData::Source(s) });
            }
        }
    }
    None
}

/// Long string literals in Python source, with the name each is assigned to
/// when the source reads `name = "..."`.
fn source_literals(src: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q == b'"' || q == b'\'' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != q {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if j >= b.len() {
                break;
            }
            if j - start >= 64 {
                let before = src[..i].trim_end();
                let name = before
                    .strip_suffix('=')
                    .map(|x| {
                        let x = x.trim_end();
                        let p = x.rfind(|c: char| !(c.is_alphanumeric() || c == '_')).map(|p| p + 1).unwrap_or(0);
                        x[p..].to_string()
                    })
                    .filter(|n| !n.is_empty());
                out.push((name, src[start..j].to_string()));
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Try to reach the next layer from Python source.
fn next_from_source(src: &str, ver: (u8, u8)) -> Option<Layer> {
    let lits = source_literals(src);
    if lits.is_empty() {
        return None;
    }
    // BlankOBF-style: the payload is several named pieces concatenated in the
    // order the decode expression uses them, some reversed ([::-1]) and the
    // first rot13'd, then base64-decoded.
    let named: HashMap<&str, &str> = lits.iter().filter_map(|(n, v)| n.as_deref().map(|n| (n, v.as_str()))).collect();
    if named.len() >= 2 {
        // The decode expression comes after the last assignment.
        let last = lits.last().map(|l| l.1.as_str()).unwrap_or("");
        let tail = src.rfind(last).map(|p| &src[p + last.len()..]).unwrap_or("");
        let mut order: Vec<(usize, &str, bool)> = Vec::new(); // (position, name, reversed)
        for n in named.keys() {
            let mut from = 0;
            while let Some(p) = tail[from..].find(n) {
                let at = from + p;
                let end = at + n.len();
                let ok = tail[..at].chars().last().is_none_or(|c| !is_ident(c)) && tail[end..].chars().next().is_none_or(|c| !is_ident(c));
                if ok {
                    order.push((at, n, tail[end..].starts_with("[::-1]")));
                    break;
                }
                from = end;
            }
        }
        order.sort_by_key(|x| x.0);
        if order.len() == named.len() {
            for rot_first in [true, false] {
                let mut joined = String::new();
                for (k, (_, n, rev)) in order.iter().enumerate() {
                    let mut piece = named[n].to_string();
                    if *rev {
                        piece = piece.chars().rev().collect();
                    }
                    if k == 0 && rot_first {
                        piece = rot13(&piece);
                    }
                    joined.push_str(&piece);
                }
                if let Some(d) = b64(&joined) {
                    let how = format!(
                        "{}{} concatenated pieces{} + base64",
                        if rot_first { "rot13 + " } else { "" },
                        order.len(),
                        if order.iter().any(|x| x.2) { " (some reversed)" } else { "" }
                    );
                    if let Some(l) = classify(d, how, 0).filter(|l| valid(l, ver)) {
                        return Some(l);
                    }
                }
            }
        }
    }
    // Generic: one literal that decodes to the next layer as is, reversed, or rot13'd.
    for (_, v) in &lits {
        let cands = [("base64", v.clone()), ("reversed + base64", v.chars().rev().collect()), ("rot13 + base64", rot13(v))];
        for (label, cand) in cands {
            if let Some(d) = b64(&cand) {
                if let Some(l) = classify(d, label.to_string(), 0).filter(|l| valid(l, ver)) {
                    return Some(l);
                }
            }
        }
    }
    None
}

/// A candidate layer is real if it's source, or marshal that parses as a
/// code object. Binary constants that merely start with the code-object type
/// byte are common, so marshal candidates are checked before being accepted.
fn valid(l: &Layer, ver: (u8, u8)) -> bool {
    match &l.data {
        LayerData::Source(_) => true,
        LayerData::Marshal(m) => parse_code(m, ver).is_ok(),
    }
}

/// Try to reach the next layer from a code object's constants.
fn next_from_code(c: &Code, ver: (u8, u8)) -> Option<Layer> {
    for code in walk(c) {
        for k in &code.consts {
            let cand = match k {
                Obj::Bytes(b) if b.len() >= 64 => classify(b.clone(), String::new(), 0)
                    .or_else(|| std::str::from_utf8(b).ok().and_then(b64).and_then(|d| classify(d, "base64".into(), 0))),
                Obj::Str(s) if s.len() >= 64 => b64(s).and_then(|d| classify(d, "base64".into(), 0)),
                _ => None,
            };
            if let Some(mut l) = cand.filter(|l| valid(l, ver)) {
                if l.how.is_empty() {
                    l.how = "embedded code object".into();
                }
                return Some(l);
            }
        }
    }
    None
}

pub struct Peeled {
    pub version: (u8, u8),
    pub outer: Code,
    pub layers: Vec<Layer>,
    /// The innermost code object reached (the outer one when nothing peeled).
    pub inner: Code,
    pub error: Option<String>,
}

/// Parse a .pyc and follow any obfuscation layers to the innermost code object.
pub fn peel(pyc: &[u8]) -> Result<Peeled, String> {
    let version = identify(pyc).ok_or("not a CPython 3.7–3.14 .pyc")?;
    let outer = parse_code(&pyc[HEADER_LEN..], version)?;
    let mut layers: Vec<Layer> = Vec::new();
    let mut inner = outer.clone();
    let mut error = None;
    let mut next = next_from_code(&outer, version);
    while let Some(l) = next.take() {
        if layers.len() >= MAX_LAYERS {
            error = Some(format!("stopped after {MAX_LAYERS} layers"));
            break;
        }
        next = match &l.data {
            LayerData::Source(s) => next_from_source(s, version),
            LayerData::Marshal(m) => match parse_code(m, version) {
                Ok(c) => {
                    let n = next_from_code(&c, version);
                    inner = c;
                    n
                }
                Err(e) => {
                    error = Some(format!("layer {}: {}", layers.len() + 2, e));
                    None
                }
            },
        };
        layers.push(l);
    }
    Ok(Peeled { version, outer, layers, inner, error })
}

/// The strings report written for mStrings: function names, names, and
/// string constants from the innermost code object, then the outer stub.
pub fn strings_report(p: &Peeled, source_name: &str) -> String {
    let mut out = format!(
        "# Python {}.{} bytecode strings from {} — extracted statically by MalChela unpack (never executed)\n",
        p.version.0, p.version.1, source_name
    );
    if !p.layers.is_empty() {
        out.push_str(&format!("# Obfuscation layers peeled: {}\n", p.layers.iter().map(|l| l.how.as_str()).collect::<Vec<_>>().join(" -> ")));
    }
    out.push('\n');
    let mut codes: Vec<(&str, &Code)> = vec![("innermost code object", &p.inner)];
    if !p.layers.is_empty() {
        codes.push(("outer stub", &p.outer));
    }
    for (label, c) in codes {
        let s = strings(c);
        out.push_str(&format!("## {} — {} function(s)\n", label, s.functions.len()));
        for f in &s.functions {
            out.push_str(f);
            out.push('\n');
        }
        out.push_str("\n## names\n");
        for n in &s.names {
            out.push_str(n);
            out.push('\n');
        }
        out.push_str("\n## string constants\n");
        for k in &s.constants {
            // One constant per line: embedded newlines become a literal \n.
            out.push_str(&k.replace('\r', "\\r").replace('\n', "\\n"));
            out.push('\n');
        }
        out.push('\n');
        for (i, list) in s.lists.iter().enumerate() {
            out.push_str(&format!("## string list {} — {} item(s), in order\n", i + 1, list.len()));
            for k in list {
                out.push_str(&k.replace('\r', "\\r").replace('\n', "\\n"));
                out.push('\n');
            }
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(m: &mut Vec<u8>, b: &[u8]) {
        m.push(b's');
        m.extend_from_slice(&(b.len() as i32).to_le_bytes());
        m.extend_from_slice(b);
    }
    fn push_str(m: &mut Vec<u8>, t: &str) {
        m.push(b'z');
        m.push(t.len() as u8);
        m.extend_from_slice(t.as_bytes());
    }

    /// Hand-built marshal for a 3.11 module code object.  `consts` is the
    /// already-encoded consts tuple.
    fn code_311(consts: &[u8], names: &[&str]) -> Vec<u8> {
        let mut m = vec![b'c'];
        for _ in 0..5 {
            m.extend_from_slice(&0i32.to_le_bytes());
        }
        push_bytes(&mut m, b"\x97\x00");
        m.extend_from_slice(consts);
        m.push(b')');
        m.push(names.len() as u8);
        for n in names {
            push_str(&mut m, n);
        }
        m.extend_from_slice(b")\x00");
        push_bytes(&mut m, b"");
        push_str(&mut m, "x.py");
        push_str(&mut m, "<module>");
        push_str(&mut m, "<module>");
        m.extend_from_slice(&1i32.to_le_bytes());
        push_bytes(&mut m, b"");
        push_bytes(&mut m, b"");
        m
    }
    fn consts_of(items: &[&str]) -> Vec<u8> {
        let mut c = vec![b')', items.len() as u8];
        for s in items {
            push_str(&mut c, s);
        }
        c
    }
    fn pyc(body: &[u8]) -> Vec<u8> {
        let mut p = 3495u16.to_le_bytes().to_vec(); // 3.11
        p.extend_from_slice(b"\r\n");
        p.resize(HEADER_LEN, 0);
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn parses_strings_and_names() {
        let p = pyc(&code_311(&consts_of(&["https://x.test/api"]), &["requests", "post"]));
        assert_eq!(identify(&p), Some((3, 11)));
        let r = peel(&p).unwrap();
        let s = strings(&r.inner);
        assert!(s.constants.contains("https://x.test/api"));
        assert!(s.names.contains("requests"));
        assert!(r.layers.is_empty());
    }

    #[test]
    fn peels_zlib_marshal_layer() {
        let inner = code_311(&consts_of(&["secret_webhook_url"]), &["exec"]);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, &inner).unwrap();
        let blob = z.finish().unwrap();
        let mut oc = vec![b')', 1];
        push_bytes(&mut oc, &blob);
        let p = pyc(&code_311(&oc, &["zlib", "marshal", "exec"]));
        let r = peel(&p).unwrap();
        assert_eq!(r.layers.len(), 1, "{:?}", r.layers.iter().map(|l| &l.how).collect::<Vec<_>>());
        assert!(strings(&r.inner).constants.contains("secret_webhook_url"));
        assert!(strings_report(&r, "t.pyc").contains("secret_webhook_url"));
    }

    #[test]
    fn peels_blankobf_source_layer() {
        // Inner code with enough constant data that each quarter of its
        // base64 is a >= 64-char literal.
        let inner = code_311(&consts_of(&["hidden_marker", &"A".repeat(200)]), &[]);
        let payload = base64::engine::general_purpose::STANDARD.encode(&inner);
        let n = payload.len() / 4;
        let (a, b, c, d) = (&payload[..n], &payload[n..2 * n], &payload[2 * n..3 * n], &payload[3 * n..]);
        let src = format!(
            "____=\"{}\";______=\"{}\";_______=\"{}\";_____=\"{}\";__import__('builtins').exec(__import__('marshal').loads(__import__('base64').b64decode(__import__('codecs').decode(____, 'rot13')+_____+______[::-1]+_______)))",
            rot13(a),
            c.chars().rev().collect::<String>(),
            d,
            b
        );
        let l = next_from_source(&src, (3, 11)).expect("layer from source");
        match l.data {
            LayerData::Marshal(m) => assert!(strings(&parse_code(&m, (3, 11)).unwrap()).constants.contains("hidden_marker")),
            _ => panic!("expected marshal, got source"),
        }
        assert!(l.how.contains("rot13") && l.how.contains("reversed"), "{}", l.how);
    }

    #[test]
    fn stray_c_prefixed_constant_is_not_a_layer() {
        let mut junk = vec![b'c'];
        junk.extend_from_slice(&[0x41; 200]);
        let mut oc = vec![b')', 2];
        push_bytes(&mut oc, &junk);
        push_str(&mut oc, "real_string");
        let r = peel(&pyc(&code_311(&oc, &[]))).unwrap();
        assert!(r.layers.is_empty() && r.error.is_none());
        assert!(strings(&r.inner).constants.contains("real_string"));
    }

    #[test]
    fn rejects_garbage_cleanly() {
        assert!(identify(b"not a pyc at all, just text").is_none());
        let mut p = pyc(b"c");
        p.extend_from_slice(&[0xff; 40]);
        assert!(peel(&p).is_err());
    }

    #[test]
    fn version_table() {
        assert_eq!(version_for_magic(3413), Some((3, 8)));
        assert_eq!(version_for_magic(3439), Some((3, 10)));
        assert_eq!(version_for_magic(3495), Some((3, 11)));
        assert_eq!(version_for_magic(3531), Some((3, 12)));
        assert_eq!(version_for_magic(3571), Some((3, 13)));
        assert_eq!(version_for_magic(3627), Some((3, 14)));
        assert_eq!(version_for_magic(62211), None); // Python 2.7
    }

    #[test]
    fn slice_constant_3_14() {
        // consts = (slice(None, 2, None), "after_slice")
        let mut c = vec![b')', 2, b':', b'N', b'i'];
        c.extend_from_slice(&2i32.to_le_bytes());
        c.push(b'N');
        push_str(&mut c, "after_slice");
        let mut p = 3627u16.to_le_bytes().to_vec();
        p.extend_from_slice(b"\r\n");
        p.resize(HEADER_LEN, 0);
        p.extend_from_slice(&code_311(&c, &[]));
        let r = peel(&p).unwrap();
        assert_eq!(r.version, (3, 14));
        assert!(strings(&r.inner).constants.contains("after_slice"));
    }
}
