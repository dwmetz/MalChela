//! Native PyInstaller CArchive extraction (same format pyinstxtractor reads).
//!
//! Layout: the archive sits at the end of the bootloader executable and ends
//! with a cookie: magic "MEI\x0c\x0b\x0a\x0b\x0e", archive length, TOC
//! offset, TOC length, Python version, and (PyInstaller >= 2.1) a 64-byte
//! Python library name. All cookie/TOC integers are big-endian.
//!
//! Entry scripts (typecode 's') are stored as bare marshalled code objects;
//! we prepend a .pyc header using the magic from the embedded PYZ archive
//! (or a version table fallback) so decompilers and mStrings can use them.

use crate::util::{safe_join, Budget};
use flate2::read::ZlibDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct Entry {
    pub name: String,
    pub typecode: char,
    pub path: PathBuf,
    pub primary: bool,
}

pub struct Extracted {
    pub pyver: u32,
    pub entries: Vec<Entry>,
    pub skipped: Vec<String>,
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// PyInstaller bootstrap / runtime-hook scripts present in every build —
/// not the author's code.
fn is_bootstrap(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("pyiboot")
        || n.starts_with("pyi_rth_")
        || n.starts_with("pyimod")
        || n == "struct"
        || n.starts_with("_pyi_rth")
}

fn magic_for(pyver: u32) -> Option<[u8; 4]> {
    // Normalise 38 / 310 (newer) and 27 (older) encodings to (major, minor).
    let (maj, min) = if pyver >= 100 { (pyver / 100, pyver % 100) } else { (pyver / 10, pyver % 10) };
    let m: u16 = match (maj, min) {
        (3, 7) => 3394,
        (3, 8) => 3413,
        (3, 9) => 3425,
        (3, 10) => 3439,
        (3, 11) => 3495,
        (3, 12) => 3531,
        (3, 13) => 3571,
        (3, 14) => 3627,
        _ => return None,
    };
    let le = m.to_le_bytes();
    Some([le[0], le[1], 0x0d, 0x0a])
}

pub fn extract(b: &[u8], cookie_off: usize, out_dir: &Path, budget: &mut Budget) -> Result<Extracted, String> {
    let pkg_len = be32(b, cookie_off + 8).ok_or("truncated cookie")? as usize;
    let toc_off = be32(b, cookie_off + 12).ok_or("truncated cookie")? as usize;
    let toc_len = be32(b, cookie_off + 16).ok_or("truncated cookie")? as usize;
    let pyver = be32(b, cookie_off + 20).ok_or("truncated cookie")?;

    // 2.1+ cookies are 88 bytes (with the 64-byte libpython name).
    let tail = b.get(cookie_off + 24..(cookie_off + 88).min(b.len())).unwrap_or(&[]);
    let new_style = tail.len() == 64 && tail.windows(6).any(|w| w.eq_ignore_ascii_case(b"python"));
    let cookie_size = if new_style { 88 } else { 24 };
    let end = cookie_off + cookie_size;
    if pkg_len > end {
        return Err(format!("archive length {} exceeds cookie end {:#x}", pkg_len, end));
    }
    let pkg_start = end - pkg_len;
    let toc_start = pkg_start + toc_off;
    let toc = b.get(toc_start..toc_start + toc_len).ok_or("TOC out of bounds")?;

    // First pass: parse TOC.
    struct Raw {
        pos: usize,
        csize: usize,
        usize_: usize,
        compressed: bool,
        tc: char,
        name: String,
    }
    let mut raws = Vec::new();
    let mut p = 0usize;
    while p + 18 <= toc.len() {
        let esize = be32(toc, p).unwrap_or(0) as usize;
        if esize < 18 || p + esize > toc.len() {
            break;
        }
        let pos = be32(toc, p + 4).unwrap() as usize;
        let csize = be32(toc, p + 8).unwrap() as usize;
        let usz = be32(toc, p + 12).unwrap() as usize;
        let compressed = toc[p + 16] == 1;
        let tc = toc[p + 17] as char;
        let raw_name = &toc[p + 18..p + esize];
        let n = raw_name.iter().position(|&c| c == 0).unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..n]).to_string();
        raws.push(Raw { pos, csize, usize_: usz, compressed, tc, name });
        p += esize;
        if raws.len() > 20_000 {
            break;
        }
    }
    if raws.is_empty() {
        return Err("empty or unparseable TOC".into());
    }

    let read_entry = |r: &Raw, budget: &mut Budget| -> Result<Vec<u8>, String> {
        let s = pkg_start + r.pos;
        let data = b.get(s..s + r.csize).ok_or("entry out of bounds")?;
        if !r.compressed {
            return Ok(data.to_vec());
        }
        let cap = budget.remaining().min(r.usize_.max(1) as u64 + 1);
        let mut out = Vec::new();
        ZlibDecoder::new(data)
            .take(cap)
            .read_to_end(&mut out)
            .map_err(|e| format!("zlib: {}", e))?;
        Ok(out)
    };

    // PYZ carries the authoritative pyc magic.
    let mut magic = magic_for(pyver);
    if let Some(pyz) = raws.iter().find(|r| r.tc == 'z' || r.tc == 'Z') {
        if let Some(d) = b.get(pkg_start + pyz.pos..pkg_start + pyz.pos + 8) {
            if &d[..4] == b"PYZ\0" {
                magic = Some([d[4], d[5], d[6], d[7]]);
            }
        }
    }

    let (maj, min) = if pyver >= 100 { (pyver / 100, pyver % 100) } else { (pyver / 10, pyver % 10) };
    let header_len = if (maj, min) >= (3, 7) { 16 } else if (maj, min) >= (3, 3) { 12 } else { 8 };

    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    for r in &raws {
        if budget.exhausted() {
            skipped.push(format!("{} (output budget exhausted)", r.name));
            continue;
        }
        let mut data = match read_entry(r, budget) {
            Ok(d) => d,
            Err(e) => {
                skipped.push(format!("{} ({})", r.name, e));
                continue;
            }
        };
        let mut name = r.name.clone();
        let mut primary = false;
        match r.tc {
            's' => {
                if let Some(m) = magic {
                    let mut hdr = m.to_vec();
                    hdr.resize(header_len, 0);
                    hdr.extend_from_slice(&data);
                    data = hdr;
                }
                name.push_str(".pyc");
                primary = !is_bootstrap(&r.name);
            }
            'm' | 'M' => {
                // PyInstaller < 5.3 stored modules with their .pyc header;
                // >= 5.3 stores bare code objects like 's' entries.
                let has_header = data.len() >= 4 && &data[2..4] == b"\r\n";
                if !has_header {
                    if let Some(m) = magic {
                        let mut hdr = m.to_vec();
                        hdr.resize(header_len, 0);
                        hdr.extend_from_slice(&data);
                        data = hdr;
                    }
                }
                name.push_str(".pyc");
            }
            'z' | 'Z' => {
                if !name.ends_with(".pyz") {
                    name.push_str(".pyz");
                }
            }
            _ => {}
        }
        let Some(path) = safe_join(out_dir, &name) else {
            skipped.push(format!("{} (unsafe path)", r.name));
            continue;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, &data) {
            skipped.push(format!("{} ({})", r.name, e));
            continue;
        }
        budget.spend(data.len() as u64);
        entries.push(Entry { name, typecode: r.tc, path, primary });
    }
    Ok(Extracted { pyver, entries, skipped })
}
