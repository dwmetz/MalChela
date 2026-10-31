//! .NET ManifestResource extraction, including Costura.Fody payloads.
//!
//! Walks the CLI header -> metadata root -> `#~` table stream far enough to
//! locate the ManifestResource table (0x28). That requires the row size of
//! every table before it, which depends on heap-index widths and on the row
//! counts of every table a coded index can point at (ECMA-335 II.22-24).

use crate::binfmt::{pe_rva_to_off, BinInfo, Rd};
use crate::util::{safe_join, Budget};
use flate2::read::DeflateDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Idx(usize),
    Coded(&'static [usize], u32),
}

const NONE: usize = 0xff;
const TYPE_DEF_OR_REF: Col = Col::Coded(&[0x02, 0x01, 0x1b], 2);
const HAS_CONSTANT: Col = Col::Coded(&[0x04, 0x08, 0x17], 2);
const HAS_CUSTOM_ATTRIBUTE: Col = Col::Coded(
    &[0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
    5,
);
const HAS_FIELD_MARSHAL: Col = Col::Coded(&[0x04, 0x08], 1);
const HAS_DECL_SECURITY: Col = Col::Coded(&[0x02, 0x06, 0x20], 2);
const MEMBER_REF_PARENT: Col = Col::Coded(&[0x02, 0x01, 0x1a, 0x06, 0x1b], 3);
const HAS_SEMANTICS: Col = Col::Coded(&[0x14, 0x17], 1);
const METHOD_DEF_OR_REF: Col = Col::Coded(&[0x06, 0x0a], 1);
const MEMBER_FORWARDED: Col = Col::Coded(&[0x04, 0x06], 1);
const IMPLEMENTATION: Col = Col::Coded(&[0x26, 0x23, 0x27], 2);
const CUSTOM_ATTRIBUTE_TYPE: Col = Col::Coded(&[NONE, NONE, 0x06, 0x0a, NONE], 3);
const RESOLUTION_SCOPE: Col = Col::Coded(&[0x00, 0x1a, 0x23, 0x01], 2);

use Col::*;

/// Schemas for tables 0x00..=0x28.
fn schema(t: usize) -> &'static [Col] {
    match t {
        0x00 => &[U16, Str, Guid, Guid, Guid],
        0x01 => &[RESOLUTION_SCOPE, Str, Str],
        0x02 => &[U32, Str, Str, TYPE_DEF_OR_REF, Idx(0x04), Idx(0x06)],
        0x03 => &[Idx(0x04)],
        0x04 => &[U16, Str, Blob],
        0x05 => &[Idx(0x06)],
        0x06 => &[U32, U16, U16, Str, Blob, Idx(0x08)],
        0x07 => &[Idx(0x08)],
        0x08 => &[U16, U16, Str],
        0x09 => &[Idx(0x02), TYPE_DEF_OR_REF],
        0x0a => &[MEMBER_REF_PARENT, Str, Blob],
        0x0b => &[U16, HAS_CONSTANT, Blob],
        0x0c => &[HAS_CUSTOM_ATTRIBUTE, CUSTOM_ATTRIBUTE_TYPE, Blob],
        0x0d => &[HAS_FIELD_MARSHAL, Blob],
        0x0e => &[U16, HAS_DECL_SECURITY, Blob],
        0x0f => &[U16, U32, Idx(0x02)],
        0x10 => &[U32, Idx(0x04)],
        0x11 => &[Blob],
        0x12 => &[Idx(0x02), Idx(0x14)],
        0x13 => &[Idx(0x14)],
        0x14 => &[U16, Str, TYPE_DEF_OR_REF],
        0x15 => &[Idx(0x02), Idx(0x17)],
        0x16 => &[Idx(0x17)],
        0x17 => &[U16, Str, Blob],
        0x18 => &[U16, Idx(0x06), HAS_SEMANTICS],
        0x19 => &[Idx(0x02), METHOD_DEF_OR_REF, METHOD_DEF_OR_REF],
        0x1a => &[Str],
        0x1b => &[Blob],
        0x1c => &[U16, MEMBER_FORWARDED, Str, Idx(0x1a)],
        0x1d => &[U32, Idx(0x04)],
        0x1e => &[U32, U32],
        0x1f => &[U32],
        0x20 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        0x21 => &[U32],
        0x22 => &[U32, U32, U32],
        0x23 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        0x24 => &[U32, Idx(0x23)],
        0x25 => &[U32, U32, U32, Idx(0x23)],
        0x26 => &[U32, Str, Blob],
        0x27 => &[U32, U32, Str, Str, IMPLEMENTATION],
        0x28 => &[U32, U32, Str, IMPLEMENTATION],
        _ => &[],
    }
}

struct Sizes {
    str_: usize,
    guid: usize,
    blob: usize,
    rows: [u32; 64],
}

impl Sizes {
    fn col(&self, c: Col) -> usize {
        match c {
            U16 => 2,
            U32 => 4,
            Str => self.str_,
            Guid => self.guid,
            Blob => self.blob,
            Idx(t) => {
                if self.rows[t] < 0x1_0000 {
                    2
                } else {
                    4
                }
            }
            Coded(tables, bits) => {
                let max = tables.iter().filter(|&&t| t != NONE).map(|&t| self.rows[t]).max().unwrap_or(0);
                if max < (1u32 << (16 - bits)) {
                    2
                } else {
                    4
                }
            }
        }
    }
    fn row(&self, t: usize) -> usize {
        schema(t).iter().map(|&c| self.col(c)).sum()
    }
}

pub struct Resource {
    pub name: String,
    pub path: PathBuf,
    pub primary: bool,
    pub note: Option<String>,
}

pub struct Extracted {
    pub resources: Vec<Resource>,
    pub skipped: Vec<String>,
}

fn read_index(r: &Rd, off: u64, size: usize) -> Option<u32> {
    if size == 2 {
        r.u16(off).map(u32::from)
    } else {
        r.u32(off)
    }
}

pub fn extract(b: &[u8], info: &BinInfo, out_dir: &Path, budget: &mut Budget) -> Result<Extracted, String> {
    let pe = info.pe.as_ref().ok_or("not a PE")?;
    let r = Rd::new(b, true);
    let soh = pe.size_of_headers;
    let cli = pe_rva_to_off(&info.sections, soh, pe.clr_rva as u64).ok_or("CLI header RVA does not map")?;
    let md_rva = r.u32(cli + 8).ok_or("truncated CLI header")? as u64;
    let res_rva = r.u32(cli + 24).ok_or("truncated CLI header")? as u64;
    let res_size = r.u32(cli + 28).unwrap_or(0) as u64;
    let md = pe_rva_to_off(&info.sections, soh, md_rva).ok_or("metadata RVA does not map")?;
    if r.u32(md) != Some(0x424a_5342) {
        return Err("metadata signature BSJB not found".into());
    }
    let vlen = r.u32(md + 12).ok_or("truncated metadata root")? as u64;
    let nstreams = r.u16(md + 16 + vlen + 2).ok_or("truncated metadata root")? as u64;
    let mut sh = md + 16 + vlen + 4;
    let (mut tables, mut strings) = (None, None);
    for _ in 0..nstreams.min(16) {
        let off = r.u32(sh).ok_or("truncated stream header")? as u64;
        let size = r.u32(sh + 4).ok_or("truncated stream header")? as u64;
        let name = r.cstr(sh + 8, 32).unwrap_or_default();
        match name.as_str() {
            "#~" | "#-" => tables = Some((md + off, size)),
            "#Strings" => strings = Some((md + off, size)),
            _ => {}
        }
        sh += 8 + ((name.len() as u64 + 1 + 3) & !3);
    }
    let (t_off, _) = tables.ok_or("no #~ table stream")?;
    let (s_off, s_size) = strings.ok_or("no #Strings heap")?;

    let heap = r.u8(t_off + 6).ok_or("truncated #~")?;
    let valid = r.u64(t_off + 8).ok_or("truncated #~")?;
    let mut sizes = Sizes {
        str_: if heap & 1 != 0 { 4 } else { 2 },
        guid: if heap & 2 != 0 { 4 } else { 2 },
        blob: if heap & 4 != 0 { 4 } else { 2 },
        rows: [0; 64],
    };
    let mut p = t_off + 24;
    for t in 0..64 {
        if valid & (1u64 << t) != 0 {
            sizes.rows[t] = r.u32(p).ok_or("truncated row counts")?;
            p += 4;
        }
    }
    if heap & 0x40 != 0 {
        p += 4;
    }
    for t in 0..0x28 {
        p += sizes.rows[t] as u64 * sizes.row(t) as u64;
    }
    let nres = sizes.rows[0x28];
    if nres == 0 {
        return Ok(Extracted { resources: vec![], skipped: vec![] });
    }
    let res_base = pe_rva_to_off(&info.sections, soh, res_rva).ok_or("resources RVA does not map")?;

    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let mut out = Extracted { resources: vec![], skipped: vec![] };
    let row = sizes.row(0x28) as u64;
    let impl_size = sizes.col(IMPLEMENTATION);
    for i in 0..nres.min(4096) as u64 {
        let ro = p + i * row;
        let offset = r.u32(ro).ok_or("truncated ManifestResource row")? as u64;
        let name_idx = read_index(&r, ro + 8, sizes.str_).ok_or("truncated row")? as u64;
        let implementation = read_index(&r, ro + 8 + sizes.str_ as u64, impl_size).ok_or("truncated row")?;
        let name = if name_idx < s_size { r.cstr(s_off + name_idx, 512).unwrap_or_default() } else { format!("resource_{}", i) };
        if implementation != 0 {
            out.skipped.push(format!("{} (linked from another file/assembly, not embedded)", name));
            continue;
        }
        if res_size > 0 && offset >= res_size {
            out.skipped.push(format!("{} (offset outside resources directory)", name));
            continue;
        }
        let Some(len) = r.u32(res_base + offset) else {
            out.skipped.push(format!("{} (truncated)", name));
            continue;
        };
        let Some(data) = r.bytes(res_base + offset + 4, len as usize) else {
            out.skipped.push(format!("{} (length {} runs past end of file)", name, len));
            continue;
        };
        if budget.exhausted() {
            out.skipped.push(format!("{} (output budget exhausted)", name));
            continue;
        }

        let lower = name.to_ascii_lowercase();
        let (file_name, content, note) = if lower.starts_with("costura.") && lower.ends_with(".compressed") {
            let inner = &name["costura.".len()..name.len() - ".compressed".len()];
            let mut dec = Vec::new();
            match DeflateDecoder::new(data).take(budget.remaining()).read_to_end(&mut dec) {
                Ok(_) => (inner.to_string(), dec, Some("Costura: deflate-decompressed".to_string())),
                Err(e) => (name.clone(), data.to_vec(), Some(format!("Costura deflate failed: {}", e))),
            }
        } else if lower.starts_with("costura.") {
            (name["costura.".len()..].to_string(), data.to_vec(), Some("Costura (uncompressed)".to_string()))
        } else {
            (name.clone(), data.to_vec(), None)
        };

        let is_exec = crate::binfmt::identify(&content).is_executable();
        let Some(path) = safe_join(out_dir, &file_name) else {
            out.skipped.push(format!("{} (unsafe name)", name));
            continue;
        };
        let path = if path.exists() { crate::util::unique_path(out_dir, &file_name) } else { path };
        if let Err(e) = std::fs::write(&path, &content) {
            out.skipped.push(format!("{} ({})", name, e));
            continue;
        }
        budget.spend(content.len() as u64);
        out.resources.push(Resource { name: file_name, path, primary: is_exec, note });
    }
    Ok(out)
}
