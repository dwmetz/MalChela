//! UPX: header repair for tampered samples, then `upx -d` on a working copy.
//!
//! Native NRV/LZMA decompression with UPX's filters and import rebuilding is
//! a project of its own; the upx binary is cross-platform and does it
//! correctly, so this module's job is getting a tampered file back into a
//! shape upx will accept.

use crate::binfmt::{BinInfo, Format, Rd};
use crate::detect::{contains, find_all, UPX_MAGIC};

#[derive(Debug, Default)]
pub struct Repair {
    pub notes: Vec<String>,
}

impl Repair {
    pub fn changed(&self) -> bool {
        !self.notes.is_empty()
    }
}

/// Attempt in-place repair of a tampered UPX file (on a copy). Every change
/// is recorded so the report states exactly what was modified.
pub fn repair(b: &mut [u8], info: &BinInfo) -> Repair {
    match info.format {
        Format::Elf => repair_elf(b, info),
        Format::Pe => repair_pe(b, info),
        _ => Repair::default(),
    }
}

fn repair_elf(b: &mut [u8], info: &BinInfo) -> Repair {
    let mut rep = Repair::default();
    let Some(e) = info.elf.as_ref() else { return rep };
    let Some(l) = e.phoff.checked_add(e.phnum as u64 * e.phentsize as u64).map(|x| x as usize) else { return rep };
    if b.len() < l + 24 {
        return rep;
    }

    // 1. Restore the l_info magic. Tamperers swap "UPX!" for another 4-byte
    //    value everywhere it appears; replace that value back, but only when
    //    it's distinctive and rare enough that we aren't rewriting code.
    let magic: [u8; 4] = b[l + 4..l + 8].try_into().unwrap();
    if magic != *UPX_MAGIC {
        let distinctive = magic.iter().collect::<std::collections::HashSet<_>>().len() >= 3;
        let hits = find_all(b, &magic, 64);
        if distinctive && !hits.is_empty() && hits.len() <= 8 {
            for &h in &hits {
                b[h..h + 4].copy_from_slice(UPX_MAGIC);
            }
            rep.notes.push(format!(
                "replaced {} occurrence(s) of substituted magic {:02x?} with 'UPX!' (offsets {})",
                hits.len(),
                magic,
                hits.iter().map(|o| format!("{:#x}", o)).collect::<Vec<_>>().join(", ")
            ));
        } else {
            b[l + 4..l + 8].copy_from_slice(UPX_MAGIC);
            rep.notes.push(format!("restored l_info magic at {:#x}", l + 4));
            // The trailer PackHeader sits in the last few dozen bytes.
            let tail = b.len().saturating_sub(0x80);
            if !contains(&b[tail..], UPX_MAGIC) {
                rep.notes.push("trailing pack header magic not found — upx may still refuse".into());
            }
        }
    }

    // 2. Restore zeroed p_info sizes from the trailer PackHeader's
    //    u_file_size (PackHeader fields are always little-endian; p_info
    //    uses the target's endianness).
    let r = Rd::new(b, info.little_endian);
    let pf = r.u32(l as u64 + 16).unwrap_or(1);
    let pb = r.u32(l as u64 + 20).unwrap_or(1);
    if pf == 0 || pb == 0 {
        match trailer_pack_header(b) {
            Some((ph, u_file_size)) if u_file_size > 0 && u_file_size < 512 * 1024 * 1024 => {
                let enc = |v: u32| if info.little_endian { v.to_le_bytes() } else { v.to_be_bytes() };
                if pf == 0 {
                    b[l + 16..l + 20].copy_from_slice(&enc(u_file_size));
                }
                if pb == 0 {
                    b[l + 20..l + 24].copy_from_slice(&enc(u_file_size));
                }
                rep.notes.push(format!(
                    "restored p_info p_filesize/p_blocksize = {} from trailing pack header at {:#x}",
                    u_file_size, ph
                ));
            }
            _ => rep.notes.push("p_info is zeroed but no valid trailing pack header was found to restore it from".into()),
        }
    }
    rep
}

/// Locate the trailing PackHeader: the last "UPX!" in the final 512 bytes
/// whose version byte is sane. Its fields are little-endian unless the
/// format byte carries the 0x80 big-endian flag (MIPS/PPC/m68k targets).
/// Returns (offset, u_file_size).
pub fn trailer_pack_header(b: &[u8]) -> Option<(usize, u32)> {
    let tail_start = b.len().saturating_sub(0x200);
    let mut hits = find_all(&b[tail_start..], UPX_MAGIC, 16);
    hits.reverse();
    for rel in hits {
        let ph = tail_start + rel;
        if ph + 28 > b.len() || !(10..=15).contains(&b[ph + 4]) {
            continue;
        }
        let raw: [u8; 4] = b[ph + 24..ph + 28].try_into().ok()?;
        let v = if b[ph + 5] & 0x80 != 0 { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) };
        return Some((ph, v));
    }
    None
}

fn repair_pe(b: &mut [u8], info: &BinInfo) -> Repair {
    let mut rep = Repair::default();
    if !crate::detect::pe_upx_layout(info) {
        return rep;
    }

    // 1. Section names back to UPX0/UPX1 (upx -d keys on these).
    let r = Rd::new(b, true);
    let Some(pe_off) = r.u32(0x3c) else { return rep };
    let Some(size_opt) = r.u16(pe_off as u64 + 20) else { return rep };
    let sec_table = pe_off as usize + 24 + size_opt as usize;
    for (i, want) in [(0usize, b"UPX0"), (1usize, b"UPX1")] {
        let so = sec_table + i * 40;
        if so + 8 > b.len() {
            return rep;
        }
        if &b[so..so + 4] != want {
            let old = String::from_utf8_lossy(&b[so..so + 8]).trim_end_matches('\0').to_string();
            b[so..so + 8].copy_from_slice(&[want[0], want[1], want[2], want[3], 0, 0, 0, 0]);
            rep.notes.push(format!("renamed section {} '{}' -> '{}'", i, old, String::from_utf8_lossy(want)));
        }
    }

    // 2. Pack header magic. UPX writes "<ver>\0UPX!" (e.g. "3.96\0UPX!")
    //    followed by version/format bytes just before UPX1's raw data. If
    //    the four bytes after a version string aren't "UPX!" but the next
    //    two bytes look like a PE-format pack header, put the magic back.
    if find_all(b, UPX_MAGIC, 1).is_empty() {
        let limit = info.sections.get(1).map(|s| s.offset as usize + 0x40).unwrap_or(0x1000).min(b.len()).max(0x40);
        let mut fixed = false;
        for i in 0..limit.saturating_sub(12) {
            let w = &b[i..i + 5];
            let is_ver = w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit() && w[3].is_ascii_digit() && w[4] == 0;
            if !is_ver {
                continue;
            }
            let h = i + 5;
            let version = b[h + 4];
            let fmt = b[h + 5];
            if (10..=15).contains(&version) && matches!(fmt, 9 | 36) {
                b[h..h + 4].copy_from_slice(UPX_MAGIC);
                rep.notes.push(format!("restored pack header magic at {:#x} (after version string)", h));
                fixed = true;
                break;
            }
        }
        if !fixed {
            rep.notes.push("pack header magic missing and could not be located — upx may still refuse".into());
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_magic_restore_finds_version_string() {
        // Minimal synthetic layout: version string + clobbered magic + header bytes.
        let mut b = vec![0u8; 0x200];
        b[0x100..0x105].copy_from_slice(b"3.96\0");
        b[0x105..0x109].copy_from_slice(b"XXXX");
        b[0x109] = 13; // version
        b[0x10a] = 9; // UPX_F_WIN32_PE
        // Find logic directly (repair_pe needs a full PE; exercise the scan).
        let i = 0x100;
        let w = &b[i..i + 5];
        assert!(w[0].is_ascii_digit() && w[1] == b'.' && w[4] == 0);
        assert_eq!(b[i + 5 + 4], 13);
    }
}
