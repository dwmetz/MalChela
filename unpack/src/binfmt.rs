//! Tolerant, hand-rolled header parsing for PE, ELF, and Mach-O.
//!
//! This deliberately does not use goblin's full parsers: packers and the
//! people who tamper with them routinely produce headers that a strict
//! parser rejects outright (zeroed section tables, import directories that
//! point nowhere, stripped ELF section headers). Every read here is bounds
//! checked and simply returns `None` on garbage, so a damaged file degrades
//! to "fewer facts" instead of "no analysis at all".

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pe,
    Elf,
    MachO,
    MachOFat,
    Unknown,
}

impl Format {
    pub fn is_executable(&self) -> bool {
        !matches!(self, Format::Unknown)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub offset: u64,
    pub raw_size: u64,
    pub vaddr: u64,
    pub vsize: u64,
    pub exec: bool,
    pub write: bool,
    pub entropy: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PeExtra {
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub size_of_headers: u64,
    pub import_dlls: Vec<String>,
    pub import_funcs: Vec<String>,
    pub cert_offset: u64,
    pub cert_size: u64,
    pub clr_rva: u32,
    pub clr_size: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ElfExtra {
    pub phoff: u64,
    pub phnum: u16,
    pub phentsize: u16,
    pub has_section_headers: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FatSlice {
    pub cputype: u32,
    pub arch: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinInfo {
    pub format: Format,
    pub bits: u8,
    pub little_endian: bool,
    pub arch: String,
    /// Sections when the format has them; for ELF without section headers,
    /// the PT_LOAD segments stand in (named LOAD0, LOAD1, ...).
    pub sections: Vec<Section>,
    /// Entry point as a file offset, when it can be mapped.
    pub entry_offset: Option<u64>,
    /// Index into `sections` that contains the entry point.
    pub entry_section: Option<usize>,
    /// File offset where data not covered by any header-described region begins.
    pub overlay_offset: Option<u64>,
    pub pe: Option<PeExtra>,
    pub elf: Option<ElfExtra>,
    pub fat_slices: Vec<FatSlice>,
}

impl BinInfo {
    fn empty(format: Format) -> Self {
        BinInfo {
            format,
            bits: 0,
            little_endian: true,
            arch: String::new(),
            sections: Vec::new(),
            entry_offset: None,
            entry_section: None,
            overlay_offset: None,
            pe: None,
            elf: None,
            fat_slices: Vec::new(),
        }
    }

    pub fn label(&self) -> String {
        let fmt = match self.format {
            Format::Pe => {
                let dotnet = self.pe.as_ref().map(|p| p.is_dotnet).unwrap_or(false);
                let kind = if self.pe.as_ref().map(|p| p.is_dll).unwrap_or(false) { " DLL" } else { "" };
                format!("PE{}{}{}", if self.bits == 64 { "32+" } else { "32" }, kind, if dotnet { " (.NET)" } else { "" })
            }
            Format::Elf => format!("ELF{}{}", self.bits, if self.little_endian { "" } else { " BE" }),
            Format::MachO => format!("Mach-O {}-bit", self.bits),
            Format::MachOFat => format!("Mach-O universal ({} slices)", self.fat_slices.len()),
            Format::Unknown => "Unknown".to_string(),
        };
        if self.arch.is_empty() {
            fmt
        } else {
            format!("{} ({})", fmt, self.arch)
        }
    }

    pub fn overlay_size(&self, file_len: u64) -> u64 {
        match self.overlay_offset {
            Some(o) if o < file_len => file_len - o,
            _ => 0,
        }
    }
}

// ── Byte reading ────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Rd<'a> {
    pub b: &'a [u8],
    pub le: bool,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8], le: bool) -> Self {
        Rd { b, le }
    }
    pub fn u8(&self, off: u64) -> Option<u8> {
        self.b.get(usize::try_from(off).ok()?).copied()
    }
    pub fn bytes(&self, off: u64, n: usize) -> Option<&'a [u8]> {
        let s = usize::try_from(off).ok()?;
        self.b.get(s..s.checked_add(n)?)
    }
    pub fn u16(&self, off: u64) -> Option<u16> {
        let a: [u8; 2] = self.bytes(off, 2)?.try_into().ok()?;
        Some(if self.le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) })
    }
    pub fn u32(&self, off: u64) -> Option<u32> {
        let a: [u8; 4] = self.bytes(off, 4)?.try_into().ok()?;
        Some(if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }
    pub fn u64(&self, off: u64) -> Option<u64> {
        let a: [u8; 8] = self.bytes(off, 8)?.try_into().ok()?;
        Some(if self.le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
    }
    pub fn cstr(&self, off: u64, max: usize) -> Option<String> {
        let s = usize::try_from(off).ok()?;
        let end = (s + max).min(self.b.len());
        let slice = self.b.get(s..end)?;
        let n = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        Some(String::from_utf8_lossy(&slice[..n]).to_string())
    }
}

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();
    // A single repeated byte gives -1·log2(1) = -0.0, which prints as "-0.00".
    if h > 0.0 { h } else { 0.0 }
}

fn slice_entropy(b: &[u8], off: u64, size: u64) -> f64 {
    let start = off.min(b.len() as u64) as usize;
    let end = off.saturating_add(size).min(b.len() as u64) as usize;
    entropy(&b[start..end])
}

// ── Identification ──────────────────────────────────────────────────────────

pub fn identify(b: &[u8]) -> Format {
    if b.len() >= 0x40 && &b[0..2] == b"MZ" {
        let r = Rd::new(b, true);
        if let Some(lfanew) = r.u32(0x3c) {
            if r.bytes(lfanew as u64, 4) == Some(b"PE\0\0") {
                return Format::Pe;
            }
        }
    }
    if b.len() >= 52 && &b[0..4] == b"\x7fELF" && matches!(b[4], 1 | 2) && matches!(b[5], 1 | 2) {
        return Format::Elf;
    }
    if b.len() >= 28 {
        let m = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if matches!(m, 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe) {
            return Format::MachO;
        }
        let mbe = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if mbe == 0xcafebabe || mbe == 0xcafebabf {
            // Java class files share 0xCAFEBABE. A fat header's nfat_arch is
            // tiny; a class file's minor/major version word is >= 45.
            let n = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
            if n > 0 && n <= 30 {
                return Format::MachOFat;
            }
        }
    }
    Format::Unknown
}

pub fn parse(b: &[u8]) -> BinInfo {
    match identify(b) {
        Format::Pe => parse_pe(b).unwrap_or_else(|| BinInfo::empty(Format::Pe)),
        Format::Elf => parse_elf(b).unwrap_or_else(|| BinInfo::empty(Format::Elf)),
        Format::MachO => parse_macho(b).unwrap_or_else(|| BinInfo::empty(Format::MachO)),
        Format::MachOFat => parse_fat(b).unwrap_or_else(|| BinInfo::empty(Format::MachOFat)),
        Format::Unknown => BinInfo::empty(Format::Unknown),
    }
}

// ── PE ──────────────────────────────────────────────────────────────────────

fn pe_machine(m: u16) -> &'static str {
    match m {
        0x14c => "x86",
        0x8664 => "x86_64",
        0x1c0 | 0x1c4 => "ARM",
        0xaa64 => "ARM64",
        0x200 => "IA64",
        _ => "",
    }
}

pub fn pe_rva_to_off(sections: &[Section], size_of_headers: u64, rva: u64) -> Option<u64> {
    if rva < size_of_headers {
        return Some(rva);
    }
    for s in sections {
        let span = s.vsize.max(s.raw_size);
        if rva >= s.vaddr && rva < s.vaddr.saturating_add(span) {
            let delta = rva - s.vaddr;
            if delta < s.raw_size {
                return Some(s.offset.saturating_add(delta));
            }
            return None; // inside the uninitialized tail of the section
        }
    }
    None
}

fn parse_pe(b: &[u8]) -> Option<BinInfo> {
    let r = Rd::new(b, true);
    let pe_off = r.u32(0x3c)? as u64;
    let coff = pe_off + 4;
    let machine = r.u16(coff)?;
    let nsections = r.u16(coff + 2)? as u64;
    let size_opt = r.u16(coff + 16)? as u64;
    let characteristics = r.u16(coff + 18)?;
    let opt = coff + 20;
    let magic = r.u16(opt)?;
    let is64 = magic == 0x20b;
    let entry_rva = r.u32(opt + 16)? as u64;
    let size_of_headers = r.u32(opt + 60).unwrap_or(0) as u64;
    let (nrva_off, dirs_off) = if is64 { (opt + 108, opt + 112) } else { (opt + 92, opt + 96) };
    let ndirs = r.u32(nrva_off).unwrap_or(0).min(16) as u64;
    let dir = |i: u64| -> (u32, u32) {
        if i >= ndirs {
            return (0, 0);
        }
        (r.u32(dirs_off + i * 8).unwrap_or(0), r.u32(dirs_off + i * 8 + 4).unwrap_or(0))
    };

    let mut info = BinInfo::empty(Format::Pe);
    info.bits = if is64 { 64 } else { 32 };
    info.arch = pe_machine(machine).to_string();

    let sec_table = opt + size_opt;
    let mut max_end = size_of_headers;
    for i in 0..nsections.min(96) {
        let so = sec_table + i * 40;
        let Some(name_raw) = r.bytes(so, 8) else { break };
        let n = name_raw.iter().position(|&c| c == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..n]).to_string();
        let vsize = r.u32(so + 8).unwrap_or(0) as u64;
        let vaddr = r.u32(so + 12).unwrap_or(0) as u64;
        let raw_size = r.u32(so + 16).unwrap_or(0) as u64;
        let raw_ptr = r.u32(so + 20).unwrap_or(0) as u64;
        let ch = r.u32(so + 36).unwrap_or(0);
        if raw_size > 0 {
            max_end = max_end.max(raw_ptr.saturating_add(raw_size));
        }
        info.sections.push(Section {
            name,
            offset: raw_ptr,
            raw_size,
            vaddr,
            vsize,
            exec: ch & 0x2000_0000 != 0 || ch & 0x20 != 0,
            write: ch & 0x8000_0000 != 0,
            entropy: slice_entropy(b, raw_ptr, raw_size),
        });
    }

    info.entry_section = info
        .sections
        .iter()
        .position(|s| entry_rva >= s.vaddr && entry_rva < s.vaddr.saturating_add(s.vsize.max(s.raw_size)));
    info.entry_offset = pe_rva_to_off(&info.sections, size_of_headers, entry_rva);

    let (cert_off, cert_size) = dir(4); // security dir holds a FILE offset, not an RVA
    let (clr_rva, clr_size) = dir(14);
    let mut extra = PeExtra {
        is_dll: characteristics & 0x2000 != 0,
        is_dotnet: clr_rva != 0 && clr_size != 0,
        size_of_headers,
        cert_offset: cert_off as u64,
        cert_size: cert_size as u64,
        clr_rva,
        clr_size,
        ..Default::default()
    };

    // A COFF symbol table (mingw/GCC builds that weren't stripped) and its
    // string table follow the sections; they're part of the image.
    let sym_ptr = r.u32(coff + 8).unwrap_or(0) as u64;
    let nsyms = r.u32(coff + 12).unwrap_or(0) as u64;
    if sym_ptr >= max_end && sym_ptr < b.len() as u64 && nsyms > 0 && nsyms < 10_000_000 {
        let strtab = sym_ptr + nsyms * 18;
        let strsize = r.u32(strtab).unwrap_or(0) as u64;
        let end = strtab.saturating_add(strsize.max(4));
        if end <= b.len() as u64 {
            max_end = end;
        }
    }

    // Overlay: anything past the last section's raw data, ignoring an
    // Authenticode blob sitting at the very end (that's expected, not hidden).
    let len = b.len() as u64;
    let mut overlay_end = len;
    if cert_off as u64 >= max_end && (cert_off as u64).saturating_add(cert_size as u64) >= len.saturating_sub(8) {
        overlay_end = cert_off as u64;
    }
    if max_end > 0 && max_end < overlay_end {
        info.overlay_offset = Some(max_end);
    }

    parse_pe_imports(&r, &info.sections, size_of_headers, dir(1).0 as u64, is64, &mut extra);
    info.pe = Some(extra);
    Some(info)
}

fn parse_pe_imports(r: &Rd, sections: &[Section], soh: u64, import_rva: u64, is64: bool, extra: &mut PeExtra) {
    if import_rva == 0 {
        return;
    }
    let Some(mut desc) = pe_rva_to_off(sections, soh, import_rva) else { return };
    for _ in 0..256 {
        let oft = r.u32(desc).unwrap_or(0) as u64;
        let name_rva = r.u32(desc + 12).unwrap_or(0) as u64;
        let ft = r.u32(desc + 16).unwrap_or(0) as u64;
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        if let Some(no) = pe_rva_to_off(sections, soh, name_rva) {
            if let Some(n) = r.cstr(no, 256) {
                if !n.is_empty() {
                    extra.import_dlls.push(n);
                }
            }
        }
        let thunk_rva = if oft != 0 { oft } else { ft };
        if let Some(mut t) = pe_rva_to_off(sections, soh, thunk_rva) {
            for _ in 0..4096 {
                let (val, ordinal) = if is64 {
                    let v = r.u64(t).unwrap_or(0);
                    (v, v & (1 << 63) != 0)
                } else {
                    let v = r.u32(t).unwrap_or(0) as u64;
                    (v, v & (1 << 31) != 0)
                };
                if val == 0 {
                    break;
                }
                if !ordinal {
                    if let Some(hn) = pe_rva_to_off(sections, soh, val & 0x7fff_ffff) {
                        if let Some(n) = r.cstr(hn + 2, 256) {
                            if !n.is_empty() {
                                extra.import_funcs.push(n);
                            }
                        }
                    }
                } else {
                    extra.import_funcs.push(format!("#ord{}", val & 0xffff));
                }
                t += if is64 { 8 } else { 4 };
                if extra.import_funcs.len() >= 8192 {
                    return;
                }
            }
        }
        desc += 20;
    }
}

/// Size of a PE image as laid out on disk (headers + section raw data).
/// Used to carve an embedded PE out of a larger blob.
pub fn pe_disk_size(b: &[u8]) -> Option<u64> {
    let info = parse_pe(b)?;
    let soh = info.pe.as_ref().map(|p| p.size_of_headers).unwrap_or(0);
    let mut end = soh;
    for s in &info.sections {
        if s.raw_size > 0 {
            end = end.max(s.offset.saturating_add(s.raw_size));
        }
    }
    if end == 0 {
        None
    } else {
        Some(end)
    }
}

// ── ELF ─────────────────────────────────────────────────────────────────────

fn elf_machine(m: u16) -> &'static str {
    match m {
        2 => "SPARC",
        3 => "x86",
        4 => "m68k",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "S390",
        40 => "ARM",
        42 => "SuperH",
        43 => "SPARCv9",
        62 => "x86_64",
        183 => "AArch64",
        243 => "RISC-V",
        258 => "LoongArch",
        _ => "",
    }
}

fn parse_elf(b: &[u8]) -> Option<BinInfo> {
    let is64 = b[4] == 2;
    let le = b[5] == 1;
    let r = Rd::new(b, le);
    let machine = r.u16(18)?;
    let (entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if is64 {
        (r.u64(24)?, r.u64(32)?, r.u64(40)?, r.u16(54)?, r.u16(56)?, r.u16(58)?, r.u16(60)?, r.u16(62)?)
    } else {
        (
            r.u32(24)? as u64,
            r.u32(28)? as u64,
            r.u32(32)? as u64,
            r.u16(42)?,
            r.u16(44)?,
            r.u16(46)?,
            r.u16(48)?,
            r.u16(50)?,
        )
    };

    let mut info = BinInfo::empty(Format::Elf);
    info.bits = if is64 { 64 } else { 32 };
    info.little_endian = le;
    info.arch = elf_machine(machine).to_string();

    let hdr_size: u64 = if is64 { 64 } else { 52 };
    let mut max_end = hdr_size.max(phoff.saturating_add(phnum as u64 * phentsize as u64));

    // PT_LOAD segments
    let mut segments = Vec::new();
    for i in 0..phnum.min(256) as u64 {
        let p = phoff.saturating_add(i * phentsize as u64);
        let (ptype, flags, off, vaddr, filesz, memsz) = if is64 {
            (r.u32(p), r.u32(p + 4), r.u64(p + 8), r.u64(p + 16), r.u64(p + 32), r.u64(p + 40))
        } else {
            (r.u32(p), r.u32(p + 24), r.u32(p + 4).map(u64::from), r.u32(p + 8).map(u64::from), r.u32(p + 16).map(u64::from), r.u32(p + 20).map(u64::from))
        };
        let (Some(ptype), Some(flags), Some(off), Some(vaddr), Some(filesz), Some(memsz)) = (ptype, flags, off, vaddr, filesz, memsz) else { break };
        if filesz > 0 && off <= b.len() as u64 {
            max_end = max_end.max(off.saturating_add(filesz));
        }
        if ptype == 1 {
            segments.push(Section {
                name: format!("LOAD{}", segments.len()),
                offset: off,
                raw_size: filesz,
                vaddr,
                vsize: memsz,
                exec: flags & 1 != 0,
                write: flags & 2 != 0,
                entropy: slice_entropy(b, off, filesz),
            });
        }
    }

    // Section headers (optional — UPX and many droppers strip them)
    let mut sections = Vec::new();
    let has_sh = shoff != 0 && shnum != 0 && shoff < b.len() as u64;
    if has_sh {
        max_end = max_end.max(shoff.saturating_add(shnum as u64 * shentsize as u64));
        let read_sh = |i: u64| -> Option<(u32, u32, u64, u64, u64, u64)> {
            let s = shoff.saturating_add(i * shentsize as u64);
            if is64 {
                Some((r.u32(s)?, r.u32(s + 4)?, r.u64(s + 8)?, r.u64(s + 16)?, r.u64(s + 24)?, r.u64(s + 32)?))
            } else {
                Some((r.u32(s)?, r.u32(s + 4)?, r.u32(s + 8)? as u64, r.u32(s + 12)? as u64, r.u32(s + 16)? as u64, r.u32(s + 20)? as u64))
            }
        };
        let strtab_off = read_sh(shstrndx as u64).map(|s| s.4);
        for i in 0..shnum.min(512) as u64 {
            let Some((name_idx, stype, flags, addr, off, size)) = read_sh(i) else { break };
            if stype == 0 {
                continue;
            }
            let nobits = stype == 8;
            if !nobits && size > 0 && off <= b.len() as u64 {
                max_end = max_end.max(off.saturating_add(size));
            }
            let name = strtab_off.and_then(|t| r.cstr(t.saturating_add(name_idx as u64), 64)).unwrap_or_default();
            sections.push(Section {
                name,
                offset: off,
                raw_size: if nobits { 0 } else { size },
                vaddr: addr,
                vsize: size,
                exec: flags & 0x4 != 0,
                write: flags & 0x1 != 0,
                entropy: if nobits { 0.0 } else { slice_entropy(b, off, size) },
            });
        }
    }

    info.sections = if sections.iter().any(|s| s.raw_size > 0) { sections } else { segments.clone() };
    let in_seg = |s: &Section| entry >= s.vaddr && entry < s.vaddr.saturating_add(s.vsize.max(s.raw_size));
    info.entry_section = info.sections.iter().position(in_seg);
    info.entry_offset = segments.iter().find(|s| in_seg(s)).map(|s| s.offset.saturating_add(entry - s.vaddr));
    if max_end < b.len() as u64 {
        info.overlay_offset = Some(max_end);
    }
    info.elf = Some(ElfExtra {
        phoff,
        phnum,
        phentsize,
        has_section_headers: has_sh,
    });
    Some(info)
}

// ── Mach-O ──────────────────────────────────────────────────────────────────

pub fn macho_cpu(cputype: u32) -> &'static str {
    match cputype {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "ARM",
        0x0100_000c => "ARM64",
        0x0200_000c => "ARM64_32",
        18 => "PowerPC",
        0x0100_0012 => "PowerPC64",
        _ => "",
    }
}

fn parse_macho(b: &[u8]) -> Option<BinInfo> {
    let m = u32::from_le_bytes(b[0..4].try_into().ok()?);
    let (is64, le) = match m {
        0xfeedface => (false, true),
        0xfeedfacf => (true, true),
        0xcefaedfe => (false, false),
        0xcffaedfe => (true, false),
        _ => return None,
    };
    let r = Rd::new(b, le);
    let cputype = r.u32(4)?;
    let ncmds = r.u32(16)?.min(4096) as u64;
    let hdr: u64 = if is64 { 32 } else { 28 };

    let mut info = BinInfo::empty(Format::MachO);
    info.bits = if is64 { 64 } else { 32 };
    info.little_endian = le;
    info.arch = macho_cpu(cputype).to_string();

    let mut lc = hdr;
    let mut max_end = 0u64;
    let mut text_fileoff_vm: Option<(u64, u64)> = None;
    let mut entryoff: Option<u64> = None;
    for _ in 0..ncmds {
        let Some(cmd) = r.u32(lc) else { break };
        let Some(cmdsize) = r.u32(lc + 4) else { break };
        if cmdsize < 8 {
            break;
        }
        match cmd {
            0x1 | 0x19 => {
                let s64 = cmd == 0x19;
                let segname = r.cstr(lc + 8, 16).unwrap_or_default();
                let (vmaddr, vmsize, fileoff, filesize, initprot, nsects, sect_base, sect_size) = if s64 {
                    (r.u64(lc + 24)?, r.u64(lc + 32)?, r.u64(lc + 40)?, r.u64(lc + 48)?, r.u32(lc + 60)?, r.u32(lc + 64)?, lc + 72, 80u64)
                } else {
                    (r.u32(lc + 24)? as u64, r.u32(lc + 28)? as u64, r.u32(lc + 32)? as u64, r.u32(lc + 36)? as u64, r.u32(lc + 44)?, r.u32(lc + 48)?, lc + 56, 68u64)
                };
                if filesize > 0 {
                    max_end = max_end.max(fileoff.saturating_add(filesize));
                }
                if segname == "__TEXT" {
                    text_fileoff_vm = Some((fileoff, vmaddr));
                }
                let seg_exec = initprot & 4 != 0;
                let seg_write = initprot & 2 != 0;
                let mut any_sect = false;
                for i in 0..nsects.min(256) as u64 {
                    let so = sect_base + i * sect_size;
                    let sectname = r.cstr(so, 16).unwrap_or_default();
                    let (addr, size, offset, flags) = if s64 {
                        (r.u64(so + 32).unwrap_or(0), r.u64(so + 40).unwrap_or(0), r.u32(so + 48).unwrap_or(0) as u64, r.u32(so + 64).unwrap_or(0))
                    } else {
                        (r.u32(so + 32).unwrap_or(0) as u64, r.u32(so + 36).unwrap_or(0) as u64, r.u32(so + 40).unwrap_or(0) as u64, r.u32(so + 56).unwrap_or(0))
                    };
                    let zerofill = matches!(flags & 0xff, 0x1 | 0xc | 0x12);
                    any_sect = true;
                    info.sections.push(Section {
                        name: format!("{},{}", segname, sectname),
                        offset,
                        raw_size: if zerofill { 0 } else { size },
                        vaddr: addr,
                        vsize: size,
                        exec: seg_exec || flags & 0x8000_0400 != 0,
                        write: seg_write,
                        entropy: if zerofill { 0.0 } else { slice_entropy(b, offset, size) },
                    });
                }
                if !any_sect && filesize > 0 {
                    info.sections.push(Section {
                        name: segname,
                        offset: fileoff,
                        raw_size: filesize,
                        vaddr: vmaddr,
                        vsize: vmsize,
                        exec: seg_exec,
                        write: seg_write,
                        entropy: slice_entropy(b, fileoff, filesize),
                    });
                }
            }
            0x8000_0028 => {
                entryoff = r.u64(lc + 8);
            }
            _ => {}
        }
        lc = lc.saturating_add(cmdsize as u64);
    }
    if let Some(eo) = entryoff {
        info.entry_offset = Some(eo);
        info.entry_section = info.sections.iter().position(|s| eo >= s.offset && eo < s.offset.saturating_add(s.raw_size));
    } else if let Some((_fo, _vm)) = text_fileoff_vm {
        // LC_UNIXTHREAD entry (older binaries, UPX output) is arch-specific
        // register state; not worth decoding for a heuristic.
    }
    if max_end > 0 && max_end < b.len() as u64 {
        info.overlay_offset = Some(max_end);
    }
    Some(info)
}

/// On-disk size of a thin Mach-O (max segment fileoff+filesize), for carving.
pub fn macho_disk_size(b: &[u8]) -> Option<u64> {
    let info = parse_macho(b)?;
    let end = info.sections.iter().map(|s| s.offset.saturating_add(s.raw_size)).max()?;
    let end = info.overlay_offset.unwrap_or(end).max(end);
    Some(end.min(b.len() as u64))
}

fn parse_fat(b: &[u8]) -> Option<BinInfo> {
    let r = Rd::new(b, false);
    let magic = r.u32(0)?;
    let fat64 = magic == 0xcafebabf;
    let n = r.u32(4)?.min(30) as u64;
    let mut info = BinInfo::empty(Format::MachOFat);
    let mut max_end = 8 + n * if fat64 { 32 } else { 20 };
    for i in 0..n {
        let (cputype, offset, size) = if fat64 {
            let o = 8 + i * 32;
            (r.u32(o)?, r.u64(o + 8)?, r.u64(o + 16)?)
        } else {
            let o = 8 + i * 20;
            (r.u32(o)?, r.u32(o + 8)? as u64, r.u32(o + 12)? as u64)
        };
        max_end = max_end.max(offset.saturating_add(size));
        let arch = macho_cpu(cputype);
        info.fat_slices.push(FatSlice {
            cputype,
            arch: if arch.is_empty() { format!("cpu_{:#x}", cputype) } else { arch.to_string() },
            offset,
            size,
        });
    }
    info.arch = info.fat_slices.iter().map(|s| s.arch.clone()).collect::<Vec<_>>().join(", ");
    if max_end < b.len() as u64 {
        info.overlay_offset = Some(max_end);
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[0u8; 100]), 0.0);
        assert!(entropy(&[7u8; 12]).is_sign_positive(), "no negative zero");
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn java_class_is_not_fat_macho() {
        let mut b = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34];
        b.resize(64, 0);
        assert_eq!(identify(&b), Format::Unknown);
    }

    #[test]
    fn garbage_does_not_panic() {
        for len in [0usize, 1, 2, 63, 64, 200] {
            let mut b = vec![0xffu8; len];
            if len >= 2 {
                b[0] = b'M';
                b[1] = b'Z';
            }
            let _ = parse(&b);
        }
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        let _ = parse(&elf);
    }
}
