//! Packer / protector / installer detection.
//!
//! Every verdict carries the concrete evidence that produced it (section
//! names, magic offsets, structural anomalies) so an analyst can check the
//! call rather than trust it. Signatures are deliberately conservative:
//! only named packers with distinctive artifacts get a name; everything
//! else falls into a "generic packing indicators" verdict built from
//! entropy and import heuristics.

use crate::binfmt::{BinInfo, Format};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Compression packer with a known static unpacking path or signature.
    Packer,
    /// Commercial protector / virtualizer — needs emulation or execution.
    Protector,
    /// Script compiler / crypter wrapping another payload.
    Crypter,
    /// Installer wrapper (NSIS, Inno Setup).
    Installer,
    /// Language bundler (PyInstaller, Costura).
    Bundler,
    /// Multi-architecture container (fat Mach-O).
    Container,
    /// Data appended or embedded that looks like a second payload.
    Embedded,
    /// Heuristic only — no named packer.
    Heuristic,
    /// Informational (e.g. Go binary) — not packing.
    Info,
}

impl Kind {
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Packer => "Packer",
            Kind::Protector => "Protector",
            Kind::Crypter => "Crypter",
            Kind::Installer => "Installer",
            Kind::Bundler => "Bundler",
            Kind::Container => "Container",
            Kind::Embedded => "Embedded payload",
            Kind::Heuristic => "Heuristic",
            Kind::Info => "Info",
        }
    }
    /// Counts as "Software Packing" (T1027.002) for ATT&CK tagging.
    pub fn is_packing(&self) -> bool {
        matches!(self, Kind::Packer | Kind::Protector | Kind::Crypter | Kind::Heuristic)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Handler {
    Upx { tampered: bool },
    FatSplit,
    PyInstaller { cookie_offset: u64 },
    /// Python bytecode: string extraction and static obfuscator peeling.
    Pyc,
    Nsis,
    Inno,
    DotnetResources,
    Carve { offset: u64, size: u64, what: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub confidence: String,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handler: Option<Handler>,
    /// Shown when no static handler exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advice: Option<String>,
}

impl Verdict {
    fn new(id: &str, name: &str, kind: Kind, confidence: &str) -> Self {
        Verdict {
            id: id.into(),
            name: name.into(),
            kind,
            confidence: confidence.into(),
            evidence: Vec::new(),
            handler: None,
            advice: None,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

pub fn find_all(hay: &[u8], needle: &[u8], limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || hay.len() < needle.len() {
        return out;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        match hay[i..hay.len() - needle.len() + 1].iter().position(|&c| c == first) {
            None => break,
            Some(p) => {
                let at = i + p;
                if &hay[at..at + needle.len()] == needle {
                    out.push(at);
                    if out.len() >= limit {
                        break;
                    }
                }
                i = at + 1;
            }
        }
    }
    out
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !find_all(hay, needle, 1).is_empty()
}

pub fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).rev().find(|&i| &hay[i..i + needle.len()] == needle)
}

pub const UPX_MAGIC: &[u8] = b"UPX!";
const UPX_INFO: &[u8] = b"$Info: This file is packed with the UPX";
pub const PYI_COOKIE: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";

/// Named PE packers/protectors identified by section names.
/// (section name prefix, display name, kind)
const PE_SECTION_SIGS: &[(&str, &str, Kind)] = &[
    (".aspack", "ASPack", Kind::Packer),
    (".adata", "ASPack", Kind::Packer),
    (".MPRESS1", "MPRESS", Kind::Packer),
    (".MPRESS2", "MPRESS", Kind::Packer),
    (".petite", "Petite", Kind::Packer),
    ("pec1", "PECompact", Kind::Packer),
    ("pec2", "PECompact", Kind::Packer),
    ("PEC2", "PECompact", Kind::Packer),
    (".nsp0", "NsPack", Kind::Packer),
    (".nsp1", "NsPack", Kind::Packer),
    (".RLPack", "RLPack", Kind::Packer),
    (".packed", "RLPack", Kind::Packer),
    (".kkrunchy", "kkrunchy", Kind::Packer),
    (".yP", "Y0da Protector", Kind::Protector),
    (".y0da", "Y0da Protector", Kind::Protector),
    (".themida", "Themida", Kind::Protector),
    (".winlice", "WinLicense", Kind::Protector),
    (".vmp0", "VMProtect", Kind::Protector),
    (".vmp1", "VMProtect", Kind::Protector),
    (".vmp2", "VMProtect", Kind::Protector),
    (".enigma1", "Enigma Protector", Kind::Protector),
    (".enigma2", "Enigma Protector", Kind::Protector),
    (".perplex", "Perplex", Kind::Protector),
    (".spack", "Simple Pack", Kind::Packer),
    (".ccg", "CCG Packer", Kind::Packer),
];

/// .NET obfuscators / bundlers identified by marker strings.
const DOTNET_MARKERS: &[(&[u8], &str, Kind)] = &[
    (b"ConfusedByAttribute", "ConfuserEx", Kind::Protector),
    (b"ConfuserEx", "ConfuserEx", Kind::Protector),
    (b"SmartAssembly.Attributes", "SmartAssembly", Kind::Protector),
    (b"DotfuscatorAttribute", "Dotfuscator", Kind::Protector),
    (b"BabelAttribute", "Babel Obfuscator", Kind::Protector),
    (b"YanoAttribute", "Yano", Kind::Protector),
    (b"Xenocode.Client.Attributes", "Xenocode", Kind::Protector),
    (b"NETGuard", "NETGuard", Kind::Protector),
    (b"CryptoObfuscator", "Crypto Obfuscator", Kind::Protector),
];

const EMULATION_ADVICE: &str =
    "No static unpacking path — this needs emulation (unipacker/Speakeasy) or a sandbox/memory dump, which is outside unpack's static-only scope.";

fn section_names(info: &BinInfo) -> Vec<String> {
    info.sections.iter().map(|s| s.name.clone()).collect()
}

// ── Detection ───────────────────────────────────────────────────────────────

pub fn detect(b: &[u8], info: &BinInfo) -> Vec<Verdict> {
    let mut v = Vec::new();

    match info.format {
        Format::MachOFat => {
            let mut fat = Verdict::new("fat_macho", "Mach-O universal binary", Kind::Container, "high");
            for s in &info.fat_slices {
                fat.evidence.push(format!("slice {} at {:#x} ({} bytes)", s.arch, s.offset, s.size));
            }
            fat.handler = Some(Handler::FatSplit);
            v.push(fat);
            return v; // each slice is analysed on its own
        }
        Format::Unknown => {
            if let Some(p) = detect_pyc(b) {
                v.push(p);
                return v;
            }
            // A damaged bootloader header shouldn't hide a PyInstaller archive.
            if let Some(off) = rfind(b, PYI_COOKIE) {
                let mut p = Verdict::new("pyinstaller", "PyInstaller", Kind::Bundler, "medium");
                p.evidence.push(format!("CArchive cookie at {:#x} (host executable header not recognised)", off));
                p.handler = Some(Handler::PyInstaller { cookie_offset: off as u64 });
                v.push(p);
                return v;
            }
            detect_embedded(b, info, &mut v);
            return v;
        }
        _ => {}
    }

    let upx = detect_upx(b, info);
    let upx_found = upx.is_some();
    if let Some(u) = upx {
        v.push(u);
    }

    if info.format == Format::Pe {
        detect_pe_named(info, &mut v);
    }

    // UPX stores its compressed blocks past the loaded segments, and
    // installers / bundlers keep their archives in the overlay — either way
    // the overlay is theirs, so raw overlay carving is suppressed.
    let mut owns_overlay = upx_found;
    if let Some(off) = rfind(b, PYI_COOKIE) {
        let mut p = Verdict::new("pyinstaller", "PyInstaller", Kind::Bundler, "high");
        p.evidence.push(format!("CArchive cookie MEI\\x0c\\x0b\\x0a\\x0b\\x0e at {:#x}", off));
        p.handler = Some(Handler::PyInstaller { cookie_offset: off as u64 });
        v.push(p);
        owns_overlay = true;
    }
    if info.format == Format::Pe {
        if let Some(off) = find_all(b, b"NullsoftInst", 1).first() {
            let mut n = Verdict::new("nsis", "NSIS installer", Kind::Installer, "high");
            n.evidence.push(format!("NullsoftInst first-header signature at {:#x}", off));
            n.handler = Some(Handler::Nsis);
            v.push(n);
            owns_overlay = true;
        }
        if let Some(off) = find_all(b, b"Inno Setup Setup Data", 1).first() {
            let mut n = Verdict::new("inno", "Inno Setup installer", Kind::Installer, "high");
            n.evidence.push(format!("'Inno Setup Setup Data' at {:#x}", off));
            n.handler = Some(Handler::Inno);
            v.push(n);
            owns_overlay = true;
        }
        if info.pe.as_ref().map(|p| p.is_dotnet).unwrap_or(false) {
            detect_dotnet(b, &mut v);
        }
    }

    // shc-compiled shell scripts (ELF / Mach-O)
    if matches!(info.format, Format::Elf | Format::MachO) && contains(b, b"E: neither argv[0] nor $_ works.") {
        let mut s = Verdict::new("shc", "shc (compiled shell script)", Kind::Crypter, "high");
        s.evidence.push("shc runtime error string 'E: neither argv[0] nor $_ works.'".into());
        s.advice = Some(
            "The script is RC4-encrypted inside the binary with the key in .data; recovery needs the shc variable layout (e.g. UnSHc) — not yet automated here.".into(),
        );
        v.push(s);
    }

    if contains(b, b"\xff Go buildinf:") {
        let mut g = Verdict::new("go", "Go binary", Kind::Info, "high");
        g.evidence.push("Go build-info header present".into());
        g.advice = Some("Not packing, but Go strings extract poorly; GoReSym recovers symbols and metadata.".into());
        v.push(g);
    }

    // Native-code heuristics don't apply to managed assemblies (resources
    // live in .text), and are redundant once a bundler/installer explains
    // the entropy.
    let is_dotnet = info.pe.as_ref().map(|p| p.is_dotnet).unwrap_or(false);
    let explained = v.iter().any(|x| matches!(x.kind, Kind::Packer | Kind::Protector | Kind::Bundler | Kind::Installer));
    if !upx_found && !explained && !is_dotnet {
        if let Some(h) = detect_heuristic(b, info) {
            v.push(h);
        }
    }

    if !owns_overlay {
        detect_overlay(b, info, &mut v);
    }
    detect_embedded(b, info, &mut v);
    v
}

/// Convenience for other MalChela tools (fileanalyzer): the name of the most
/// significant packing-type verdict, if any.
pub fn packer_summary(b: &[u8]) -> Option<String> {
    let info = crate::binfmt::parse(b);
    let verdicts = detect(b, &info);
    let named: Vec<String> = verdicts
        .iter()
        .filter(|v| v.kind.is_packing() || matches!(v.kind, Kind::Installer | Kind::Bundler))
        .map(|v| v.name.clone())
        .collect();
    if named.is_empty() {
        None
    } else {
        Some(named.join(", "))
    }
}

fn detect_upx(b: &[u8], info: &BinInfo) -> Option<Verdict> {
    let magics = find_all(b, UPX_MAGIC, 16);
    let has_info = contains(b, UPX_INFO);
    let names = section_names(info);
    let upx_sections: Vec<&String> = names.iter().filter(|n| n.starts_with("UPX")).collect();

    let mut ev = Vec::new();
    if !upx_sections.is_empty() {
        ev.push(format!("section names: {}", upx_sections.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !magics.is_empty() {
        ev.push(format!(
            "'UPX!' magic at {}",
            magics.iter().take(4).map(|o| format!("{:#x}", o)).collect::<Vec<_>>().join(", ")
        ));
    }
    if has_info {
        ev.push("UPX $Info banner string".into());
    }

    let mut tampered_ev = Vec::new();
    match info.format {
        Format::Elf => {
            if let Some(t) = elf_upx_tamper(b, info) {
                tampered_ev.extend(t);
            }
        }
        Format::Pe => {
            if pe_upx_layout(info) {
                let renamed = !names.first().map(|n| n.starts_with("UPX")).unwrap_or(false)
                    || !names.get(1).map(|n| n.starts_with("UPX")).unwrap_or(false);
                if renamed {
                    tampered_ev.push(format!(
                        "UPX section layout (empty first section + high-entropy entry section) under renamed sections: {}",
                        names.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
                if magics.is_empty() {
                    tampered_ev.push("UPX section layout but no 'UPX!' pack header".into());
                }
            }
        }
        _ => {}
    }

    if ev.is_empty() && tampered_ev.is_empty() {
        return None;
    }
    // A lone "UPX!" four-byte hit in a big binary with nothing else is weak.
    let strong = !upx_sections.is_empty() || has_info || magics.len() >= 2 || !tampered_ev.is_empty();
    if !strong {
        return None;
    }
    let tampered = !tampered_ev.is_empty();
    let mut v = Verdict::new(
        "upx",
        if tampered { "UPX (tampered)" } else { "UPX" },
        Kind::Packer,
        if tampered && ev.is_empty() { "medium" } else { "high" },
    );
    v.evidence = ev;
    v.evidence.extend(tampered_ev);
    v.handler = Some(Handler::Upx { tampered });
    Some(v)
}

/// UPX ELF layout: l_info (12 bytes) then p_info (12 bytes) immediately after
/// the program headers. Tampering (Mirai and friends) overwrites the l_info
/// magic and/or zeroes p_filesize / p_blocksize so `upx -d` refuses the file.
pub fn elf_upx_tamper(b: &[u8], info: &BinInfo) -> Option<Vec<String>> {
    let e = info.elf.as_ref()?;
    let l = e.phoff.checked_add(e.phnum as u64 * e.phentsize as u64)? as usize;
    if b.len() < l + 24 {
        return None;
    }
    let magic = &b[l + 4..l + 8];
    let r = crate::binfmt::Rd::new(b, info.little_endian);
    let p_filesize = r.u32(l as u64 + 16)?;
    let p_blocksize = r.u32(l as u64 + 20)?;

    let tail_start = b.len().saturating_sub(0x400);
    let tail_has_upx = contains(&b[tail_start..], UPX_MAGIC);
    let tail_has_same = magic != UPX_MAGIC && magic.iter().any(|&c| c != 0) && contains(&b[tail_start..], magic);
    let few_loads = info.sections.iter().all(|s| s.name.starts_with("LOAD")) && info.sections.len() <= 4;

    let mut ev = Vec::new();
    if magic == UPX_MAGIC {
        if p_filesize == 0 || p_blocksize == 0 {
            ev.push(format!(
                "p_info zeroed (p_filesize={}, p_blocksize={}) — upx -d will refuse this file",
                p_filesize, p_blocksize
            ));
        }
    } else if tail_has_same && few_loads && !e.has_section_headers {
        ev.push(format!(
            "l_info magic replaced with {:02x?} (also present in the trailing pack header)",
            magic
        ));
        if p_filesize == 0 || p_blocksize == 0 {
            ev.push("p_info zeroed".into());
        }
    } else if tail_has_upx && few_loads && !e.has_section_headers && magic != UPX_MAGIC {
        ev.push(format!("l_info magic at {:#x} is {:02x?}, expected 'UPX!'", l + 4, magic));
    }
    if ev.is_empty() {
        None
    } else {
        Some(ev)
    }
}

/// UPX's PE layout: a first section with no raw data but a large virtual
/// size (the decompression target), followed by a high-entropy section that
/// holds the entry point.
pub fn pe_upx_layout(info: &BinInfo) -> bool {
    if info.sections.len() < 2 {
        return false;
    }
    let s0 = &info.sections[0];
    let s1 = &info.sections[1];
    s0.raw_size == 0 && s0.vsize > 0x1000 && s1.raw_size > 0 && s1.entropy > 7.0 && info.entry_section == Some(1)
}

fn detect_pe_named(info: &BinInfo, v: &mut Vec<Verdict>) {
    let names = section_names(info);
    let mut seen = std::collections::BTreeMap::<&str, (Kind, Vec<String>)>::new();
    for n in &names {
        for (prefix, name, kind) in PE_SECTION_SIGS {
            if n == prefix || (prefix.len() >= 4 && n.starts_with(prefix)) {
                seen.entry(name).or_insert((*kind, Vec::new())).1.push(n.clone());
            }
        }
    }
    if names.first().map(|n| n == "MEW").unwrap_or(false) {
        seen.entry("MEW").or_insert((Kind::Packer, Vec::new())).1.push("MEW".into());
    }
    for (name, (kind, secs)) in seen {
        let mut x = Verdict::new(&name.to_lowercase().replace(' ', "_"), name, kind, "high");
        x.evidence.push(format!("section names: {}", secs.join(", ")));
        x.advice = Some(EMULATION_ADVICE.into());
        v.push(x);
    }
}

fn detect_dotnet(b: &[u8], v: &mut Vec<Verdict>) {
    let mut found = std::collections::BTreeMap::<&str, (Kind, Vec<String>)>::new();
    for (marker, name, kind) in DOTNET_MARKERS {
        if contains(b, marker) {
            found.entry(name).or_insert((*kind, Vec::new())).1.push(String::from_utf8_lossy(marker).to_string());
        }
    }
    for (name, (kind, markers)) in found {
        let mut x = Verdict::new(&name.to_lowercase().replace(' ', "_"), name, kind, "medium");
        x.evidence.push(format!("marker string(s): {}", markers.join(", ")));
        x.advice = Some("Managed obfuscation — de4dot (Windows/.NET) can often clean this; unpack still extracts embedded resources.".into());
        v.push(x);
    }
    let costura = contains(b, b"costura.") && (contains(b, b".compressed") || contains(b, b"Costura.AssemblyLoader"));
    let mut r = Verdict::new(
        if costura { "costura" } else { "dotnet_resources" },
        if costura { "Costura.Fody (embedded assemblies)" } else { ".NET embedded resources" },
        if costura { Kind::Bundler } else { Kind::Info },
        if costura { "high" } else { "low" },
    );
    r.evidence.push("CLR header present — managed resources will be extracted".into());
    if costura {
        r.evidence.push("'costura.*' resource names / Costura.AssemblyLoader".into());
    }
    r.handler = Some(Handler::DotnetResources);
    v.push(r);
}

fn detect_heuristic(b: &[u8], info: &BinInfo) -> Option<Verdict> {
    let mut ev = Vec::new();
    let mut score = 0;

    let hi: Vec<String> = info
        .sections
        .iter()
        .filter(|s| s.exec && s.raw_size >= 4096 && s.entropy >= 7.2)
        .map(|s| format!("{} ({:.2})", if s.name.is_empty() { "<unnamed>" } else { &s.name }, s.entropy))
        .collect();
    if !hi.is_empty() {
        ev.push(format!("high-entropy executable section(s): {}", hi.join(", ")));
        score += 2;
    }
    let wx: Vec<&str> = info.sections.iter().filter(|s| s.exec && s.write && s.raw_size > 0).map(|s| s.name.as_str()).collect();
    if !wx.is_empty() && info.format != Format::Elf {
        ev.push(format!("writable + executable section(s): {}", wx.join(", ")));
        score += 1;
    }
    if let Some(pe) = &info.pe {
        if !pe.is_dotnet {
            let lower: Vec<String> = pe.import_funcs.iter().map(|s| s.to_ascii_lowercase()).collect();
            let resolver = lower.iter().any(|f| f.starts_with("loadlibrary")) && lower.iter().any(|f| f == "getprocaddress");
            if pe.import_funcs.len() <= 12 && resolver {
                ev.push(format!(
                    "minimal import table ({} imports incl. LoadLibrary/GetProcAddress)",
                    pe.import_funcs.len()
                ));
                score += 2;
            } else if pe.import_funcs.is_empty() && !pe.is_dll {
                ev.push("no imports".into());
                score += 1;
            }
        }
        if let Some(idx) = info.entry_section {
            let first_exec = info.sections.iter().position(|s| s.exec);
            if first_exec.is_some() && first_exec != Some(idx) {
                ev.push(format!("entry point in non-first code section '{}'", info.sections[idx].name));
                score += 1;
            }
        }
    }
    if let Some(e) = &info.elf {
        if !e.has_section_headers && !hi.is_empty() {
            ev.push("no ELF section headers".into());
            score += 1;
        }
    }
    let overall = crate::binfmt::entropy(b);
    if overall >= 7.4 && b.len() > 16 * 1024 {
        ev.push(format!("whole-file entropy {:.2}", overall));
        score += 1;
    }
    if score < 3 {
        return None;
    }
    let mut v = Verdict::new("generic", "Unknown packer (heuristic)", Kind::Heuristic, if score >= 5 { "medium" } else { "low" });
    v.evidence = ev;
    v.advice = Some(EMULATION_ADVICE.into());
    Some(v)
}

/// Magic for data commonly found appended as an overlay.
pub fn sniff_magic(d: &[u8]) -> Option<(&'static str, &'static str)> {
    let m = |p: &[u8]| d.len() >= p.len() && &d[..p.len()] == p;
    if crate::binfmt::identify(d) == Format::Pe {
        return Some(("PE executable", "exe"));
    }
    if crate::binfmt::identify(d) == Format::Elf {
        return Some(("ELF executable", "elf"));
    }
    if matches!(crate::binfmt::identify(d), Format::MachO | Format::MachOFat) {
        return Some(("Mach-O executable", "macho"));
    }
    if m(b"PK\x03\x04") {
        return Some(("ZIP archive", "zip"));
    }
    if m(b"7z\xbc\xaf\x27\x1c") {
        return Some(("7-Zip archive", "7z"));
    }
    if m(b"Rar!\x1a\x07") {
        return Some(("RAR archive", "rar"));
    }
    if m(b"MSCF\0\0\0\0") {
        return Some(("CAB archive", "cab"));
    }
    if m(b"\x1f\x8b\x08") {
        return Some(("gzip stream", "gz"));
    }
    if m(b"\xfd7zXZ\0") {
        return Some(("xz stream", "xz"));
    }
    if m(b"%PDF-") {
        return Some(("PDF document", "pdf"));
    }
    None
}

fn detect_overlay(b: &[u8], info: &BinInfo, v: &mut Vec<Verdict>) {
    let Some(off) = info.overlay_offset else { return };
    let size = info.overlay_size(b.len() as u64);
    let data = &b[off as usize..];
    // Small unidentified tails are routine; a recognised format is worth
    // carving at any size (a dropper's zipped stage-2 can be tiny).
    if size < 512 && sniff_magic(data).is_none() {
        return;
    }
    // Zero / 0xFF padding is routine alignment, not a payload.
    if data.iter().all(|&c| c == 0) || data.iter().all(|&c| c == 0xff) {
        return;
    }
    let ent = crate::binfmt::entropy(data);
    match sniff_magic(data) {
        Some((what, _ext)) => {
            let mut x = Verdict::new("overlay", &format!("Overlay: {}", what), Kind::Embedded, "high");
            x.evidence.push(format!("{} bytes appended at {:#x} (entropy {:.2})", size, off, ent));
            x.handler = Some(Handler::Carve { offset: off, size, what: what.to_string() });
            v.push(x);
        }
        None if ent >= 7.0 && size >= 4096 => {
            let mut x = Verdict::new("overlay", "Overlay: high-entropy data", Kind::Embedded, "low");
            x.evidence.push(format!("{} bytes appended at {:#x} (entropy {:.2}) — likely encrypted/compressed payload", size, off, ent));
            x.handler = Some(Handler::Carve { offset: off, size, what: "overlay data".into() });
            v.push(x);
        }
        None => {}
    }
}

/// Executables embedded inside this file (resources, data sections, blobs),
/// validated structurally so random "MZ" bytes don't count.
/// Python bytecode. Obfuscation layers (an xz/zlib blob or encoded marshal
/// in the constants) make it a crypter verdict; plain bytecode is
/// informational, with a handler that still extracts its strings.
fn detect_pyc(b: &[u8]) -> Option<Verdict> {
    let (maj, min) = crate::pyc::identify(b)?;
    match crate::pyc::peel(b) {
        Ok(p) if !p.layers.is_empty() => {
            let mut v = Verdict::new("python_obfuscated", "Obfuscated Python bytecode", Kind::Crypter, "high");
            v.evidence.push(format!("Python {maj}.{min} .pyc"));
            v.evidence.push(format!(
                "{} layer(s) peeled statically: {}",
                p.layers.len(),
                p.layers.iter().map(|l| l.how.as_str()).collect::<Vec<_>>().join(" -> ")
            ));
            let funcs = crate::pyc::walk(&p.inner).len();
            v.evidence.push(format!("innermost code object: {funcs} function(s)"));
            if let Some(e) = &p.error {
                v.evidence.push(format!("stopped: {e}"));
            }
            v.handler = Some(Handler::Pyc);
            Some(v)
        }
        Ok(p) => {
            let mut v = Verdict::new("python_bytecode", "Python bytecode", Kind::Info, "high");
            v.evidence.push(format!("Python {maj}.{min} .pyc, {} code object(s); no obfuscation layer found", crate::pyc::walk(&p.inner).len()));
            v.handler = Some(Handler::Pyc);
            Some(v)
        }
        Err(e) => {
            let mut v = Verdict::new("python_bytecode", "Python bytecode", Kind::Info, "medium");
            v.evidence.push(format!("Python {maj}.{min} .pyc header; marshal data could not be parsed: {e}"));
            Some(v)
        }
    }
}

fn detect_embedded(b: &[u8], info: &BinInfo, v: &mut Vec<Verdict>) {
    if b.len() > 256 * 1024 * 1024 {
        return;
    }
    let overlay = info.overlay_offset.unwrap_or(u64::MAX);
    // Regions already claimed by an overlay carve.
    let claimed: Vec<(u64, u64)> = v
        .iter()
        .filter_map(|x| match &x.handler {
            Some(Handler::Carve { offset, size, .. }) => Some((*offset, offset + size)),
            _ => None,
        })
        .collect();
    let mut hits: Vec<(u64, u64, &'static str)> = Vec::new();

    for off in find_all(b, b"MZ", 100_000) {
        if off == 0 || hits.len() >= 32 {
            continue;
        }
        let d = &b[off..];
        let r = crate::binfmt::Rd::new(d, true);
        let Some(lfanew) = r.u32(0x3c) else { continue };
        if !(0x40..0x1000).contains(&lfanew) || r.bytes(lfanew as u64, 4) != Some(b"PE\0\0") {
            continue;
        }
        let machine = r.u16(lfanew as u64 + 4).unwrap_or(0);
        let nsec = r.u16(lfanew as u64 + 6).unwrap_or(0);
        if !matches!(machine, 0x14c | 0x8664 | 0x1c0 | 0x1c4 | 0xaa64) || nsec == 0 || nsec > 96 {
            continue;
        }
        if let Some(sz) = crate::binfmt::pe_disk_size(d) {
            let sz = sz.min(d.len() as u64);
            if sz >= 512 {
                hits.push((off as u64, sz, "PE executable"));
            }
        }
    }
    for off in find_all(b, b"\x7fELF", 1000) {
        if off == 0 || hits.len() >= 32 {
            continue;
        }
        let d = &b[off..];
        if d.len() < 64 || !matches!(d[4], 1 | 2) || !matches!(d[5], 1 | 2) || d[6] != 1 {
            continue;
        }
        let ei = crate::binfmt::parse(d);
        if ei.arch.is_empty() || ei.sections.is_empty() {
            continue;
        }
        let end = ei.overlay_offset.unwrap_or(d.len() as u64);
        if end >= 512 {
            hits.push((off as u64, end, "ELF executable"));
        }
    }
    for off in find_all(b, b"\xcf\xfa\xed\xfe", 1000).into_iter().chain(find_all(b, b"\xce\xfa\xed\xfe", 1000)) {
        if off == 0 || hits.len() >= 32 || info.format == Format::MachOFat {
            continue;
        }
        let d = &b[off..];
        let r = crate::binfmt::Rd::new(d, true);
        let ncmds = r.u32(16).unwrap_or(0);
        let filetype = r.u32(12).unwrap_or(0);
        if ncmds == 0 || ncmds > 512 || !(1..=12).contains(&filetype) || crate::binfmt::macho_cpu(r.u32(4).unwrap_or(0)).is_empty() {
            continue;
        }
        if let Some(sz) = crate::binfmt::macho_disk_size(d) {
            if sz >= 512 {
                hits.push((off as u64, sz, "Mach-O executable"));
            }
        }
    }

    hits.sort();
    let mut last_end = 0u64;
    for (off, size, what) in hits {
        if off < last_end {
            continue; // nested inside a previous hit — the outer carve will recurse into it
        }
        if claimed.iter().any(|&(s, e)| off >= s && off < e) {
            continue;
        }
        last_end = off + size;
        let mut x = Verdict::new("embedded", &format!("Embedded {}", what), Kind::Embedded, "medium");
        x.evidence.push(format!(
            "{} at {:#x}, {} bytes{}",
            what,
            off,
            size,
            if off >= overlay { " (in overlay)" } else { "" }
        ));
        x.handler = Some(Handler::Carve { offset: off, size, what: what.to_string() });
        v.push(x);
    }
}
