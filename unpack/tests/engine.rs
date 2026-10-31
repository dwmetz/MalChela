//! Self-contained engine tests: every input is synthesised here, so no
//! samples or external tools (upx, 7-Zip) are needed.

use std::io::Write;
use unpack::engine::{self, Options};

fn opts(dir: &std::path::Path) -> Options {
    Options { out_dir: dir.join("out"), max_depth: 3, max_output: 64 * 1024 * 1024, use_external: false }
}

/// A minimal thin Mach-O: 64-bit header + one LC_SEGMENT_64 covering the file.
fn thin_macho(cputype: u32, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    b[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    b[4..8].copy_from_slice(&cputype.to_le_bytes());
    b[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    b[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
    b[20..24].copy_from_slice(&72u32.to_le_bytes()); // sizeofcmds
    let lc = 32;
    b[lc..lc + 4].copy_from_slice(&0x19u32.to_le_bytes());
    b[lc + 4..lc + 8].copy_from_slice(&72u32.to_le_bytes());
    b[lc + 8..lc + 14].copy_from_slice(b"__TEXT");
    b[lc + 48..lc + 56].copy_from_slice(&(len as u64).to_le_bytes()); // filesize
    b[lc + 60..lc + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot r-x
    b
}

#[test]
fn fat_macho_is_split_into_slices() {
    let a = thin_macho(0x0100_0007, 0x800);
    let b = thin_macho(0x0100_000c, 0x900);
    let mut fat = vec![0u8; 0x1000];
    fat[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    fat[4..8].copy_from_slice(&2u32.to_be_bytes());
    for (i, (cpu, off, sz)) in [(0x0100_0007u32, 0x1000u32, a.len()), (0x0100_000c, 0x2000, b.len())].iter().enumerate() {
        let o = 8 + i * 20;
        fat[o..o + 4].copy_from_slice(&cpu.to_be_bytes());
        fat[o + 8..o + 12].copy_from_slice(&off.to_be_bytes());
        fat[o + 12..o + 16].copy_from_slice(&(*sz as u32).to_be_bytes());
    }
    fat.extend_from_slice(&a);
    fat.resize(0x2000, 0);
    fat.extend_from_slice(&b);

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("universal");
    std::fs::write(&input, &fat).unwrap();
    let out = engine::run(&input, opts(dir.path())).unwrap();
    let payloads = engine::payloads(&out.root);
    assert_eq!(payloads.len(), 2);
    assert!(payloads.iter().any(|p| p.name.ends_with("x86_64")));
    assert!(payloads.iter().any(|p| p.name.ends_with("ARM64")));
    assert_eq!(std::fs::read(&payloads[0].path).unwrap(), a);
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn pyinstaller_archive_is_extracted_with_pyc_header() {
    // CArchive: [entry data...][TOC][cookie]
    let script = b"\xe3fake-marshalled-code http://c2.example.test".to_vec();
    let boot = b"\xe3bootstrap".to_vec();
    let entries = [("pyiboot01_bootstrap", b's', zlib(&boot), boot.len()), ("evil", b's', zlib(&script), script.len())];

    let mut pkg = Vec::new();
    let mut toc = Vec::new();
    for (name, tc, data, ulen) in &entries {
        let pos = pkg.len() as u32;
        pkg.extend_from_slice(data);
        let mut nm = name.as_bytes().to_vec();
        nm.push(0);
        while (18 + nm.len()) % 16 != 0 {
            nm.push(0);
        }
        let esize = (18 + nm.len()) as u32;
        toc.extend_from_slice(&esize.to_be_bytes());
        toc.extend_from_slice(&pos.to_be_bytes());
        toc.extend_from_slice(&(data.len() as u32).to_be_bytes());
        toc.extend_from_slice(&(*ulen as u32).to_be_bytes());
        toc.push(1);
        toc.push(*tc);
        toc.extend_from_slice(&nm);
    }
    let toc_off = pkg.len() as u32;
    pkg.extend_from_slice(&toc);
    let mut cookie = Vec::new();
    cookie.extend_from_slice(b"MEI\x0c\x0b\x0a\x0b\x0e");
    let pkg_len = (pkg.len() + 88) as u32;
    cookie.extend_from_slice(&pkg_len.to_be_bytes());
    cookie.extend_from_slice(&toc_off.to_be_bytes());
    cookie.extend_from_slice(&(toc.len() as u32).to_be_bytes());
    cookie.extend_from_slice(&312u32.to_be_bytes());
    let mut lib = b"libpython3.12.so.1.0".to_vec();
    lib.resize(64, 0);
    cookie.extend_from_slice(&lib);

    let mut file = vec![0x7f, b'E', b'L', b'F'];
    file.resize(4096, 0x90); // stand-in bootloader bytes
    file.extend_from_slice(&pkg);
    file.extend_from_slice(&cookie);

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("bundle");
    std::fs::write(&input, &file).unwrap();
    let out = engine::run(&input, opts(dir.path())).unwrap();
    assert!(out.root.verdicts.iter().any(|v| v.id == "pyinstaller"));
    let payloads = engine::payloads(&out.root);
    assert_eq!(payloads.len(), 1, "only the non-bootstrap script is a payload");
    assert_eq!(payloads[0].name, "evil.pyc");
    let pyc = std::fs::read(&payloads[0].path).unwrap();
    assert_eq!(&pyc[..4], &[0xcb, 0x0d, 0x0d, 0x0a], "3.12 pyc magic");
    assert_eq!(&pyc[16..], &script[..]);
}

#[test]
fn appended_zip_overlay_is_carved_and_clean_input_writes_nothing() {
    // Clean: random-ish text, no overlay, nothing to do.
    let dir = tempfile::tempdir().unwrap();
    let clean = dir.path().join("notes.txt");
    std::fs::write(&clean, b"just some text\n".repeat(100)).unwrap();
    let out = engine::run(&clean, opts(dir.path())).unwrap();
    assert!(out.root.verdicts.is_empty());
    assert!(!dir.path().join("out").exists(), "empty output dir is removed");

    // Minimal ELF64 with one PT_LOAD covering 0x200 bytes, then a ZIP.
    let mut elf = vec![0u8; 0x200];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[18] = 62;
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&0x200u64.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x200u64.to_le_bytes());
    let zip = b"PK\x03\x04stage2-goes-here".to_vec();
    elf.extend_from_slice(&zip);
    let input = dir.path().join("dropper");
    std::fs::write(&input, &elf).unwrap();
    let out = engine::run(&input, opts(dir.path())).unwrap();
    let p = engine::payloads(&out.root);
    assert_eq!(p.len(), 1);
    assert!(p[0].name.ends_with(".zip"));
    assert_eq!(std::fs::read(&p[0].path).unwrap(), zip);
}
