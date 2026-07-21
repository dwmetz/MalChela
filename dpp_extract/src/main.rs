use clap::Parser;
use dpp::{DmgPipeline, FilesystemHandle, FsEntryKind};
use serde::Serialize;
use std::fs;
use std::io::{BufReader, Cursor, Read, Seek};
use std::path::{Component, Path, PathBuf};
use std::process::exit;

#[derive(Parser)]
#[command(name = "dpp_extract")]
#[command(
    about = "Unwrap Apple DMG/PKG containers (UDIF -> HFS+/APFS -> XAR -> PBZX/CPIO) to reach the real payload files inside",
    long_about = None
)]
struct Cli {
    #[arg(value_name = "PATH", help = "Path to a .dmg or .pkg file")]
    path: String,

    #[arg(short, long, help = "Output directory (default: <stem>_extracted next to input)")]
    out: Option<String>,

    #[arg(long, help = "Optional case name to save output under")]
    case: Option<String>,

    #[arg(
        long,
        help = "Emit a machine-readable JSON summary instead of human-readable text",
        default_value_t = false
    )]
    json: bool,
}

#[derive(Serialize, Default)]
struct PkgSummary {
    pkg_path: String,
    components: Vec<String>,
    payload_files: u64,
    scripts_files: u64,
}

#[derive(Serialize)]
struct ExtractSummary {
    success: bool,
    input: String,
    container_type: String,  // "dmg" | "pkg"
    extraction_mode: String, // "pkg_payload" | "raw_filesystem"
    extracted_dir: String,
    packages: Vec<PkgSummary>,
    files_extracted: u64,
    skipped: Vec<String>,
    note: String,
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(summary) => {
            if cli.json {
                println!("{}", serde_json::to_string(&summary).unwrap());
            } else {
                print_summary(&summary);
            }
        }
        Err(e) => {
            if cli.json {
                let payload = serde_json::json!({ "success": false, "input": cli.path, "error": e });
                println!("{}", payload);
            } else {
                eprintln!("Error: {}", e);
            }
            exit(1);
        }
    }
}

fn run(cli: &Cli) -> Result<ExtractSummary, String> {
    let input = PathBuf::from(&cli.path);
    if !input.is_file() {
        return Err(format!("Input path does not exist or is not a file: {}", cli.path));
    }

    let case_output_dir = if let Some(ref name) = cli.case {
        common_config::ensure_case_json(name);
        let path = PathBuf::from(format!("saved_output/cases/{}/dpp_extract", name));
        fs::create_dir_all(&path).map_err(|e| format!("Failed to create case output directory: {}", e))?;
        Some(path)
    } else {
        None
    };

    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("extracted");
    let default_dest = input
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{}_extracted", stem));
    let dest = cli
        .out
        .as_ref()
        .map(PathBuf::from)
        .or(case_output_dir)
        .unwrap_or(default_dest);

    let ext = input
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "dmg" => extract_dmg(&input, &dest),
        "pkg" => extract_pkg_file(&input, &dest),
        other => Err(format!(
            "Unsupported extension '.{}' — dpp_extract handles .dmg and .pkg",
            other
        )),
    }
}

fn extract_dmg(input: &Path, dest: &Path) -> Result<ExtractSummary, String> {
    let mut pipeline = DmgPipeline::open(input).map_err(|e| format!("Failed to open DMG: {}", e))?;
    let mut fs_handle = pipeline
        .open_filesystem()
        .map_err(|e| format!("Failed to open filesystem in DMG: {}", e))?;

    let entries = fs_handle
        .walk()
        .map_err(|e| format!("Failed to walk DMG filesystem: {}", e))?;
    let pkg_paths: Vec<String> = entries
        .iter()
        .filter(|e| e.entry.kind == FsEntryKind::File && e.path.to_lowercase().ends_with(".pkg"))
        .map(|e| e.path.clone())
        .collect();

    if pkg_paths.is_empty() {
        // No installer inside — the raw filesystem tree IS the payload. Extract
        // entry-by-entry (not dpp's own all-or-nothing extract_all/extract_path)
        // so one bad HFS+/APFS entry doesn't abort the whole DMG: real-world
        // DMGs have hit both an embedded-NUL-byte decoded filename and a
        // walk()-listed alias (.DropDMGBackground) that read_file_to can't
        // resolve. Both are hfsplus/apfs crate quirks, not something we can
        // fix upstream here, but we can keep going around them.
        fs::create_dir_all(dest).map_err(|e| format!("Failed to create output dir: {}", e))?;
        let (files, dirs, skipped) = extract_walk_resilient(&mut fs_handle, &entries, dest);
        return Ok(ExtractSummary {
            success: true,
            input: input.display().to_string(),
            container_type: "dmg".into(),
            extraction_mode: "raw_filesystem".into(),
            extracted_dir: dest.display().to_string(),
            packages: vec![],
            files_extracted: files,
            note: format!(
                "No .pkg found inside DMG — extracted raw filesystem ({} files, {} dirs{}).",
                files,
                dirs,
                if skipped.is_empty() {
                    String::new()
                } else {
                    format!(", {} entries skipped", skipped.len())
                }
            ),
            skipped,
        });
    }

    let mut packages = Vec::new();
    let mut total_files = 0u64;
    for pkg_path in &pkg_paths {
        let mut pkg = fs_handle
            .open_pkg(pkg_path)
            .map_err(|e| format!("Failed to open pkg '{}': {}", pkg_path, e))?;
        let (payload_files, scripts_files, components) = extract_pkg_payloads(&mut pkg, pkg_path, dest)?;
        total_files += payload_files + scripts_files;
        packages.push(PkgSummary {
            pkg_path: pkg_path.clone(),
            components,
            payload_files,
            scripts_files,
        });
    }

    Ok(ExtractSummary {
        success: true,
        input: input.display().to_string(),
        container_type: "dmg".into(),
        extraction_mode: "pkg_payload".into(),
        extracted_dir: dest.display().to_string(),
        packages,
        files_extracted: total_files,
        skipped: vec![],
        note: format!(
            "Extracted payload from {} package(s) inside DMG ({} files total).",
            pkg_paths.len(),
            total_files
        ),
    })
}

fn extract_pkg_file(input: &Path, dest: &Path) -> Result<ExtractSummary, String> {
    let file = std::fs::File::open(input).map_err(|e| format!("Failed to open pkg: {}", e))?;
    let reader = BufReader::new(file);
    let mut pkg = dpp::xara::PkgReader::open(reader).map_err(|e| format!("Failed to parse pkg: {}", e))?;
    let pkg_path = input.display().to_string();
    let (payload_files, scripts_files, components) = extract_pkg_payloads(&mut pkg, &pkg_path, dest)?;
    let files_extracted = payload_files + scripts_files;

    Ok(ExtractSummary {
        success: true,
        input: pkg_path.clone(),
        container_type: "pkg".into(),
        extraction_mode: "pkg_payload".into(),
        extracted_dir: dest.display().to_string(),
        packages: vec![PkgSummary {
            pkg_path,
            components,
            payload_files,
            scripts_files,
        }],
        files_extracted,
        skipped: vec![],
        note: format!("Extracted payload from pkg ({} files).", files_extracted),
    })
}

/// Extract every component's Payload (PBZX/CPIO) and Scripts (preinstall/
/// postinstall archive) from an already-open PkgReader into `dest` — one
/// subdirectory per named component for a product/distribution package, or
/// flat for a single component package. Scripts is extracted unconditionally
/// alongside Payload: some real installers (oRAT's "Bitget Apps.pkg",
/// Shlayer's "Player.pkg") ship an empty or near-empty Payload and drop their
/// actual malicious behavior entirely from the postinstall script instead, so
/// Payload-only extraction silently misses the payload in those cases.
/// Returns (payload files extracted, scripts files extracted, component names found).
fn extract_pkg_payloads<R: Read + Seek>(
    pkg: &mut dpp::xara::PkgReader<R>,
    pkg_path: &str,
    dest: &Path,
) -> Result<(u64, u64, Vec<String>), String> {
    let components = pkg.components();
    let pkg_stem = Path::new(pkg_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("pkg");
    let mut payload_files = 0u64;
    let mut scripts_files = 0u64;

    for component in &components {
        let comp_dir = if component.is_empty() {
            dest.join(pkg_stem)
        } else {
            dest.join(pkg_stem).join(component)
        };

        let payload = pkg
            .payload(component)
            .map_err(|e| format!("Failed to read payload for '{}' component '{}': {}", pkg_path, component, e))?;
        let archive = decode_payload(&payload)
            .map_err(|e| format!("Failed to decode Payload for '{}': {}", pkg_path, e))?;
        let payload_dir = comp_dir.join("Payload");
        fs::create_dir_all(&payload_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;
        let stats = archive
            .extract_all(&payload_dir)
            .map_err(|e| format!("Failed to extract payload for '{}': {}", pkg_path, e))?;
        payload_files += stats.files;

        let scripts_path = if component.is_empty() {
            "Scripts".to_string()
        } else {
            format!("{}/Scripts", component)
        };
        if let Some(scripts_file) = pkg.xar().find(&scripts_path).cloned() {
            match pkg.xar_mut().read_file(&scripts_file) {
                Ok(data) => match decode_payload(&data) {
                    Ok(archive) => {
                        let scripts_dir = comp_dir.join("Scripts");
                        if fs::create_dir_all(&scripts_dir).is_ok() {
                            if let Ok(stats) = archive.extract_all(&scripts_dir) {
                                scripts_files += stats.files;
                            }
                        }
                    }
                    Err(_) => {} // Scripts present but not a PBZX/CPIO stream we recognize — skip, not fatal.
                },
                Err(_) => {}
            }
        }
    }

    Ok((payload_files, scripts_files, components))
}

/// A PKG's Payload/Scripts entry is either PBZX-wrapped CPIO (modern Apple
/// installers, magic "pbzx") or a plain gzip-compressed CPIO stream (the
/// classic format still produced by pkgbuild for simple flat packages — this
/// is what a lot of older/simpler malware installers like EvilQuest's use,
/// and it has no "pbzx" magic to detect the wrapper by).
fn decode_payload(payload: &[u8]) -> Result<dpp::pbzx::Archive, String> {
    if payload.starts_with(b"pbzx") {
        return dpp::pbzx::Archive::from_reader(Cursor::new(payload)).map_err(|e| e.to_string());
    }

    let mut decoder = flate2::read::GzDecoder::new(payload);
    let mut cpio_data = Vec::new();
    decoder
        .read_to_end(&mut cpio_data)
        .map_err(|e| format!("not PBZX and not gzip-compressed CPIO either: {}", e))?;
    dpp::pbzx::Archive::from_cpio(&cpio_data).map_err(|e| e.to_string())
}

/// Reject `..`/absolute components and strip embedded NUL bytes (a NUL in a
/// path is rejected outright by the OS on file creation — dpp's own decoded
/// HFS+/APFS entry names have been observed to contain one on real-world
/// DMGs, which otherwise aborts extraction of the entire volume on a single
/// bad entry). Returns None if nothing usable remains after sanitizing.
fn sanitize_rel_path(raw: &str) -> Option<PathBuf> {
    let cleaned: String = raw.chars().filter(|&c| c != '\0').collect();
    let trimmed = cleaned.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let mut clean = PathBuf::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(c) => clean.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

/// Walk-then-extract a filesystem entry-by-entry instead of using
/// FilesystemHandle::extract_all/extract_path, which abort the whole
/// extraction on the first per-entry error. Returns (files, dirs, skipped
/// entries with a reason).
fn extract_walk_resilient(
    fs_handle: &mut FilesystemHandle,
    entries: &[dpp::FsWalkEntry],
    dest: &Path,
) -> (u64, u64, Vec<String>) {
    let mut files = 0u64;
    let mut dirs = 0u64;
    let mut skipped = Vec::new();

    for entry in entries {
        let rel = match sanitize_rel_path(&entry.path) {
            Some(p) => p,
            None => {
                skipped.push(format!("{} (unusable path after sanitizing)", entry.path));
                continue;
            }
        };
        let dest_path = dest.join(&rel);

        match entry.entry.kind {
            FsEntryKind::Directory => match fs::create_dir_all(&dest_path) {
                Ok(_) => dirs += 1,
                Err(e) => skipped.push(format!("{} (mkdir failed: {})", entry.path, e)),
            },
            FsEntryKind::File => {
                let result: Result<(), String> = (|| {
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    let mut out = fs::File::create(&dest_path).map_err(|e| e.to_string())?;
                    fs_handle
                        .read_file_to(&entry.path, &mut out)
                        .map_err(|e| e.to_string())?;
                    Ok(())
                })();
                match result {
                    Ok(_) => files += 1,
                    Err(e) => skipped.push(format!("{} ({})", entry.path, e)),
                }
            }
            FsEntryKind::Symlink => {} // matches dpp's own extract_all behavior: symlinks are never created
        }
    }

    (files, dirs, skipped)
}

fn print_summary(s: &ExtractSummary) {
    println!("Input: {}", s.input);
    println!("Container: {}", s.container_type);
    println!("Mode: {}", s.extraction_mode);
    for p in &s.packages {
        let comp_label = if p.components.iter().all(|c| c.is_empty()) {
            "flat".to_string()
        } else {
            p.components.join(", ")
        };
        println!(
            "  Package: {} (components: {}) -> {} payload file(s), {} scripts file(s)",
            p.pkg_path, comp_label, p.payload_files, p.scripts_files
        );
    }
    println!("Extracted {} file(s) to: {}", s.files_extracted, s.extracted_dir);
    if !s.skipped.is_empty() {
        println!("Skipped {} entries:", s.skipped.len());
        for entry in &s.skipped {
            println!("  - {}", entry);
        }
    }
    println!("{}", s.note);
}
