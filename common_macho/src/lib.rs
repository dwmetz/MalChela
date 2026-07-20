// Shared macOS .app bundle helpers for MalChela's Mach-O tooling.
//
// A macOS app bundle can embed additional Mach-O binaries (frameworks, XPC
// services, app extensions, login items, helper tools) well beyond the main
// executable named in Info.plist. This crate provides bundle detection,
// Info.plist metadata extraction, and a bundle walker that discovers every
// embedded Mach-O binary so consuming tools (mstrings, macho_info,
// codesign_check) can analyze the whole bundle, not just the front door.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Bundle-level metadata pulled from Contents/Info.plist.
pub struct BundleInfo {
    pub bundle_identifier: Option<String>,
    pub bundle_executable: Option<String>,
    /// CFBundleShortVersionString, falling back to CFBundleVersion.
    pub bundle_version: Option<String>,
    pub info_plist_path: Option<PathBuf>,
}

// Bundle subdirectories that can legitimately contain Mach-O binaries.
const SCAN_SUBDIRS: &[&str] = &[
    "Contents/MacOS",
    "Contents/Frameworks",
    "Contents/PlugIns",
    "Contents/XPCServices",
    "Contents/Library/LoginItems",
    "Contents/Helpers",
];

// Obviously-non-binary extensions skipped before attempting a Mach-O parse.
// This is only a performance pre-filter — actual Mach-O confirmation is done
// with goblin, since main executables typically have no extension at all.
const SKIP_EXTENSIONS: &[&str] = &[
    "plist", "nib", "storyboardc", "strings", "stringsdict", "loctable",
    "png", "jpg", "jpeg", "gif", "tiff", "icns", "car", "pdf",
    "json", "txt", "md", "html", "htm", "css", "js", "xml", "rtf",
    "sig", "der", "cer", "pem", "otf", "ttf", "ttc",
    "h", "modulemap", "swiftmodule", "swiftdoc", "swiftinterface", "tbd",
    "mom", "momd", "db", "sqlite", "dat", "wav", "aiff", "mp3", "mp4", "mov",
];

// Mach-O / fat binary magic values (both endiannesses).
const MACHO_MAGICS: &[[u8; 4]] = &[
    [0xfe, 0xed, 0xfa, 0xce], // MH_MAGIC
    [0xce, 0xfa, 0xed, 0xfe], // MH_CIGAM
    [0xfe, 0xed, 0xfa, 0xcf], // MH_MAGIC_64
    [0xcf, 0xfa, 0xed, 0xfe], // MH_CIGAM_64
    [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC
    [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM
    [0xca, 0xfe, 0xba, 0xbf], // FAT_MAGIC_64
    [0xbf, 0xba, 0xfe, 0xca], // FAT_CIGAM_64
];

/// True if `path` is a directory containing Contents/Info.plist.
pub fn is_app_bundle(path: &Path) -> bool {
    path.is_dir() && path.join("Contents").join("Info.plist").is_file()
}

/// Parse Contents/Info.plist under `bundle_path` for bundle metadata.
/// Returns None if the path is not a recognized bundle or the plist fails to parse.
pub fn bundle_metadata(bundle_path: &Path) -> Option<BundleInfo> {
    let info_plist = bundle_path.join("Contents").join("Info.plist");
    let dict = plist::from_file::<_, plist::Dictionary>(&info_plist).ok()?;

    fn get_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
        dict.get(key)?.as_string().map(String::from)
    }

    Some(BundleInfo {
        bundle_identifier: get_string(&dict, "CFBundleIdentifier"),
        bundle_executable: get_string(&dict, "CFBundleExecutable"),
        bundle_version: get_string(&dict, "CFBundleShortVersionString")
            .or_else(|| get_string(&dict, "CFBundleVersion")),
        info_plist_path: Some(info_plist),
    })
}

/// Walk a .app bundle and return every embedded Mach-O binary found under the
/// standard binary-bearing subdirectories (Contents/MacOS, Frameworks, PlugIns,
/// XPCServices, Library/LoginItems, Helpers).
///
/// Each candidate is confirmed by attempting a goblin parse — only files that
/// parse as Mach-O (thin or fat) are returned. Results are deduplicated by
/// canonicalized real path (so `Versions/Current -> A` symlinks don't produce
/// duplicates), symlinks resolving outside the bundle root are not followed,
/// and the returned paths are sorted for deterministic ordering.
pub fn find_macho_binaries(bundle_path: &Path) -> Vec<PathBuf> {
    let mut results: Vec<PathBuf> = Vec::new();

    let bundle_root = match fs::canonicalize(bundle_path) {
        Ok(p) => p,
        Err(_) => return results,
    };

    let mut visited_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut seen_files: BTreeSet<PathBuf> = BTreeSet::new();

    for sub in SCAN_SUBDIRS {
        let dir = bundle_path.join(sub);
        if dir.is_dir() {
            walk_dir(&dir, &bundle_root, &mut visited_dirs, &mut seen_files, &mut results);
        }
    }

    results.sort();
    results
}

fn walk_dir(
    dir: &Path,
    bundle_root: &Path,
    visited_dirs: &mut BTreeSet<PathBuf>,
    seen_files: &mut BTreeSet<PathBuf>,
    results: &mut Vec<PathBuf>,
) {
    // Canonicalize to guard against symlink cycles and links escaping the bundle.
    let canon = match fs::canonicalize(dir) {
        Ok(c) => c,
        Err(_) => return,
    };
    if !canon.starts_with(bundle_root) || !visited_dirs.insert(canon) {
        return;
    }

    let mut entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(_) => return,
    };
    entries.sort();

    for path in entries {
        if path.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            walk_dir(&path, bundle_root, visited_dirs, seen_files, results);
        } else if path.is_file() {
            if should_skip_file(&path) {
                continue;
            }
            let canon_file = match fs::canonicalize(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !canon_file.starts_with(bundle_root) || !seen_files.insert(canon_file) {
                continue;
            }
            if is_macho_file(&path) {
                results.push(path);
            }
        }
    }
}

fn should_skip_dir(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name == "_CodeSignature" || name.ends_with(".lproj"),
        None => false,
    }
}

fn should_skip_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if SKIP_EXTENSIONS.iter().any(|s| *s == ext) {
            return true;
        }
    }
    false
}

// Confirm a file is actually Mach-O/fat: cheap magic pre-check, then a full
// goblin parse. The goblin parse is the correctness check — filename and magic
// alone are not trusted.
fn is_macho_file(path: &Path) -> bool {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() < 4 || !MACHO_MAGICS.iter().any(|m| bytes[..4] == m[..]) {
        return false;
    }
    matches!(goblin::Object::parse(&bytes), Ok(goblin::Object::Mach(_)))
}

/// Convenience entry point for tools accepting either a file or a .app bundle:
/// - regular file            -> that single path
/// - recognized .app bundle  -> every embedded Mach-O binary in the bundle
/// - anything else           -> empty vec
pub fn resolve_scan_targets(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.to_path_buf()]
    } else if is_app_bundle(path) {
        find_macho_binaries(path)
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const INFO_PLIST_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.testapp</string>
    <key>CFBundleExecutable</key>
    <string>FakeExe</string>
    <key>CFBundleShortVersionString</key>
    <string>1.2.3</string>
</dict>
</plist>
"#;

    fn make_fixture_bundle(root: &Path) -> PathBuf {
        let bundle = root.join("Test.app");
        let macos_dir = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos_dir).unwrap();
        fs::write(bundle.join("Contents").join("Info.plist"), INFO_PLIST_XML).unwrap();
        fs::write(macos_dir.join("FakeExe"), "this is plain text, not a Mach-O binary").unwrap();
        bundle
    }

    #[test]
    fn non_macho_files_are_filtered_out() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_fixture_bundle(tmp.path());

        // Plain-text "executable" must be rejected by the goblin parse check,
        // proving discovery verifies file contents rather than just walking.
        let found = find_macho_binaries(&bundle);
        assert!(
            found.is_empty(),
            "expected no Mach-O binaries in fixture bundle, got: {:?}",
            found
        );
    }

    #[test]
    fn bundle_metadata_extracts_plist_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_fixture_bundle(tmp.path());

        let info = bundle_metadata(&bundle).expect("fixture bundle should parse");
        assert_eq!(info.bundle_identifier.as_deref(), Some("com.example.testapp"));
        assert_eq!(info.bundle_executable.as_deref(), Some("FakeExe"));
        assert_eq!(info.bundle_version.as_deref(), Some("1.2.3"));
        assert!(info.info_plist_path.unwrap().ends_with("Contents/Info.plist"));
    }

    #[test]
    fn plain_directory_is_not_a_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let plain = tmp.path().join("just_a_dir");
        fs::create_dir_all(&plain).unwrap();

        assert!(!is_app_bundle(&plain));
        assert!(bundle_metadata(&plain).is_none());
        assert!(resolve_scan_targets(&plain).is_empty());
    }

    #[test]
    fn resolve_scan_targets_returns_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("some_file.bin");
        fs::write(&file, "hello").unwrap();

        assert_eq!(resolve_scan_targets(&file), vec![file.clone()]);
    }
}
