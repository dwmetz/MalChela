//! Cache state for hot-reload.
//!
//! A directory signature is a `BTreeMap<PathBuf, (size, mtime)>` capturing
//! every rule file's identity-from-the-filesystem's-point-of-view. Two
//! signatures comparing equal means the rule set on disk has not changed
//! since the last load. Two signatures comparing different means at least
//! one file was added, removed, modified, or had its mtime bumped (e.g.
//! by a `touch`) — and we should recompile.
//!
//! The signature uses size **and** mtime together so that filesystems with
//! coarse mtime resolution (FAT32 = 2s) still detect changes that only
//! affect content length. Two writes with the same size and same mtime
//! tick would alias to one signature; that is a documented hot-reload
//! limitation rather than a defect — at coarse-mtime resolution, no
//! signature scheme without re-hashing every file can reliably detect
//! that case.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use yara_x::Rules;

pub(crate) type DirSignature = BTreeMap<PathBuf, (u64, SystemTime)>;

#[derive(Debug)]
pub(crate) struct CacheState {
    pub signature: DirSignature,
    pub rules: Arc<Rules>,
    pub compile_warnings: Vec<String>,
}

/// Build a directory signature from a list of file paths.
///
/// Each file's metadata is fetched via `std::fs::metadata`, which follows
/// symlinks. Files that fail to stat (e.g. removed between the WalkDir and
/// this call) propagate as an `io::Error`; callers decide whether to retry
/// or surface the failure.
pub(crate) fn signature_for_files(files: &[PathBuf]) -> std::io::Result<DirSignature> {
    let mut out = DirSignature::new();
    for f in files {
        let meta = std::fs::metadata(f)?;
        let mtime = meta.modified()?;
        out.insert(f.clone(), (meta.len(), mtime));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::path::Path;
    use std::time::Duration;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, content).expect("write");
        p
    }

    #[test]
    fn signature_is_empty_for_empty_list() {
        let sig = signature_for_files(&[]).unwrap();
        assert!(sig.is_empty());
    }

    #[test]
    fn signature_is_stable_across_repeated_calls() {
        let td = TempDir::new().unwrap();
        let p = write(td.path(), "a.yar", "rule a { condition: true }");
        let sig1 = signature_for_files(std::slice::from_ref(&p)).unwrap();
        let sig2 = signature_for_files(&[p]).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn signature_changes_when_a_file_is_added() {
        let td = TempDir::new().unwrap();
        let a = write(td.path(), "a.yar", "rule a { condition: true }");
        let sig_one = signature_for_files(std::slice::from_ref(&a)).unwrap();
        let b = write(td.path(), "b.yar", "rule b { condition: true }");
        let sig_two = signature_for_files(&[a, b]).unwrap();
        assert_ne!(sig_one, sig_two);
        assert_eq!(sig_one.len(), 1);
        assert_eq!(sig_two.len(), 2);
    }

    #[test]
    fn signature_changes_when_size_changes() {
        let td = TempDir::new().unwrap();
        let p = write(td.path(), "r.yar", "rule a { condition: true }");
        let sig1 = signature_for_files(std::slice::from_ref(&p)).unwrap();
        write(td.path(), "r.yar", "rule longer_name { condition: true }");
        let sig2 = signature_for_files(&[p]).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn signature_changes_when_mtime_changes() {
        let td = TempDir::new().unwrap();
        let p = write(td.path(), "r.yar", "rule a { condition: true }");
        let sig1 = signature_for_files(std::slice::from_ref(&p)).unwrap();

        let f = OpenOptions::new().write(true).open(&p).unwrap();
        let bumped = SystemTime::now() + Duration::from_secs(120);
        f.set_modified(bumped).expect("set_modified");
        drop(f);

        let sig2 = signature_for_files(&[p]).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn signature_propagates_io_error_on_missing_file() {
        let td = TempDir::new().unwrap();
        let phantom = td.path().join("never_existed.yar");
        let res = signature_for_files(&[phantom]);
        assert!(res.is_err());
    }

    #[test]
    fn signature_is_deterministic_across_input_orderings() {
        let td = TempDir::new().unwrap();
        let a = write(td.path(), "a.yar", "rule a { condition: true }");
        let b = write(td.path(), "b.yar", "rule b { condition: true }");
        let c = write(td.path(), "c.yar", "rule c { condition: true }");
        let s1 = signature_for_files(&[a.clone(), b.clone(), c.clone()]).unwrap();
        let s2 = signature_for_files(&[c, a, b]).unwrap();
        assert_eq!(
            s1, s2,
            "BTreeMap key ordering should canonicalise the result"
        );
    }
}
