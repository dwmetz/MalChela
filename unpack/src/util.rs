use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{:02x}", x)).collect()
}

/// Join an archive-supplied relative name onto `base`, refusing absolute
/// paths, `..`, drive prefixes, and NUL bytes. Backslashes are treated as
/// separators (Windows-built archives).
pub fn safe_join(base: &Path, raw: &str) -> Option<PathBuf> {
    let cleaned: String = raw.chars().filter(|&c| c != '\0').collect::<String>().replace('\\', "/");
    let trimmed = cleaned.trim_start_matches('/');
    let mut out = base.to_path_buf();
    let mut any = false;
    for c in Path::new(trimmed).components() {
        match c {
            Component::Normal(p) => {
                out.push(p);
                any = true;
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    if any {
        Some(out)
    } else {
        None
    }
}

/// `dir/name`, or `dir/name_2`, `dir/name_3`... if taken.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 2.. {
        let c = dir.join(format!("{}_{}{}", stem, n, ext));
        if !c.exists() {
            return c;
        }
    }
    unreachable!()
}

pub fn file_stem(p: &Path) -> String {
    p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "sample".into())
}

/// Running cap on total bytes written across a whole unpack run — the
/// zip-bomb guard. Every handler spends from the same budget.
#[derive(Debug)]
pub struct Budget {
    limit: u64,
    used: u64,
}

impl Budget {
    pub fn new(limit: u64) -> Self {
        Budget { limit, used: 0 }
    }
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
    pub fn exhausted(&self) -> bool {
        self.used >= self.limit
    }
    pub fn spend(&mut self, n: u64) {
        self.used = self.used.saturating_add(n);
    }
    pub fn used(&self) -> u64 {
        self.used
    }
}

pub fn walk_files(dir: &Path, out: &mut Vec<PathBuf>, limit: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        if out.len() >= limit {
            return;
        }
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk_files(&p, out, limit);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_traversal() {
        let base = Path::new("/tmp/x");
        assert!(safe_join(base, "../etc/passwd").is_none());
        assert!(safe_join(base, "a/../../b").is_none());
        assert!(safe_join(base, "").is_none());
        assert_eq!(safe_join(base, "/abs/file").unwrap(), Path::new("/tmp/x/abs/file"));
        assert_eq!(safe_join(base, "dir\\file.pyc").unwrap(), Path::new("/tmp/x/dir/file.pyc"));
    }
}
