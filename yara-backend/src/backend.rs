//! YaraBackend — the public facade.
//!
//! Two constructors:
//! * [`YaraBackend::load_from_dir`] for rule directories (used by
//!   fileanalyzer's yara_scan path).
//! * [`YaraBackend::from_inline_sources`] for callers that ship rules as
//!   string constants (mzhash, mzcount, xmzhash, mismatchminer, and
//!   fileanalyzer/packed.rs).
//!
//! Scanning is via [`YaraBackend::scan_file`] or [`YaraBackend::scan_bytes`].
//! Both internally call [`YaraBackend::reload_if_changed`] so the hot-reload
//! contract is preserved without callers needing to track signatures.
//!
//! Concurrency: cheap to clone (`Arc`-backed); safe to share across worker
//! threads. Each scan allocates a fresh `yara_x::Scanner` from the cached
//! `Arc<Rules>`, which keeps multi-thread scans lock-free on the read path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

use crate::cache::{self, CacheState, DirSignature};
use crate::compile;
use crate::error::{Error, Result};
use crate::match_types::ScanReport;
use crate::scan;

#[derive(Debug)]
pub struct YaraBackend {
    rules_dir: Option<PathBuf>,
    state: Arc<RwLock<CacheState>>,
}

impl YaraBackend {
    /// Build a backend by walking a directory of `.yar`/`.yara` files.
    ///
    /// Returns `Err(LoadRules)` if the directory does not exist or cannot
    /// be walked. Returns `Err(CompileFailed)` or `Err(UnsupportedModule)`
    /// if any rule fails to compile (initial load is fail-fast).
    pub fn load_from_dir<P: AsRef<Path>>(rules_dir: P) -> Result<Self> {
        let dir = rules_dir.as_ref().to_path_buf();
        if !dir.exists() {
            return Err(Error::LoadRules {
                dir,
                reason: "directory does not exist".to_string(),
            });
        }
        let files = compile::discover_rule_files(&dir).map_err(|e| Error::LoadRules {
            dir: dir.clone(),
            reason: format!("{e}"),
        })?;
        let signature = cache::signature_for_files(&files).map_err(|e| Error::LoadRules {
            dir: dir.clone(),
            reason: format!("{e}"),
        })?;
        let output = compile::compile_files(&files, true)?;
        let n = output.rules.iter().count();
        log::info!("yara-backend loaded {n} rule(s) from {}", dir.display());
        let state = CacheState {
            signature,
            rules: output.rules,
            compile_warnings: output.warnings,
        };
        Ok(YaraBackend {
            rules_dir: Some(dir),
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Build a backend from inline `(namespace, source)` pairs.
    ///
    /// Intended for compile time string constants shipped inside a
    /// caller crate (e.g. the inline rules in `mzhash`, `mzcount`,
    /// `xmzhash`, `mismatchminer`, and `fileanalyzer/packed.rs`).
    ///
    /// Each source is capped at 16 MiB; passing something larger
    /// returns [`Error::SourceTooLarge`] without touching the engine.
    pub fn from_inline_sources(sources: &[(&str, &str)]) -> Result<Self> {
        let rules = compile::compile_sources(sources)?;
        let n = rules.iter().count();
        log::debug!(
            "yara-backend loaded {n} inline rule(s) from {} source(s)",
            sources.len()
        );
        let state = CacheState {
            signature: DirSignature::new(),
            rules,
            compile_warnings: Vec::new(),
        };
        Ok(YaraBackend {
            rules_dir: None,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Re-walk the rules directory and recompile if anything changed.
    ///
    /// Returns `Ok(true)` if a recompile happened, `Ok(false)` if no change
    /// was detected. Returns `Ok(false)` immediately for inline-source
    /// backends. On a successful recompile, individual bad rules become
    /// warnings on `ScanReport::compile_warnings` rather than aborting.
    pub fn reload_if_changed(&self) -> Result<bool> {
        let Some(dir) = self.rules_dir.as_ref() else {
            return Ok(false);
        };
        if !dir.exists() {
            return Err(Error::RulesDirGone { dir: dir.clone() });
        }
        let files = compile::discover_rule_files(dir).map_err(|e| Error::LoadRules {
            dir: dir.clone(),
            reason: format!("{e}"),
        })?;
        let new_sig = cache::signature_for_files(&files).map_err(|e| Error::LoadRules {
            dir: dir.clone(),
            reason: format!("{e}"),
        })?;
        {
            let state = self.state.read();
            if state.signature == new_sig {
                return Ok(false);
            }
        }
        let output = compile::compile_files(&files, false)?;
        let new_count = output.rules.iter().count();
        let deadline = Duration::from_secs(5);
        let mut state = self
            .state
            .try_write_for(deadline)
            .ok_or(Error::CompileLockTimeout(deadline))?;
        let prior_count = state.rules.iter().count();
        // Defense in depth: if every file failed to compile (output is empty
        // and warnings are present) but we had a working rule set before,
        // keep the prior rules so a typo'd edit can't cause a silent
        // detection blackout. The signature is still updated so we do not
        // re-attempt the failing compile on every scan.
        if new_count == 0 && !output.warnings.is_empty() && prior_count > 0 {
            log::warn!(
                "yara-backend reload produced 0 rules; keeping {prior_count} prior rule(s). Warnings: {:?}",
                output.warnings
            );
            state.signature = new_sig;
            state.compile_warnings = output.warnings;
            return Ok(true);
        }
        log::info!(
            "yara-backend reloaded {new_count} rule(s) from {}",
            dir.display()
        );
        *state = CacheState {
            signature: new_sig,
            rules: output.rules,
            compile_warnings: output.warnings,
        };
        Ok(true)
    }

    /// Scan a file. Pass `Duration::ZERO` to disable the timeout.
    ///
    /// The file is capped at 256 MiB; anything larger returns
    /// [`Error::ScanInputTooLarge`] before yara-x is invoked.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P, timeout: Duration) -> Result<ScanReport> {
        if let Err(e) = self.reload_if_changed() {
            log::warn!("yara-backend reload failed: {e}; continuing with cached rules");
        }
        let (rules_arc, warnings) = {
            let state = self.state.read();
            (state.rules.clone(), state.compile_warnings.clone())
        };
        let path = path.as_ref();
        let target = path.display().to_string();
        scan::scan_file_with(&rules_arc, path, timeout, &target, warnings)
    }

    /// Scan a byte buffer. Pass `Duration::ZERO` to disable the timeout.
    ///
    /// The buffer is capped at 256 MiB; passing something larger
    /// returns [`Error::ScanInputTooLarge`] without touching the
    /// engine. Each call allocates a fresh short lived
    /// `yara_x::Scanner`; high fan out workloads (eg `par_iter` over
    /// thousands of small samples) are supported by design but the
    /// per scan allocation cost is real and is caller visible.
    pub fn scan_bytes(&self, data: &[u8], timeout: Duration) -> Result<ScanReport> {
        if let Err(e) = self.reload_if_changed() {
            log::warn!("yara-backend reload failed: {e}; continuing with cached rules");
        }
        let (rules_arc, warnings) = {
            let state = self.state.read();
            (state.rules.clone(), state.compile_warnings.clone())
        };
        scan::scan_bytes_with(&rules_arc, data, timeout, "<buffer>", warnings)
    }

    /// Count of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.state.read().rules.iter().count()
    }

    /// Compiled rule names, in arbitrary order.
    pub fn rule_names(&self) -> Vec<String> {
        self.state
            .read()
            .rules
            .iter()
            .map(|r| r.identifier().to_string())
            .collect()
    }

    /// Compile warnings produced during the most recent (re)load.
    pub fn compile_warnings(&self) -> Vec<String> {
        self.state.read().compile_warnings.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const MINIMAL: &str = "rule r1 { condition: true }";
    const MZ: &str = r#"
        rule mz_header {
            strings: $mz = { 4D 5A }
            condition: $mz at 0
        }
    "#;

    fn mz_buf() -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = 0x4D;
        v[1] = 0x5A;
        v
    }

    #[test]
    fn load_from_dir_empty_dir_succeeds() {
        let td = TempDir::new().unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        assert_eq!(b.rule_count(), 0);
    }

    #[test]
    fn load_from_dir_missing_dir_errors_out() {
        let phantom = std::path::Path::new("/never/exists/yara-backend-test");
        let err = YaraBackend::load_from_dir(phantom).unwrap_err();
        assert!(matches!(err, Error::LoadRules { .. }));
    }

    #[test]
    fn load_from_dir_picks_up_rule_files() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join("a.yar"), MZ).unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        assert_eq!(b.rule_count(), 1);
        assert!(b.rule_names().contains(&"mz_header".to_string()));
    }

    #[test]
    fn load_from_dir_with_malformed_rule_fails_fast() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join("broken.yar"), "rule incomplete { strings:").unwrap();
        let err = YaraBackend::load_from_dir(td.path()).unwrap_err();
        assert!(matches!(err, Error::CompileFailed { .. }));
    }

    #[test]
    fn from_inline_sources_compiles_one_rule() {
        let b = YaraBackend::from_inline_sources(&[("default", MINIMAL)]).unwrap();
        assert_eq!(b.rule_count(), 1);
    }

    #[test]
    fn from_inline_sources_empty_list_succeeds() {
        let b = YaraBackend::from_inline_sources(&[]).unwrap();
        assert_eq!(b.rule_count(), 0);
    }

    #[test]
    fn scan_bytes_returns_match_for_loaded_rule() {
        let b = YaraBackend::from_inline_sources(&[("default", MZ)]).unwrap();
        let r = b.scan_bytes(&mz_buf(), Duration::ZERO).unwrap();
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.rule_names_sorted(), vec!["mz_header"]);
    }

    #[test]
    fn scan_file_returns_match_for_loaded_rule() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("sample.bin");
        fs::write(&p, mz_buf()).unwrap();
        let b = YaraBackend::from_inline_sources(&[("default", MZ)]).unwrap();
        let r = b.scan_file(&p, Duration::ZERO).unwrap();
        assert_eq!(r.matches.len(), 1);
    }

    #[test]
    fn reload_if_changed_returns_false_for_inline_backend() {
        let b = YaraBackend::from_inline_sources(&[("default", MINIMAL)]).unwrap();
        assert!(!b.reload_if_changed().unwrap());
    }

    #[test]
    fn reload_if_changed_returns_false_when_dir_unchanged() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join("a.yar"), MZ).unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        assert!(!b.reload_if_changed().unwrap());
    }

    #[test]
    fn reload_if_changed_returns_true_when_file_added() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join("a.yar"), MZ).unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        assert_eq!(b.rule_count(), 1);
        fs::write(
            td.path().join("b.yar"),
            "rule b { strings: $x = \"x\" condition: $x }",
        )
        .unwrap();
        assert!(b.reload_if_changed().unwrap());
        assert_eq!(b.rule_count(), 2);
    }

    #[test]
    fn reload_if_changed_returns_dir_gone_when_directory_disappears() {
        let td = TempDir::new().unwrap();
        let dir = td.path().to_path_buf();
        fs::write(dir.join("a.yar"), MZ).unwrap();
        let b = YaraBackend::load_from_dir(&dir).unwrap();
        drop(td);
        let err = b.reload_if_changed().unwrap_err();
        assert!(matches!(err, Error::RulesDirGone { .. }));
    }

    #[test]
    fn backend_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<YaraBackend>();
        assert_send_sync::<Arc<YaraBackend>>();
    }

    #[test]
    fn reload_keeps_prior_rules_when_every_file_breaks() {
        use std::fs::OpenOptions;
        use std::time::SystemTime;
        let td = TempDir::new().unwrap();
        let path = td.path().join("a.yar");
        fs::write(&path, MZ).unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        assert_eq!(b.rule_count(), 1);
        // Corrupt the only rule file (incomplete syntax).
        fs::write(&path, "rule broken { strings: $a = \"x\"").unwrap();
        // Bump mtime deterministically so the signature definitely changes.
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(120))
            .unwrap();
        drop(f);
        // Next scan triggers reload. The compile fails, but the prior rule
        // is retained so the scan still matches.
        let r = b.scan_bytes(&mz_buf(), Duration::ZERO).unwrap();
        assert_eq!(
            r.matches.len(),
            1,
            "prior rules must survive a fully-broken reload"
        );
        assert_eq!(b.rule_count(), 1);
        // Warning surfaces so callers can show it to the operator.
        assert!(!b.compile_warnings().is_empty());
    }

    #[test]
    fn reload_to_empty_dir_clears_rules_intentionally() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("a.yar");
        fs::write(&path, MZ).unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        assert_eq!(b.rule_count(), 1);
        // User deliberately removes the rule file (no warning expected).
        fs::remove_file(&path).unwrap();
        let r = b.scan_bytes(&mz_buf(), Duration::ZERO).unwrap();
        assert_eq!(r.matches.len(), 0, "intentional removal should clear rules");
        assert_eq!(b.rule_count(), 0);
        assert!(b.compile_warnings().is_empty());
    }

    #[test]
    fn scan_picks_up_new_rule_dropped_into_dir() {
        let td = TempDir::new().unwrap();
        let b = YaraBackend::load_from_dir(td.path()).unwrap();
        // Initially no rules; scan returns empty.
        let r = b.scan_bytes(&mz_buf(), Duration::ZERO).unwrap();
        assert_eq!(r.matches.len(), 0);
        // Drop a rule into the dir.
        fs::write(td.path().join("mz.yar"), MZ).unwrap();
        // Next scan picks it up via the auto reload.
        let r = b.scan_bytes(&mz_buf(), Duration::ZERO).unwrap();
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.rule_names_sorted(), vec!["mz_header"]);
    }
}
