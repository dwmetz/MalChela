//! Error types surfaced by yara-backend.
//!
//! Every variant carries enough context for a caller to render a useful
//! message without consulting other state (which path failed, which target
//! was being scanned, what the underlying engine said).

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("YARA: failed to load rules from {}: {reason}", dir.display())]
    LoadRules { dir: PathBuf, reason: String },

    #[error("YARA: rule file {} failed to compile: {msg}", path.display())]
    CompileFailed { path: PathBuf, msg: String },

    #[error("YARA: rule file {} uses unsupported module `{module}`; rewrite or remove the rule", path.display())]
    UnsupportedModule { path: PathBuf, module: String },

    #[error("YARA: rule source `{name}` is {size} bytes; the limit is {limit} bytes")]
    SourceTooLarge { name: String, size: u64, limit: u64 },

    #[error("YARA: scan input `{target}` is {size} bytes; the limit is {limit} bytes")]
    ScanInputTooLarge {
        target: String,
        size: u64,
        limit: u64,
    },

    #[error("YARA: scan failed on {target}: {reason}")]
    ScanFailed { target: String, reason: String },

    #[error("YARA: scan timed out on {target} after {elapsed:?}")]
    Timeout { target: String, elapsed: Duration },

    #[error("YARA: rules directory disappeared: {}", dir.display())]
    RulesDirGone { dir: PathBuf },

    #[error("YARA: failed to acquire compile lock within {0:?}")]
    CompileLockTimeout(Duration),

    #[error("YARA: I/O error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn display_load_rules_includes_path_and_reason() {
        let err = Error::LoadRules {
            dir: PathBuf::from("/tmp/rules"),
            reason: "permission denied".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("/tmp/rules"), "expected path in: {s}");
        assert!(s.contains("permission denied"), "expected reason in: {s}");
    }

    #[test]
    fn display_compile_failed_includes_path_and_msg() {
        let err = Error::CompileFailed {
            path: PathBuf::from("rules/bad.yar"),
            msg: "syntax error at line 3".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("bad.yar"), "expected path in: {s}");
        assert!(s.contains("syntax error at line 3"), "expected msg in: {s}");
    }

    #[test]
    fn display_unsupported_module_names_the_module() {
        let err = Error::UnsupportedModule {
            path: PathBuf::from("rules/uses_magic.yar"),
            module: "magic".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("magic"), "expected module name in: {s}");
        assert!(s.contains("uses_magic.yar"), "expected path in: {s}");
    }

    #[test]
    fn display_timeout_shows_duration_and_target() {
        let err = Error::Timeout {
            target: "sample.bin".to_string(),
            elapsed: Duration::from_secs(5),
        };
        let s = err.to_string();
        assert!(s.contains("sample.bin"), "expected target in: {s}");
        assert!(s.contains("5"), "expected duration digits in: {s}");
    }

    #[test]
    fn display_compile_lock_timeout_shows_deadline() {
        let err = Error::CompileLockTimeout(Duration::from_secs(5));
        let s = err.to_string();
        assert!(s.contains("5"), "expected deadline in: {s}");
    }

    #[test]
    fn from_io_error_round_trips_through_source_chain() {
        let io = io::Error::new(io::ErrorKind::NotFound, "missing");
        let err: Error = io.into();
        match err {
            Error::Io { source } => assert_eq!(source.kind(), io::ErrorKind::NotFound),
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    #[test]
    fn errors_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
        assert_send_sync::<Result<()>>();
    }
}
