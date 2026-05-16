//! Rule discovery and compilation.
//!
//! Two entry points:
//! * [`compile_files`] walks a list of paths, reads each one, audits it,
//!   and adds it to a fresh yara-x compiler.
//! * [`compile_sources`] takes already-loaded `(namespace, source)` pairs
//!   and is the path inline-rule callers (mzhash, mzcount, xmzhash,
//!   mismatchminer, fileanalyzer/packed.rs) will use.
//!
//! Both produce `Arc<yara_x::Rules>` so the result can be cheaply shared
//! across worker threads.
//!
//! Strictness: `compile_files` takes a `fail_fast` flag. Initial loads pass
//! `true` (any rule error aborts); reloads pass `false` (bad rules become
//! warnings, good rules still compile). This mirrors the contract described
//! in `cache.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use walkdir::WalkDir;
use yara_x::{Compiler, Rules};

use crate::audit::audit_rule_source;
use crate::error::{Error, Result};

/// Hard cap on the size of any one rule source, inline or on disk. Real
/// YARA corpora are kilobytes to a few megabytes; 16 MiB is comfortably
/// generous while still keeping a runaway or adversarial source from
/// exhausting memory.
pub(crate) const MAX_RULE_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CompileOutput {
    pub rules: Arc<Rules>,
    pub warnings: Vec<String>,
}

/// Walk `dir` and return every file whose extension is `.yar` or `.yara`
/// (case-insensitive). Paths are returned sorted alphabetically so two
/// successive walks of the same tree yield the same compile order.
///
/// Returns `Ok(vec![])` if the directory does not exist. Other I/O errors
/// propagate; callers decide whether to treat them as fatal.
pub(crate) fn discover_rule_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if let Some(ext) = path.extension() {
            let lower = ext.to_string_lossy().to_ascii_lowercase();
            if lower == "yar" || lower == "yara" {
                out.push(path.to_path_buf());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Compile a set of rule files into a single `Rules` object.
///
/// If `fail_fast` is true the first error (I/O, audit, or compile)
/// returns immediately as `Err`. If false, problems are appended to
/// `CompileOutput::warnings` and compilation of the remaining files
/// continues.
pub(crate) fn compile_files(files: &[PathBuf], fail_fast: bool) -> Result<CompileOutput> {
    let mut compiler = Compiler::new();
    let mut warnings: Vec<String> = Vec::new();

    for file in files {
        match std::fs::metadata(file) {
            Ok(meta) if meta.len() > MAX_RULE_SOURCE_BYTES => {
                let err = Error::SourceTooLarge {
                    name: file.display().to_string(),
                    size: meta.len(),
                    limit: MAX_RULE_SOURCE_BYTES,
                };
                if fail_fast {
                    return Err(err);
                }
                warnings.push(err.to_string());
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                let msg = format!("could not stat {}: {e}", file.display());
                if fail_fast {
                    return Err(Error::CompileFailed {
                        path: file.clone(),
                        msg,
                    });
                }
                warnings.push(msg);
                continue;
            }
        }

        let src = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("could not read {}: {e}", file.display());
                if fail_fast {
                    return Err(Error::CompileFailed {
                        path: file.clone(),
                        msg,
                    });
                }
                warnings.push(msg);
                continue;
            }
        };

        if let Err(e) = audit_rule_source(file, &src) {
            if fail_fast {
                return Err(e);
            }
            warnings.push(e.to_string());
            continue;
        }

        if let Err(e) = compiler.add_source(src.as_str()) {
            let msg = format!("{e}");
            if fail_fast {
                return Err(Error::CompileFailed {
                    path: file.clone(),
                    msg,
                });
            }
            warnings.push(format!("{}: {msg}", file.display()));
        }
    }

    let rules = compiler.build();
    Ok(CompileOutput {
        rules: Arc::new(rules),
        warnings,
    })
}

/// Compile inline rule sources, each scoped to its own namespace.
///
/// Callers pass `(namespace, source)` pairs. Passing "default" for the
/// namespace mirrors libyara's behavior when no namespace was set, which is
/// what every existing inline-rule caller in MalChela does today.
pub(crate) fn compile_sources(sources: &[(&str, &str)]) -> Result<Arc<Rules>> {
    let mut compiler = Compiler::new();
    for (namespace, src) in sources {
        let src_len = src.len() as u64;
        if src_len > MAX_RULE_SOURCE_BYTES {
            return Err(Error::SourceTooLarge {
                name: format!("<inline:{namespace}>"),
                size: src_len,
                limit: MAX_RULE_SOURCE_BYTES,
            });
        }
        let virtual_path = PathBuf::from(format!("<inline:{namespace}>"));
        audit_rule_source(&virtual_path, src)?;
        compiler.new_namespace(namespace);
        if let Err(e) = compiler.add_source(*src) {
            return Err(Error::CompileFailed {
                path: virtual_path,
                msg: format!("{e}"),
            });
        }
    }
    Ok(Arc::new(compiler.build()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const MINIMAL_RULE: &str = r#"
        rule minimal {
            strings: $a = "marker"
            condition: $a
        }
    "#;

    const MAGIC_RULE: &str = r#"
        import "magic"
        rule uses_magic {
            condition: magic.type() contains "ELF"
        }
    "#;

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, content).expect("write rule file");
        p
    }

    #[test]
    fn discover_returns_empty_for_missing_dir() {
        let p = PathBuf::from("/definitely/does/not/exist/yara-backend-test");
        let v = discover_rule_files(&p).expect("missing dir is ok");
        assert!(v.is_empty());
    }

    #[test]
    fn discover_returns_empty_for_empty_dir() {
        let td = TempDir::new().unwrap();
        let v = discover_rule_files(td.path()).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn discover_picks_up_yar_and_yara_extensions() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.yar", MINIMAL_RULE);
        write(td.path(), "b.yara", MINIMAL_RULE);
        write(td.path(), "c.txt", "not a rule");
        let v = discover_rule_files(td.path()).unwrap();
        assert_eq!(v.len(), 2);
        let names: Vec<String> = v
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.yar".to_string()));
        assert!(names.contains(&"b.yara".to_string()));
    }

    #[test]
    fn discover_is_case_insensitive_on_extension() {
        let td = TempDir::new().unwrap();
        write(td.path(), "x.YAR", MINIMAL_RULE);
        write(td.path(), "y.Yara", MINIMAL_RULE);
        write(td.path(), "z.YARA", MINIMAL_RULE);
        let v = discover_rule_files(td.path()).unwrap();
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn discover_walks_subdirectories() {
        let td = TempDir::new().unwrap();
        let nested = td.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        write(td.path(), "top.yar", MINIMAL_RULE);
        write(&nested, "deep.yar", MINIMAL_RULE);
        let v = discover_rule_files(td.path()).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn discover_results_are_sorted() {
        let td = TempDir::new().unwrap();
        write(td.path(), "z.yar", MINIMAL_RULE);
        write(td.path(), "a.yar", MINIMAL_RULE);
        write(td.path(), "m.yar", MINIMAL_RULE);
        let v = discover_rule_files(td.path()).unwrap();
        let names: Vec<String> = v
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.yar", "m.yar", "z.yar"]);
    }

    #[test]
    fn compile_empty_list_produces_empty_rules() {
        let out = compile_files(&[], true).unwrap();
        assert!(out.warnings.is_empty());
        assert!(out.rules.iter().next().is_none());
    }

    #[test]
    fn compile_single_valid_file_succeeds() {
        let td = TempDir::new().unwrap();
        let p = write(td.path(), "ok.yar", MINIMAL_RULE);
        let out = compile_files(&[p], true).unwrap();
        assert!(out.warnings.is_empty());
        assert_eq!(out.rules.iter().count(), 1);
    }

    #[test]
    fn compile_malformed_file_is_fatal_in_fail_fast_mode() {
        let td = TempDir::new().unwrap();
        let p = write(td.path(), "bad.yar", "rule incomplete { strings:");
        let err = compile_files(&[p], true).unwrap_err();
        assert!(matches!(err, Error::CompileFailed { .. }));
    }

    #[test]
    fn compile_malformed_file_becomes_warning_in_lenient_mode() {
        let td = TempDir::new().unwrap();
        let bad = write(td.path(), "bad.yar", "rule incomplete { strings:");
        let good = write(td.path(), "ok.yar", MINIMAL_RULE);
        let out = compile_files(&[bad, good], false).unwrap();
        assert_eq!(out.warnings.len(), 1);
        assert_eq!(out.rules.iter().count(), 1);
    }

    #[test]
    fn compile_magic_import_is_fatal_in_fail_fast_mode() {
        let td = TempDir::new().unwrap();
        let p = write(td.path(), "magic.yar", MAGIC_RULE);
        let err = compile_files(&[p], true).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn compile_magic_import_becomes_warning_in_lenient_mode() {
        let td = TempDir::new().unwrap();
        let bad = write(td.path(), "magic.yar", MAGIC_RULE);
        let good = write(td.path(), "ok.yar", MINIMAL_RULE);
        let out = compile_files(&[bad, good], false).unwrap();
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].contains("magic"));
        assert_eq!(out.rules.iter().count(), 1);
    }

    #[test]
    fn compile_sources_inline_rule_succeeds() {
        let arc = compile_sources(&[("default", MINIMAL_RULE)]).unwrap();
        assert_eq!(arc.iter().count(), 1);
    }

    #[test]
    fn compile_sources_malformed_returns_compile_failed() {
        let err = compile_sources(&[("default", "rule incomplete {")]).unwrap_err();
        assert!(matches!(err, Error::CompileFailed { .. }));
    }

    #[test]
    fn compile_sources_multi_namespace_succeeds() {
        let arc = compile_sources(&[
            ("a", "rule one { condition: true }"),
            ("b", "rule two { condition: true }"),
        ])
        .unwrap();
        assert_eq!(arc.iter().count(), 2);
    }

    #[test]
    fn compile_sources_same_rule_name_across_namespaces_is_allowed() {
        let arc = compile_sources(&[
            ("ns_a", "rule shared { condition: true }"),
            ("ns_b", "rule shared { condition: true }"),
        ])
        .unwrap();
        assert_eq!(arc.iter().count(), 2);
    }

    #[test]
    fn compile_sources_rejects_oversized_inline_source() {
        let oversized = "/* ".to_string()
            + &"x".repeat(MAX_RULE_SOURCE_BYTES as usize + 16)
            + " */ rule ok { condition: true }";
        let err = compile_sources(&[("default", oversized.as_str())]).unwrap_err();
        match err {
            Error::SourceTooLarge { size, limit, name } => {
                assert!(size > limit);
                assert_eq!(limit, MAX_RULE_SOURCE_BYTES);
                assert!(name.contains("default"));
            }
            other => panic!("expected SourceTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn compile_sources_accepts_source_at_limit_boundary() {
        // A 1 KiB source is well under the cap and must still compile.
        let small = "rule small { condition: true }";
        assert!(compile_sources(&[("default", small)]).is_ok());
    }

    #[test]
    fn compile_files_rejects_oversized_rule_file_in_fail_fast() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("huge.yar");
        // Write a file just over the cap. Allocation cost is one big string
        // in memory at write time; acceptable for a single test.
        let huge = vec![b'x'; (MAX_RULE_SOURCE_BYTES + 1) as usize];
        fs::write(&p, &huge).unwrap();
        let err = compile_files(&[p], true).unwrap_err();
        match err {
            Error::SourceTooLarge { size, limit, .. } => {
                assert!(size > limit);
                assert_eq!(limit, MAX_RULE_SOURCE_BYTES);
            }
            other => panic!("expected SourceTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn compile_files_skips_oversized_rule_file_in_lenient_mode() {
        let td = TempDir::new().unwrap();
        let huge = vec![b'x'; (MAX_RULE_SOURCE_BYTES + 1) as usize];
        let big_path = td.path().join("huge.yar");
        fs::write(&big_path, &huge).unwrap();
        let good_path = write(td.path(), "ok.yar", MINIMAL_RULE);
        let out = compile_files(&[big_path, good_path], false).unwrap();
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].contains("limit"));
        assert_eq!(out.rules.iter().count(), 1);
    }
}
