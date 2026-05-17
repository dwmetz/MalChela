//! Pre-compile audit for rule sources.
//!
//! yara-x does not implement every libyara import module. Rules that use
//! `import "magic"` (and a small handful of similar gaps) will refuse to
//! compile under yara-x with a low level error. We do a cheap source level
//! audit first so callers see a clear, named error instead of the engine's
//! diagnostic, and so the same finding can be surfaced by the companion
//! `tools/audit_yara_rules.sh` script during a CI pre-build hook.
//!
//! The audit walks the source as a single byte stream rather than line by
//! line. yara-x's parser is whitespace insensitive between tokens, so
//! `import "magic"` and `import\n"magic"` (or with a block comment in the
//! middle) parse the same way. The audit therefore tokenises lightly:
//!
//! * `/* ... */` block comments are stripped first so a commented-out
//!   import is never flagged.
//! * `//` line comments are skipped during the walk.
//! * String literals inside rule bodies are skipped so a rule whose
//!   condition string happens to contain the substring `import` cannot
//!   produce a false positive.
//! * `import` is matched as a whole word (no false hits on
//!   `important_var` or `$import_thing`).
//! * Any amount of whitespace, including newlines, may sit between the
//!   `import` keyword and the quoted module name.
//! * String escapes inside the quoted module name (`\xHH`, `\n`, `\t`,
//!   `\\`, `\"`, `\'`) are decoded before the comparison so that
//!   `import "ma\x67ic"` is recognised as `import "magic"`.
//!
//! Anything more involved (preprocessor tricks, exotic Unicode, etc.) is
//! out of scope; yara-x will still refuse such rules at compile time and
//! the wrapper surfaces the engine's error.

use std::path::Path;

use crate::error::{Error, Result};

/// Modules that yara-x does not currently implement. Adding a module to this
/// list means rule files mentioning it will be rejected at load time with a
/// clear error rather than a low level engine diagnostic.
pub(crate) const FORBIDDEN_IMPORTS: &[&str] = &["magic"];

const IMPORT_KEYWORD: &[u8] = b"import";

pub(crate) fn audit_rule_source(path: &Path, src: &str) -> Result<()> {
    let stripped = strip_block_comments(src);
    let bytes = stripped.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Line comment runs to end of line.
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // A string literal inside a rule body could otherwise contain the
        // substring `import`; skip it as one token so we don't false-flag.
        if b == b'"' || b == b'\'' {
            i = skip_string_literal(bytes, i, b);
            continue;
        }

        // Whole-word match for `import`.
        if matches_keyword(bytes, i, IMPORT_KEYWORD) {
            let after_keyword = i + IMPORT_KEYWORD.len();
            let j = skip_ws_and_line_comments(bytes, after_keyword);
            if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                let quote = bytes[j];
                if let Some((module, end)) = read_quoted_module(bytes, j + 1, quote) {
                    for forbidden in FORBIDDEN_IMPORTS {
                        if module == *forbidden {
                            return Err(Error::UnsupportedModule {
                                path: path.to_path_buf(),
                                module: (*forbidden).to_string(),
                            });
                        }
                    }
                    i = end;
                    continue;
                }
            }
            i = after_keyword;
            continue;
        }

        i += 1;
    }
    Ok(())
}

/// Advance past ASCII whitespace and `//` line comments. Block comments
/// have already been stripped from the source before the walker starts.
fn skip_ws_and_line_comments(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        break;
    }
    i
}

fn matches_keyword(bytes: &[u8], start: usize, kw: &[u8]) -> bool {
    let end = start + kw.len();
    if end > bytes.len() || &bytes[start..end] != kw {
        return false;
    }
    let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
    let after_ok = end == bytes.len() || !is_ident_byte(bytes[end]);
    before_ok && after_ok
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_string_literal(bytes: &[u8], start: usize, quote: u8) -> usize {
    debug_assert_eq!(bytes[start], quote);
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

/// Read a quoted module string starting just after the opening quote.
/// Returns the decoded module name and the byte index immediately after the
/// closing quote.
fn read_quoted_module(bytes: &[u8], start: usize, quote: u8) -> Option<(String, usize)> {
    let mut decoded = String::new();
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if c == quote {
            return Some((decoded, i + 1));
        }
        if c == b'\\' && i + 1 < bytes.len() {
            let escape = bytes[i + 1];
            i += 2;
            match escape {
                b'x' => {
                    if i + 1 >= bytes.len() {
                        return None;
                    }
                    let hex = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
                    let value = u8::from_str_radix(hex, 16).ok()?;
                    decoded.push(value as char);
                    i += 2;
                }
                b'n' => decoded.push('\n'),
                b't' => decoded.push('\t'),
                b'r' => decoded.push('\r'),
                b'\\' => decoded.push('\\'),
                b'"' => decoded.push('"'),
                b'\'' => decoded.push('\''),
                other => {
                    decoded.push('\\');
                    decoded.push(other as char);
                }
            }
            continue;
        }
        decoded.push(c as char);
        i += 1;
    }
    None
}

fn strip_block_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                break;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_with_only_supported_imports_passes() {
        let src = r#"
            import "pe"
            import "hash"
            rule supported {
                strings: $a = "test"
                condition: $a
            }
        "#;
        assert!(audit_rule_source(Path::new("supported.yar"), src).is_ok());
    }

    #[test]
    fn double_quoted_magic_import_is_rejected() {
        let src = "import \"magic\"\nrule bad { condition: magic.type() contains \"ELF\" }";
        let err = audit_rule_source(Path::new("bad.yar"), src).unwrap_err();
        match err {
            Error::UnsupportedModule { module, path } => {
                assert_eq!(module, "magic");
                assert_eq!(path, Path::new("bad.yar"));
            }
            other => panic!("expected UnsupportedModule, got {other:?}"),
        }
    }

    #[test]
    fn single_quoted_magic_import_is_also_rejected() {
        let src = "import 'magic'\nrule bad { condition: true }";
        let err = audit_rule_source(Path::new("bad.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn commented_out_magic_import_is_allowed() {
        let src = "// import \"magic\"  -- left here for reference\nrule ok { condition: true }";
        assert!(audit_rule_source(Path::new("ok.yar"), src).is_ok());
    }

    #[test]
    fn mix_of_imports_reports_the_forbidden_one() {
        let src = r#"
            import "pe"
            import "hash"
            import "magic"
            import "math"
            rule mixed { condition: true }
        "#;
        let err = audit_rule_source(Path::new("mixed.yar"), src).unwrap_err();
        match err {
            Error::UnsupportedModule { module, .. } => assert_eq!(module, "magic"),
            other => panic!("expected UnsupportedModule, got {other:?}"),
        }
    }

    #[test]
    fn empty_source_passes() {
        assert!(audit_rule_source(Path::new("empty.yar"), "").is_ok());
    }

    #[test]
    fn whitespace_only_source_passes() {
        assert!(audit_rule_source(Path::new("ws.yar"), "   \n\t\n  ").is_ok());
    }

    // Regression: previous version flagged block-commented imports as if they
    // were real. yara-x ignores block comments, so the audit must too.
    #[test]
    fn block_commented_magic_import_is_allowed() {
        let src = "/* import \"magic\" */\nrule ok { condition: true }";
        assert!(audit_rule_source(Path::new("ok.yar"), src).is_ok());
    }

    #[test]
    fn multi_line_block_commented_magic_import_is_allowed() {
        let src = "/*\n  import \"magic\"\n*/\nrule ok { condition: true }";
        assert!(audit_rule_source(Path::new("ok.yar"), src).is_ok());
    }

    // Regression: previous version missed hex-escaped module names. yara-x
    // decodes \xHH in string literals, so the audit must decode too.
    #[test]
    fn hex_escaped_magic_import_is_rejected() {
        let src = "import \"ma\\x67ic\"\nrule bypass { condition: true }";
        let err = audit_rule_source(Path::new("bypass.yar"), src).unwrap_err();
        match err {
            Error::UnsupportedModule { module, .. } => assert_eq!(module, "magic"),
            other => panic!("expected UnsupportedModule, got {other:?}"),
        }
    }

    #[test]
    fn fully_hex_escaped_magic_import_is_rejected() {
        let src = "import \"\\x6d\\x61\\x67\\x69\\x63\"\nrule bypass { condition: true }";
        let err = audit_rule_source(Path::new("bypass.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn escaped_quote_inside_module_name_does_not_panic() {
        // `import "ma\"gic"` (a quote inside the module name) does not match
        // `magic` after decoding; should pass the audit.
        let src = "import \"ma\\\"gic\"\nrule ok { condition: true }";
        assert!(audit_rule_source(Path::new("ok.yar"), src).is_ok());
    }

    // Regression: previous line-by-line implementation missed
    // `import\n"magic"` because the keyword and the string sat on different
    // lines. yara-x's parser is whitespace insensitive so this audit must be
    // too.
    #[test]
    fn newline_between_import_and_module_string_is_rejected() {
        let src = "import\n\"magic\"\nrule x { condition: true }";
        let err = audit_rule_source(Path::new("split.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn carriage_return_newline_between_import_and_module_string_is_rejected() {
        let src = "import\r\n\"magic\"\nrule x { condition: true }";
        let err = audit_rule_source(Path::new("crlf.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn block_comment_between_import_and_module_string_is_rejected() {
        let src = "import /* hidden */ \"magic\"\nrule x { condition: true }";
        let err = audit_rule_source(Path::new("midcomment.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn multi_line_block_comment_between_import_and_module_string_is_rejected() {
        let src = "import /*\nignored\n*/ \"magic\"\nrule x { condition: true }";
        let err = audit_rule_source(Path::new("midmulti.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    #[test]
    fn line_comment_between_import_keyword_and_string_is_rejected() {
        let src = "import // skip me\n\"magic\"\nrule x { condition: true }";
        let err = audit_rule_source(Path::new("midline.yar"), src).unwrap_err();
        assert!(matches!(err, Error::UnsupportedModule { .. }));
    }

    // The substring `import` appearing inside an identifier (e.g.
    // `important_var`) or a string literal must NOT trigger the audit.
    #[test]
    fn import_substring_inside_identifier_does_not_false_flag() {
        let src = "rule x { strings: $important_marker = \"magic\" condition: $important_marker }";
        assert!(audit_rule_source(Path::new("subid.yar"), src).is_ok());
    }

    #[test]
    fn import_substring_inside_string_literal_does_not_false_flag() {
        let src = "rule x { strings: $s = \"please import \\\"magic\\\"\" condition: $s }";
        assert!(audit_rule_source(Path::new("substr.yar"), src).is_ok());
    }

    #[test]
    fn import_substring_inside_single_quoted_literal_does_not_false_flag() {
        let src = "rule x { strings: $s = \"import 'magic' here\" condition: $s }";
        assert!(audit_rule_source(Path::new("substr2.yar"), src).is_ok());
    }

    #[test]
    fn import_after_a_dot_identifier_does_not_false_flag() {
        // `foo.import` shouldn't match because the `import` is not at a
        // word boundary on the left.
        let src = "rule x { condition: pe.imports(\"magic\") }";
        assert!(audit_rule_source(Path::new("dot.yar"), src).is_ok());
    }

    #[test]
    fn unterminated_import_string_does_not_panic() {
        // A rule with a malformed import shouldn't crash the audit; yara-x
        // will surface the real syntax error.
        let src = "import \"magic\nrule bad { condition: true }";
        let _ = audit_rule_source(Path::new("bad.yar"), src);
    }

    #[test]
    fn truncated_block_comment_does_not_loop_forever() {
        let src = "/* never closed\nrule should_be_swallowed { condition: true }";
        let _ = audit_rule_source(Path::new("bad.yar"), src);
    }

    #[test]
    fn strip_block_comments_preserves_line_numbers() {
        let src = "rule a {}\n/* hidden\nstuff\nhere */rule b {}";
        let stripped = strip_block_comments(src);
        assert_eq!(stripped.lines().count(), 4);
    }
}
