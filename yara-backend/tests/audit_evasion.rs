//! Audit-evasion regression tests.
//!
//! These exercise corner cases an adversarial rule author might try when
//! sneaking a yara-x-incompatible module past the pre-compile audit. The
//! audit runs on both file-based and inline rule sources, and the evasion
//! attempts that yara-x's own parser would still catch are documented as
//! such (defense in depth).

use yara_backend::{Error, YaraBackend};

fn assert_unsupported_magic(res: Result<YaraBackend, Error>) {
    match res {
        Err(Error::UnsupportedModule { module, .. }) if module == "magic" => {}
        Err(other) => panic!("expected UnsupportedModule(magic), got {other:?}"),
        Ok(_) => panic!("expected audit to reject `magic` import, but compile succeeded"),
    }
}

#[test]
fn inline_audit_blocks_magic_with_extra_spaces() {
    let src = r#"
        import   "magic"
        rule x { condition: true }
    "#;
    assert_unsupported_magic(YaraBackend::from_inline_sources(&[("default", src)]));
}

#[test]
fn inline_audit_blocks_magic_with_tabs() {
    let src = "\timport\t\t\"magic\"\nrule x { condition: true }";
    assert_unsupported_magic(YaraBackend::from_inline_sources(&[("default", src)]));
}

#[test]
fn inline_audit_blocks_magic_via_hex_escape() {
    // \x6D decodes to 'm', so this is `import "magic"` once decoded.
    let src = r#"
        import "\x6Dagic"
        rule x { condition: true }
    "#;
    assert_unsupported_magic(YaraBackend::from_inline_sources(&[("default", src)]));
}

#[test]
fn inline_audit_does_not_false_flag_block_comment_with_magic() {
    let src = r#"
        /* This rule used to `import "magic"` and no longer does. */
        rule benign { condition: true }
    "#;
    assert!(YaraBackend::from_inline_sources(&[("default", src)]).is_ok());
}

#[test]
fn inline_audit_does_not_false_flag_line_comment_with_magic() {
    let src = r#"
        // import "magic"
        rule benign { condition: true }
    "#;
    assert!(YaraBackend::from_inline_sources(&[("default", src)]).is_ok());
}

#[test]
fn capitalised_magic_is_not_silently_accepted() {
    // `Magic` is not a known yara-x module. yara-x will reject this as
    // CompileFailed; we only assert the audit does not let it through
    // as a successful load.
    let src = r#"
        import "Magic"
        rule x { condition: true }
    "#;
    let res = YaraBackend::from_inline_sources(&[("default", src)]);
    assert!(res.is_err(), "capitalised Magic must not load successfully");
}
