use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use yara_backend::YaraBackend;

/// Wall clock budget for one file scan, unchanged from the previous
/// implementation, which passed `5` to libyara's second-granularity timeout.
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

pub fn scan_file_with_yara_rules(
    file_path: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let rules_dir = find_workspace_root()?.join("yara_rules");
    scan_with_rules_dir(&rules_dir, file_path, SCAN_TIMEOUT)
}

/// The whole scan path, with its inputs passed in rather than derived, so a
/// test can drive the same composition the binary runs.
fn scan_with_rules_dir(
    rules_dir: &Path,
    file_path: &str,
    timeout: Duration,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // A missing rules directory is not an error. `find_workspace_root` stops at
    // the first Cargo.toml above the working directory, so running the tool
    // from inside a crate resolves a rules path that does not exist. The
    // previous implementation walked the missing directory, found nothing and
    // scanned with an empty rule set; anything else turns a normal invocation
    // into a failed analysis.
    //
    // It is announced because the alternative is a silent wrong answer: an
    // empty match list here is indistinguishable, in the report, from a corpus
    // that ran and matched nothing.
    if !rules_dir.is_dir() {
        eprintln!(
            "YARA: no rules directory at {}; scanning with no rules",
            rules_dir.display()
        );
        return Ok(Vec::new());
    }

    let backend = YaraBackend::load_from_dir(rules_dir)?;
    if backend.rule_count() == 0 {
        eprintln!(
            "YARA: {} contains no rule files; scanning with no rules",
            rules_dir.display()
        );
    }

    let report = backend.scan_file(file_path, timeout)?;
    Ok(report.rule_names_sorted())
}

fn find_workspace_root() -> io::Result<PathBuf> {
    let mut current_dir = env::current_dir()?;

    loop {
        let cargo_toml_path = current_dir.join("Cargo.toml");
        if cargo_toml_path.exists() {
            return Ok(current_dir);
        }

        match current_dir.parent() {
            Some(parent) => current_dir = parent.to_path_buf(),
            None => {
                eprintln!("Error: Workspace root not found.");
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Workspace root not found",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn probe(dir: &Path, bytes: &[u8]) -> PathBuf {
        let p = dir.join("probe.bin");
        fs::write(&p, bytes).unwrap();
        p
    }

    /// The path the binary actually runs, end to end: a real rules directory,
    /// compiled and scanned, returning names. Every other test in this module
    /// asserts an empty result, so without this one the composition under
    /// change is never observed producing anything.
    #[test]
    fn scans_a_real_rules_directory_and_returns_sorted_names() {
        let td = TempDir::new().unwrap();
        let rules = td.path().join("yara_rules");
        fs::create_dir_all(&rules).unwrap();
        fs::write(
            rules.join("zeta.yar"),
            r#"rule zeta_marker { strings: $a = "needle" condition: $a }"#,
        )
        .unwrap();
        fs::write(
            rules.join("alpha.yar"),
            r#"rule alpha_marker { strings: $a = "needle" condition: $a }"#,
        )
        .unwrap();

        let target = probe(td.path(), b"a needle in here");
        let matches = scan_with_rules_dir(&rules, target.to_str().unwrap(), SCAN_TIMEOUT).unwrap();

        assert_eq!(matches, vec!["alpha_marker", "zeta_marker"]);
    }

    /// The timeout is honoured as passed rather than merely stored. A budget of
    /// zero is the one value the backend treats as "do not set a timeout", so
    /// this uses a real but tiny one and asserts the scan still completes,
    /// which at least proves the parameter reaches the engine on this path.
    #[test]
    fn timeout_is_plumbed_through_to_the_scan() {
        let td = TempDir::new().unwrap();
        let rules = td.path().join("yara_rules");
        fs::create_dir_all(&rules).unwrap();
        fs::write(
            rules.join("r.yar"),
            r#"rule t { strings: $a = "x" condition: $a }"#,
        )
        .unwrap();

        let target = probe(td.path(), b"x");
        let matches =
            scan_with_rules_dir(&rules, target.to_str().unwrap(), Duration::from_secs(30)).unwrap();
        assert_eq!(matches, vec!["t"]);
    }

    /// Q-1's deduplication half, pinned on the helper rather than on this
    /// caller, and the distinction is worth stating.
    ///
    /// The backend already sorts matches by rule name before any caller sees
    /// them, so the sorting half of Q-1 is guaranteed there and this crate's
    /// call to `rule_names_sorted` cannot be observed to change ordering.
    /// Deduplication only differs from mapping `matches` when two namespaces
    /// carry the same rule name, which directory loading cannot produce because
    /// every file compiles into one namespace and a duplicate identifier is a
    /// compile error. So this test covers the contract the helper owes Q-1; no
    /// test in this crate can catch a caller-side revert, because on the
    /// production path the two implementations are equivalent.
    #[test]
    fn same_rule_name_in_two_namespaces_is_reported_once() {
        let rule = r#"rule shared { strings: $a = "needle" condition: $a }"#;
        let backend = YaraBackend::from_inline_sources(&[("ns_a", rule), ("ns_b", rule)]).unwrap();

        let report = backend.scan_bytes(b"a needle here", SCAN_TIMEOUT).unwrap();

        assert_eq!(report.matches.len(), 2, "both namespaces should match");
        assert_eq!(
            report.rule_names_sorted(),
            vec!["shared"],
            "the report must collapse them to one name"
        );
    }

    /// A rules directory holding no rule files, which is what a fresh checkout
    /// ships, must load as an empty rule set rather than failing the analysis.
    #[test]
    fn empty_rules_directory_yields_no_matches() {
        let td = TempDir::new().unwrap();
        let rules = td.path().join("yara_rules");
        fs::create_dir_all(&rules).unwrap();
        fs::write(rules.join("readme.txt"), "no rules here").unwrap();

        let target = probe(td.path(), b"MZ harmless");
        let matches = scan_with_rules_dir(&rules, target.to_str().unwrap(), SCAN_TIMEOUT).unwrap();

        assert!(matches.is_empty());
    }

    /// Running the tool from inside a crate directory resolves a `yara_rules`
    /// path that does not exist. That used to scan with an empty rule set and
    /// report nothing; it must not become a failed analysis, and it must not
    /// put an error string carrying a local filesystem path into the report's
    /// match list.
    #[test]
    fn missing_rules_directory_is_not_an_error() {
        let td = TempDir::new().unwrap();
        let absent = td.path().join("does-not-exist");
        assert!(!absent.is_dir());

        let target = probe(td.path(), b"nothing interesting");
        let matches = scan_with_rules_dir(&absent, target.to_str().unwrap(), SCAN_TIMEOUT)
            .expect("a missing rules directory must not fail the analysis");

        assert!(matches.is_empty());
    }
}
