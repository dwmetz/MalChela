// ── OCSP revocation checking for Developer ID code-signing certificates ───────
//
// Apple's codesign tool emits the embedded CMS blob using BER indefinite-length
// encoding (SEQUENCE tag followed by 0x80 rather than a definite length byte).
// That's valid BER but not valid DER, so strict-DER parsers (including Rust's
// RustCrypto `der`/`cms`/`x509-cert` crates) reject it outright. `openssl`'s
// ASN.1 parser is BER-tolerant and handles it without issue, so this module
// leans on the `openssl` CLI for both certificate extraction (`pkcs7`/`x509`)
// and the actual OCSP network round trip (`ocsp`) — one dependency instead of
// fighting encoding quirks in a second parser. openssl is already a MalChela
// requirement, and works the same way on macOS/Linux/Windows (wherever it's
// on PATH).

use std::fs;
use std::path::Path;
use std::process::Command;

pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
    NotChecked(String),
}

pub struct RevocationResult {
    pub status:   RevocationStatus,
    pub ocsp_url: Option<String>,
    pub detail:   Option<String>,
}

fn not_checked(reason: &str) -> RevocationResult {
    RevocationResult {
        status:   RevocationStatus::NotChecked(reason.to_string()),
        ocsp_url: None,
        detail:   None,
    }
}

fn run(cmd: &mut Command) -> Option<(String, String, bool)> {
    let out = cmd.output().ok()?;
    Some((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    ))
}

// Split a multi-cert PEM blob (as emitted by `openssl pkcs7 -print_certs`)
// into individual "-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----"
// blocks.
fn split_pem_certs(pem: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let from_start = &rest[start..];
        if let Some(end) = from_start.find("-----END CERTIFICATE-----") {
            let end = end + "-----END CERTIFICATE-----".len();
            certs.push(from_start[..end].to_string());
            rest = &from_start[end..];
        } else {
            break;
        }
    }
    certs
}

// subject= / issuer= lines from `openssl x509 -noout -subject -issuer`.
fn subject_and_issuer(cert_path: &Path) -> Option<(String, String)> {
    let (stdout, _stderr, ok) = run(Command::new("openssl")
        .args(["x509", "-noout", "-subject", "-issuer", "-in"])
        .arg(cert_path))?;
    if !ok {
        return None;
    }
    let mut subject = None;
    let mut issuer = None;
    for line in stdout.lines() {
        if let Some(s) = line.strip_prefix("subject=") {
            subject = Some(s.trim().to_string());
        } else if let Some(s) = line.strip_prefix("issuer=") {
            issuer = Some(s.trim().to_string());
        }
    }
    Some((subject?, issuer?))
}

fn ocsp_uri(cert_path: &Path) -> Option<String> {
    let (stdout, _stderr, ok) = run(Command::new("openssl")
        .args(["x509", "-noout", "-ocsp_uri", "-in"])
        .arg(cert_path))?;
    if !ok {
        return None;
    }
    let url = stdout.lines().next()?.trim().to_string();
    if url.is_empty() { None } else { Some(url) }
}

// Query Apple's OCSP responder for the leaf certificate's revocation status.
// `cms_der` is the raw CMS ContentInfo blob extracted from the Mach-O
// LC_CODE_SIGNATURE superblob's BlobWrapper entry.
pub fn check_revocation(cms_der: &[u8]) -> RevocationResult {
    // Same MALCHELA_OFFLINE convention every other network-touching tool
    // (nsrlquery, tiquery, fileanalyzer's VT check) already honors — checked
    // here, at the source, so this is offline-safe even when --check-revocation
    // is passed directly on the CLI rather than through Analyze's own gating.
    if common_config::is_offline_mode() {
        return RevocationResult {
            status: RevocationStatus::NotChecked("offline mode (MALCHELA_OFFLINE) — skipped OCSP network request".into()),
            ocsp_url: None,
            detail: None,
        };
    }

    let tmp_dir = std::env::temp_dir().join(format!("malchela_ocsp_{}", std::process::id()));
    if fs::create_dir_all(&tmp_dir).is_err() {
        return not_checked("failed to create temp directory for OCSP check");
    }
    // Always clean up on the way out, whatever path we take.
    let result = check_revocation_inner(cms_der, &tmp_dir);
    let _ = fs::remove_dir_all(&tmp_dir);
    result
}

fn check_revocation_inner(cms_der: &[u8], tmp_dir: &Path) -> RevocationResult {
    let blob_path = tmp_dir.join("blob.der");
    if fs::write(&blob_path, cms_der).is_err() {
        return not_checked("failed to write temporary code-signature blob");
    }

    // Extract every embedded certificate as PEM. openssl's BER-tolerant ASN.1
    // parser handles Apple's indefinite-length CMS encoding without complaint.
    let certs_path = tmp_dir.join("certs.pem");
    let extracted = run(Command::new("openssl")
        .arg("pkcs7")
        .arg("-inform").arg("DER")
        .arg("-in").arg(&blob_path)
        .arg("-print_certs")
        .arg("-out").arg(&certs_path));
    let Some((_out, err, ok)) = extracted else {
        return not_checked("openssl not available or failed to run");
    };
    if !ok {
        return not_checked(&format!(
            "openssl pkcs7 could not parse the code signature: {}",
            err.lines().next().unwrap_or("").trim()
        ));
    }

    let Ok(certs_pem) = fs::read_to_string(&certs_path) else {
        return not_checked("failed to read extracted certificate bundle");
    };
    let cert_blocks = split_pem_certs(&certs_pem);
    if cert_blocks.is_empty() {
        return not_checked("no X.509 certificates found in signature");
    }

    // Write each cert to its own file and pull subject/issuer via openssl.
    let mut cert_paths = Vec::new();
    let mut subjects = Vec::new();
    let mut issuers = Vec::new();
    for (i, block) in cert_blocks.iter().enumerate() {
        let path = tmp_dir.join(format!("cert_{i}.pem"));
        if fs::write(&path, block).is_err() {
            continue;
        }
        match subject_and_issuer(&path) {
            Some((s, iss)) => {
                cert_paths.push(path);
                subjects.push(s);
                issuers.push(iss);
            }
            None => continue,
        }
    }
    if cert_paths.is_empty() {
        return not_checked("could not read subject/issuer from extracted certificates");
    }

    // Leaf = the certificate whose subject never appears as another
    // certificate's issuer (nothing in the set was issued BY it). Works
    // regardless of chain length (leaf-only, leaf+intermediate, or full
    // chain to root).
    let leaf_idx = (0..cert_paths.len()).find(|&i| {
        !(0..cert_paths.len()).any(|j| j != i && issuers[j] == subjects[i])
    });
    let Some(leaf_idx) = leaf_idx else {
        return not_checked("could not identify leaf certificate in chain");
    };
    let issuer_idx = subjects.iter().position(|s| *s == issuers[leaf_idx]);
    let Some(issuer_idx) = issuer_idx else {
        return not_checked("issuer certificate not present in embedded chain");
    };

    let Some(url) = ocsp_uri(&cert_paths[leaf_idx]) else {
        return not_checked("certificate has no OCSP responder URL (older signing format, or no AIA extension)");
    };

    // openssl ocsp matches status lines against the -cert file's basename,
    // so give the leaf a predictable name to make output parsing reliable.
    let leaf_path = tmp_dir.join("leaf.pem");
    if fs::copy(&cert_paths[leaf_idx], &leaf_path).is_err() {
        return not_checked("failed to stage leaf certificate for OCSP query");
    }

    let queried = run(Command::new("openssl")
        .arg("ocsp")
        .arg("-issuer").arg(&cert_paths[issuer_idx])
        .arg("-cert").arg(&leaf_path)
        .arg("-url").arg(&url)
        .arg("-no_nonce")
        .arg("-timeout").arg("10"));
    let Some((stdout, stderr, _ok)) = queried else {
        return RevocationResult {
            status: RevocationStatus::NotChecked("openssl not available or failed to run".into()),
            ocsp_url: Some(url),
            detail: None,
        };
    };

    let combined = format!("{stdout}{stderr}");
    let status = if combined.contains("leaf.pem: good") {
        RevocationStatus::Good
    } else if combined.contains("leaf.pem: revoked") {
        RevocationStatus::Revoked
    } else if combined.contains("leaf.pem: unknown") {
        RevocationStatus::Unknown
    } else {
        let first_line = combined.lines().next().unwrap_or("").trim();
        RevocationStatus::NotChecked(format!("unexpected openssl ocsp output: {first_line}"))
    };

    RevocationResult {
        status,
        ocsp_url: Some(url),
        detail: Some(combined.trim().to_string()),
    }
}
