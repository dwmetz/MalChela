// packed.rs
use std::fs::File;
use std::io::Read;
use std::time::Duration;

use yara_backend::YaraBackend;

/// Wall clock budget for the in memory packer scan, unchanged from the
/// previous implementation, which passed `10` to libyara.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

const PACKER_RULE: &str = r#"
rule is_packed {
    meta:
        description = "Detects packed executables (UPX, etc.)"
        author = "Your Name"
        date = "2024-10-27"
    strings:
        // UPX Signatures (more refined)
        $upx_sig1 = "UPX!"
        $upx_sig2 = { 60 EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 61 C3 }
        $upx_sig3 = { 8B ?? ?? ?? ?? 60 } // Common UPX jump
        $upx_sig4 = { 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 } //Another common UPX signature.
        // Common Packer Strings (can be extended)
        $packer_str1 = "UPX"
        $packer_str2 = "PECompact"
        $packer_str3 = "ASPack"
        $packer_str4 = "FSG"
        $packer_str5 = "RLPack"
        $packer_str6 = "MEW"
        $packer_str7 = "aPLib"
        $packer_str8 = "LZMA"
        $packer_str9 = "zlib"
        $packer_str10 = "PKLITE"

        // Entropy-related signatures.
        $high_entropy_section = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? } // Matches a large sequence of high entropy bytes.

    condition:
        ($upx_sig1 and ($upx_sig2 or $upx_sig3 or $upx_sig4)) or
        ($packer_str1 or $packer_str2 or $packer_str3 or $packer_str4 or $packer_str5 or $packer_str6 or $packer_str7 or $packer_str8 or $packer_str9 or $packer_str10) or
        (uint16(0) == 0x5A4D and #high_entropy_section > 5) // PE header and many high entropy sections.
}
"#;

pub fn detect_packing(file_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let backend = YaraBackend::from_inline_sources(&[("packed", PACKER_RULE)])?;

    let mut file = File::open(file_path)?;
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content)?;

    let report = backend.scan_bytes(&file_content, SCAN_TIMEOUT)?;
    Ok(!report.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packer_rule_compiles_under_the_backend() {
        let backend =
            YaraBackend::from_inline_sources(&[("packed", PACKER_RULE)]).expect("rule compiles");
        assert_eq!(backend.rule_count(), 1);
    }

    #[test]
    fn upx_marker_is_detected_and_plain_bytes_are_not() {
        let backend = YaraBackend::from_inline_sources(&[("packed", PACKER_RULE)]).unwrap();

        let packed = backend
            .scan_bytes(
                b"UPX! and some padding to look like a payload",
                SCAN_TIMEOUT,
            )
            .unwrap();
        assert!(!packed.is_empty(), "UPX marker should match");

        let plain = backend
            .scan_bytes(b"ordinary text with nothing of interest", SCAN_TIMEOUT)
            .unwrap();
        assert!(plain.is_empty(), "plain bytes should not match");
    }
}
