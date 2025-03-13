// packed.rs
use yara::{Compiler, Rules};
use std::fs::File;
use std::io::Read;

pub fn detect_packing(file_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let mut compiler = Compiler::new()?;
    compiler = compiler.add_rules_str(r#" // Reassign compiler
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
    "#)?;

    let rules: Rules = compiler.compile_rules()?;

    let mut file = File::open(file_path)?;
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content)?;

    let results = rules.scan_mem(&file_content, 10)?;
    Ok(!results.is_empty())
}