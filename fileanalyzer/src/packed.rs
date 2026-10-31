// packed.rs
//
// Packing verdict for File Analyzer, delegated to the `unpack` crate's
// detector so both tools agree. The previous inline YARA rule matched any
// file containing the strings "zlib" or "LZMA" — i.e. most ordinary
// binaries — so "may be packed" carried little signal. The unpack detector
// names the packer and only reports one when it has structural evidence
// (UPX headers/sections incl. tampered layouts, named packer sections,
// installer/bundler signatures, or a combined entropy/import heuristic).

use std::error::Error;

/// `Ok(Some(name))` when a packer/protector/installer/bundler is detected.
pub fn detect_packing(file_path: &str) -> Result<Option<String>, Box<dyn Error>> {
    let bytes = std::fs::read(file_path)?;
    Ok(unpack::packer_summary(&bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn plain_bytes_are_not_packed() {
        assert!(unpack::packer_summary(b"ordinary text with nothing of interest").is_none());
    }
}
