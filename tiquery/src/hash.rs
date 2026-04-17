/// Hash algorithm inferred from string length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Unknown,
}

impl HashType {
    pub fn detect(hash: &str) -> Self {
        let h = hash.trim();
        if h.chars().all(|c| c.is_ascii_hexdigit()) {
            match h.len() {
                32 => HashType::Md5,
                40 => HashType::Sha1,
                64 => HashType::Sha256,
                _ => HashType::Unknown,
            }
        } else {
            HashType::Unknown
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA1",
            HashType::Sha256 => "SHA256",
            HashType::Unknown => "UNKNOWN",
        }
    }
}
