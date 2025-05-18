use sha2::{Sha256, Digest as ShaDigest};
use md5::Md5;

pub fn calculate_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

pub fn calculate_md5(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}