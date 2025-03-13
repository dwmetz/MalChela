use sha2::{Sha256, Digest};

pub fn calculate_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}