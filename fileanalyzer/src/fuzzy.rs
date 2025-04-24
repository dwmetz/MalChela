use ssdeep::hash;

pub fn compute_fuzzy_hash(file_content: &[u8]) -> Option<String> {
    std::panic::catch_unwind(|| hash(file_content).ok())
        .ok()
        .flatten()
}
