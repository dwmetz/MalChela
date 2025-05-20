use md5::{Md5, Digest};

pub fn calculate_imphash(imports: &[String]) -> Result<String, String> {
    if imports.is_empty() {
        return Err("No imports provided for imphash calculation.".to_string());
    }

    let mut import_names: Vec<String> = imports
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    import_names.sort();
    let joined = import_names.join(",");
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}
