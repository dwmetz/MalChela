use md5;

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
    let hash = md5::compute(joined.as_bytes());
    Ok(format!("{:x}", hash))
}
