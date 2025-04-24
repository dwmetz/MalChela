use md5;

pub fn compute_imphash(imports: &[String]) -> String {
    let mut import_names: Vec<String> = imports
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    import_names.sort();
    let joined = import_names.join(",");
    let hash = md5::compute(joined.as_bytes());
    format!("{:x}", hash)
}
