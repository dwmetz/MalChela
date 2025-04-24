

pub fn detect_file_type(file_content: &[u8]) -> String {
    if let Some(kind) = infer::get(file_content) {
        format!("{} ({})", kind.mime_type(), kind.extension())
    } else {
        "Unknown or unrecognized file type".to_string()
    }
}