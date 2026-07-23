// infer only matches magic bytes, and plain text has none — a .txt/.md/.csv/
// etc. file always falls through to "Unknown or unrecognized file type" with
// nothing to back that up. Same gap fileminer's looks_like_text() closes for
// its own suggested-tools routing; ported here so FileAnalyzer's own File
// Type line stops reporting a readme.txt as unrecognized.
fn looks_like_text(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(8000)];
    if sample.is_empty() {
        return true; // empty file — nothing to contradict "text"
    }
    if sample.contains(&0u8) {
        return false; // NUL byte — binary, not text
    }
    let printable = sample
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
        .count();
    (printable as f64 / sample.len() as f64) >= 0.95
}

pub fn detect_file_type(file_content: &[u8]) -> String {
    if let Some(kind) = infer::get(file_content) {
        format!("{} ({})", kind.mime_type(), kind.extension())
    } else if looks_like_text(file_content) {
        "text/plain (txt)".to_string()
    } else {
        "Unknown or unrecognized file type".to_string()
    }
}