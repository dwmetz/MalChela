use regex::Regex;

pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let re = Regex::new(r"[ -~]{4,}").unwrap(); // ASCII printable chars, min length 4
    let content = String::from_utf8_lossy(data);
    re.find_iter(&content).map(|m| m.as_str().to_string()).collect()
}