use super::{SourceResult, SourceStatus, ThreatSource};
use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Triage {
    api_key: Option<String>,
}

impl Triage {
    pub fn new(api_key: Option<String>) -> Self {
        Triage { api_key }
    }

    /// Download a public sample by SHA256 and save it inside a password-protected
    /// zip (password `infected`), the same convention MalwareBazaar uses. Triage
    /// serves the raw file, so it is never written to disk unwrapped, and its
    /// SHA256 is checked against the requested hash before anything is saved.
    pub async fn download_sample(&self, sha256: &str, output_dir: &Path) -> Result<PathBuf, String> {
        let key = self.api_key.as_deref().ok_or("No Triage API key configured")?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;

        // Find the public sample ID for this hash (same search the lookup uses).
        let resp = client
            .get("https://tria.ge/api/v0/search")
            .query(&[("query", format!("sha256:{}", sha256))])
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
            .map_err(|e| format!("search error: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("search HTTP {}", resp.status().as_u16()));
        }
        let body: Value = resp.json().await.map_err(|e| format!("search parse: {}", e))?;
        let first = body
            .get("data")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .ok_or("sample not found in Triage")?;
        let sample_id = first.get("id").and_then(Value::as_str).ok_or("search result without a sample id")?;
        let ext = first
            .get("filename")
            .and_then(Value::as_str)
            .and_then(|f| Path::new(f).extension())
            .and_then(|e| e.to_str())
            .filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()))
            .map(|e| format!(".{}", e.to_ascii_lowercase()))
            .unwrap_or_default();

        // GET /v0/samples/{id}/sample returns the original file, raw.
        let resp = client
            .get(format!("https://tria.ge/api/v0/samples/{}/sample", sample_id))
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
            .map_err(|e| format!("download error: {}", e))?;
        match resp.status().as_u16() {
            200 => {}
            401 | 403 => return Err("Triage refused the download (check API key and account permissions)".into()),
            404 => return Err("Triage has no downloadable file for this sample".into()),
            code => return Err(format!("download HTTP {}", code)),
        }
        let bytes = resp.bytes().await.map_err(|e| format!("download error: {}", e))?;

        let got = hex::encode(Sha256::digest(&bytes));
        if !got.eq_ignore_ascii_case(sha256) {
            return Err(format!("hash mismatch: Triage returned {} (not saved)", got));
        }

        std::fs::create_dir_all(output_dir).map_err(|e| format!("could not create output dir: {}", e))?;
        let zip_path = output_dir.join(format!("{}.zip", &sha256[..16]));
        write_infected_zip(&zip_path, &format!("{}{}", sha256.to_ascii_lowercase(), ext), &bytes)?;
        Ok(zip_path)
    }
}

/// Write `data` as the single entry `name` in a ZipCrypto zip with password
/// `infected`. ZipCrypto is weak by design here: it's the malware-sharing
/// convention that keeps AV/EDR and accidental double-clicks off the sample,
/// and every unzip tool (macOS Archive Utility, unzip, 7-Zip) can open it.
pub(crate) fn write_infected_zip(path: &Path, name: &str, data: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use zip::unstable::write::FileOptionsExt;
    let file = std::fs::File::create(path).map_err(|e| format!("write error: {}", e))?;
    let mut zw = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .with_deprecated_encryption(b"infected")
        .map_err(|e| format!("zip error: {}", e))?;
    zw.start_file(name, opts).map_err(|e| format!("zip error: {}", e))?;
    zw.write_all(data).map_err(|e| format!("zip error: {}", e))?;
    zw.finish().map_err(|e| format!("zip error: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_infected_zip;
    use std::io::Read as _;

    #[test]
    fn infected_zip_round_trips_and_needs_the_password() {
        let dir = std::env::temp_dir().join(format!("tq-zip-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.zip");
        let payload = b"MZ\x90\x00not really a PE, just test bytes".to_vec();
        write_infected_zip(&path, "abc.exe", &payload).unwrap();

        let mut ar = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        assert!(ar.by_name("abc.exe").is_err(), "entry must be encrypted");
        let mut out = Vec::new();
        ar.by_name_decrypt("abc.exe", b"infected").unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
        assert!(ar.by_name_decrypt("abc.exe", b"wrong").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[async_trait]
impl ThreatSource for Triage {
    fn name(&self) -> &str { "Triage (Recorded Future)" }
    fn short_name(&self) -> &str { "TR" }

    async fn query(&self, hash: &str) -> SourceResult {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SourceResult::no_key(self.short_name()),
        };

        let client = reqwest::Client::new();

        // Triage requires a typed hash prefix; use reqwest's query builder so the
        // colon is percent-encoded (%3A) which the API requires for exact hash lookups.
        let hash_prefix = match hash.len() {
            32 => "md5",
            40 => "sha1",
            64 => "sha256",
            _  => "sha256",
        };
        let typed_query = format!("{}:{}", hash_prefix, hash);

        // Step 1: search for the hash — /search queries public samples;
        // /samples only returns the authenticated user's own submissions.
        let resp = match client
            .get("https://tria.ge/api/v0/search")
            .query(&[("query", &typed_query)])
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let status = resp.status();
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return SourceResult::error(self.short_name(), "invalid API key");
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return SourceResult::error(self.short_name(), "rate limited");
        }
        if !status.is_success() {
            let snippet = text.chars().take(120).collect::<String>();
            return SourceResult::error(self.short_name(), format!("HTTP {} — {}", status.as_u16(), snippet));
        }

        let body: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return SourceResult::error(self.short_name(), format!("parse: {}", e)),
        };

        let data = match body.get("data").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr.clone(),
            _ => return SourceResult::not_found(self.short_name()),
        };

        let sample = &data[0];
        let sample_id = match sample.get("id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return SourceResult::error(self.short_name(), "missing sample id"),
        };

        let file_name = sample.get("filename").and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let submitted = sample.get("submitted").and_then(|v| v.as_str())
            .map(|s| s.chars().take(10).collect::<String>());

        // Step 2: fetch summary for family/tags/verdict
        let summary_url = format!("https://tria.ge/api/v0/samples/{}/summary", sample_id);
        let sum_resp = match client
            .get(&summary_url)
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let sum_text = match sum_resp.text().await {
            Ok(t) => t,
            Err(e) => return SourceResult::error(self.short_name(), e.to_string()),
        };

        let sum: Value = serde_json::from_str(&sum_text).unwrap_or(Value::Null);

        let analysis = sum.get("analysis");

        let family: Option<String> = analysis
            .and_then(|a| a.get("family"))
            .and_then(|f| f.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let tags: Vec<String> = analysis
            .and_then(|a| a.get("tags"))
            .and_then(|t| t.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default();

        let score: Option<u64> = analysis
            .and_then(|a| a.get("score"))
            .and_then(|v| v.as_u64());

        let detections = score.map(|s| format!("score {}/10", s));

        SourceResult {
            source:     self.short_name().to_string(),
            status:     Some(SourceStatus::Found),
            family,
            detections,
            file_name,
            file_type:  None,
            first_seen: submitted,
            tags,
            link:       Some(format!("https://tria.ge/{}", sample_id)),
            extra:      Default::default(),
        }
    }
}
