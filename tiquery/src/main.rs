mod config;
mod hash;
mod sources;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use futures::future::join_all;
use hash::HashType;
use sources::{
    AlienVaultOTX, FileScan, GoogleSafeBrowsing, HybridAnalysis, MalwareBazaar, Malshare,
    MetaDefender, ObjectiveSee, SourceResult, SourceStatus, StubSource, ThreatSource, Triage,
    UrlScan, VirusTotal,
};
use std::io::Write as _;
use std::sync::Arc;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "tiquery", about = "Multi-source threat intel lookup (hashes and URLs)")]
struct Args {
    /// Hash (MD5/SHA1/SHA256) or URL to query
    hash: Option<String>,

    /// Sources to query, comma-separated: mb,vt,otx,md,os,ha,fs,ms,tr,urlscan,gsb
    /// Default: all sources with a configured API key
    #[arg(short, long, value_delimiter = ',', value_name = "SRC")]
    sources: Option<Vec<String>>,

    /// Output machine-readable JSON to stdout (ordered array)
    #[arg(long)]
    json: bool,

    /// Output CSV to stdout
    #[arg(long)]
    csv: bool,

    /// Download sample from MalwareBazaar after lookup (SHA256 only)
    #[arg(short = 'd', long)]
    download: bool,

    /// Case name for routing saved output
    #[arg(long)]
    case: Option<String>,

    /// Save output file (-t / -j / -m required)
    #[arg(short, long)]
    output: bool,

    /// Save as plain text
    #[arg(short = 't', long)]
    text: bool,

    /// Save as Markdown
    #[arg(short = 'm', long)]
    markdown: bool,

    /// Include per-engine VT detections in output
    #[arg(long)]
    verbose_vt: bool,

    /// Bulk hash lookup: read hashes from a file (one per line, or CSV)
    #[arg(long, value_name = "FILE", conflicts_with = "hash")]
    bulk: Option<String>,

    /// QR code decode: extract URL from an image and query it
    #[arg(long, value_name = "IMAGE", conflicts_with = "hash")]
    qr: Option<String>,
}

// ── Source registry ───────────────────────────────────────────────────────────

/// All known source IDs in canonical query order.
/// Sources that need a key are only included when one is configured.
const ALL_SOURCE_IDS: &[(&str, bool)] = &[
    // (id, needs_key)
    ("mb",  true),
    ("vt",  true),
    ("otx", true),
    ("md",  true),
    ("ha",  true),
    ("fs",  true),
    ("ms",  true),
    ("tr",  true),
    ("os",  false),
];

/// Source IDs used when the input is a URL.
const URL_SOURCE_IDS: &[(&str, bool)] = &[
    // (id, needs_key)
    ("vt",      true),
    ("urlscan", false),
    ("gsb",     true),
];

fn default_source_ids() -> Vec<String> {
    let cfg = config::TiQueryConfig::load().unwrap_or_default();
    ALL_SOURCE_IDS
        .iter()
        .filter(|(id, needs_key)| {
            if !cfg.source_enabled(id) { return false; }
            if !needs_key { return true; }
            cfg.source_api_key(id)
                .or_else(|| common_config::resolve_api_key(id))
                .is_some()
        })
        .map(|(id, _)| id.to_string())
        .collect()
}

fn default_url_source_ids() -> Vec<String> {
    let cfg = config::TiQueryConfig::load().unwrap_or_default();
    URL_SOURCE_IDS
        .iter()
        .filter(|(id, needs_key)| {
            if !cfg.source_enabled(id) { return false; }
            if !needs_key { return true; }
            cfg.source_api_key(id)
                .or_else(|| common_config::resolve_api_key(id))
                .is_some()
        })
        .map(|(id, _)| id.to_string())
        .collect()
}

// ── Source factory ────────────────────────────────────────────────────────────

fn build_sources(ids: &[String], _hash_type: HashType, verbose_vt: bool) -> Vec<Arc<dyn ThreatSource>> {
    // Key resolution: YAML config override → api/<src>-api.txt → legacy migration
    let cfg = config::TiQueryConfig::load().unwrap_or_default();

    let resolve = |id: &str| -> Option<String> {
        cfg.source_api_key(id)
            .or_else(|| common_config::resolve_api_key(id))
    };

    let mut out: Vec<Arc<dyn ThreatSource>> = Vec::new();

    for id in ids {
        if !cfg.source_enabled(id) {
            continue;
        }
        let src: Arc<dyn ThreatSource> = match id.as_str() {
            "mb"  => Arc::new(MalwareBazaar::new(resolve("mb"))),
            "vt"  => {
                let vt = VirusTotal::new(resolve("vt"));
                if verbose_vt { Arc::new(vt.with_verbose()) } else { Arc::new(vt) }
            }
            "otx" => Arc::new(AlienVaultOTX::new(resolve("otx"))),
            "md"  => Arc::new(MetaDefender::new(resolve("md"))),
            "ha"  => Arc::new(HybridAnalysis::new(resolve("ha"))),
            "fs"  => Arc::new(FileScan::new(resolve("fs"))),
            "ms"  => Arc::new(Malshare::new(resolve("ms"))),
            "tr"  => Arc::new(Triage::new(resolve("tr"))),
            "os"  => Arc::new(ObjectiveSee::new()),
            "urlscan" => Arc::new(UrlScan::new(resolve("url"))),
            "gsb"     => Arc::new(GoogleSafeBrowsing::new(resolve("gsb"))),
            other => Arc::new(StubSource::new(other)),
        };
        out.push(src);
    }

    out
}

// ── Output helpers ────────────────────────────────────────────────────────────

const COL_SRC: usize = 8;
const COL_STATUS: usize = 12;
const COL_FAMILY: usize = 22;
const COL_DET: usize = 13;

fn separator() -> String {
    format!(
        "  {:<COL_SRC$}  {:<COL_STATUS$}  {:<COL_FAMILY$}  {:<COL_DET$}  {}",
        "─".repeat(COL_SRC),
        "─".repeat(COL_STATUS),
        "─".repeat(COL_FAMILY),
        "─".repeat(COL_DET),
        "─".repeat(40),
        COL_SRC = COL_SRC,
        COL_STATUS = COL_STATUS,
        COL_FAMILY = COL_FAMILY,
        COL_DET = COL_DET,
    )
}

fn status_colored(s: &SourceStatus) -> colored::ColoredString {
    match s {
        SourceStatus::Found => "FOUND".green().bold(),
        SourceStatus::NotFound => "NOT FOUND".dimmed(),
        SourceStatus::NoKey => "NO KEY".yellow(),
        SourceStatus::Error(_) => "ERROR".red(),
        SourceStatus::Skipped(_) => "SKIPPED".dimmed(),
    }
}

fn status_label(s: &SourceStatus) -> String {
    match s {
        SourceStatus::Found => "FOUND".to_string(),
        SourceStatus::NotFound => "NOT FOUND".to_string(),
        SourceStatus::NoKey => "NO KEY".to_string(),
        SourceStatus::Error(e) => format!("ERROR: {}", e),
        SourceStatus::Skipped(r) => format!("SKIPPED ({})", r),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn output_matrix(hash: &str, input_label: &str, results: &[(String, SourceResult)]) {
    println!();
    println!("  {} {} ({})", "tiquery".cyan().bold(), hash.white(), input_label.dimmed());
    println!("{}", separator());
    println!(
        "  {:<COL_SRC$}  {:<COL_STATUS$}  {:<COL_FAMILY$}  {:<COL_DET$}  {}",
        "Source".bold(),
        "Status".bold(),
        "Family / Tags".bold(),
        "Detections".bold(),
        "Reference".bold(),
        COL_SRC = COL_SRC,
        COL_STATUS = COL_STATUS,
        COL_FAMILY = COL_FAMILY,
        COL_DET = COL_DET,
    );
    println!("{}", separator());

    for (name, result) in results {
        let status = result.status.as_ref().map(status_colored).unwrap_or("?".normal());

        let family_str = {
            let f = result.family.as_deref().unwrap_or("");
            let t = if !result.tags.is_empty() {
                result.tags.join(", ")
            } else {
                String::new()
            };
            let combined = if !f.is_empty() && !t.is_empty() {
                format!("{} [{}]", f, t)
            } else if !f.is_empty() {
                f.to_string()
            } else {
                t
            };
            truncate(&combined, COL_FAMILY)
        };

        let det_str = result
            .detections
            .as_deref()
            .map(|d| truncate(d, COL_DET))
            .unwrap_or_default();

        let link = result.link.as_deref().unwrap_or("-");

        // Color the source name based on result
        let src_colored = match &result.status {
            Some(SourceStatus::Found) => name.green(),
            Some(SourceStatus::Error(_)) => name.red(),
            Some(SourceStatus::NoKey) => name.yellow(),
            _ => name.normal().dimmed(),
        };

        println!(
            "  {:<COL_SRC$}  {:<COL_STATUS$}  {:<COL_FAMILY$}  {:<COL_DET$}  {}",
            src_colored,
            status,
            family_str,
            det_str,
            link.dimmed(),
            COL_SRC = COL_SRC,
            COL_STATUS = COL_STATUS,
            COL_FAMILY = COL_FAMILY,
            COL_DET = COL_DET,
        );
    }

    println!("{}", separator());
    println!();
}

fn output_json(results: &[(String, SourceResult)]) {
    // Ordered array — preserves source query order for GUI / MCP consumers.
    let arr: Vec<serde_json::Value> = results
        .iter()
        .map(|(_, r)| serde_json::to_value(r).unwrap_or_default())
        .collect();
    println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
}

fn output_csv(results: &[(String, SourceResult)]) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(std::io::stdout());
    wtr.write_record(["source", "status", "family", "detections", "file_name", "file_type", "first_seen", "link"])?;
    for (name, r) in results {
        let status = r.status.as_ref().map(|s| status_label(s)).unwrap_or_default();
        wtr.write_record([
            name.as_str(),
            &status,
            r.family.as_deref().unwrap_or(""),
            r.detections.as_deref().unwrap_or(""),
            r.file_name.as_deref().unwrap_or(""),
            r.file_type.as_deref().unwrap_or(""),
            r.first_seen.as_deref().unwrap_or(""),
            r.link.as_deref().unwrap_or(""),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

fn output_text(hash: &str, input_label: &str, results: &[(String, SourceResult)]) -> String {
    let mut out = String::new();
    out.push_str(&format!("tiquery results for: {} ({})\n", hash, input_label));
    out.push_str(&"─".repeat(60));
    out.push('\n');
    for (name, r) in results {
        let status = r.status.as_ref().map(|s| status_label(s)).unwrap_or_default();
        out.push_str(&format!("[{}] {}\n", name, status));
        if let Some(f) = &r.family { out.push_str(&format!("  Family: {}\n", f)); }
        if let Some(d) = &r.detections { out.push_str(&format!("  Detections: {}\n", d)); }
        if let Some(l) = &r.link { out.push_str(&format!("  Link: {}\n", l)); }
        if !r.tags.is_empty() { out.push_str(&format!("  Tags: {}\n", r.tags.join(", "))); }
    }
    out
}

fn output_markdown(hash: &str, input_label: &str, results: &[(String, SourceResult)]) -> String {
    let mut md = String::new();
    md.push_str("# TI Query Report\n\n");
    md.push_str(&format!("| Field | Value |\n|-------|-------|\n"));
    md.push_str(&format!("| Input | `{}` |\n", hash));
    md.push_str(&format!("| Type | {} |\n\n", input_label));
    md.push_str("## Results\n\n");
    md.push_str("| Source | Status | Family / Tags | Detections | Link |\n");
    md.push_str("|--------|--------|---------------|------------|------|\n");
    for (name, r) in results {
        let status = r.status.as_ref().map(|s| status_label(s)).unwrap_or_default();
        let family = {
            let f = r.family.as_deref().unwrap_or("");
            let t = if !r.tags.is_empty() { r.tags.join(", ") } else { String::new() };
            if !f.is_empty() && !t.is_empty() { format!("{} [{}]", f, t) }
            else if !f.is_empty() { f.to_string() }
            else { t }
        };
        let det = r.detections.as_deref().unwrap_or("");
        let link = r.link.as_deref().unwrap_or("-");
        let link_cell = if link != "-" { format!("[link]({})", link) } else { "-".to_string() };
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            name, status, family, det, link_cell
        ));
    }
    md.push('\n');
    md
}

// ── Bulk / QR helpers ─────────────────────────────────────────────────────────

fn is_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_hash_file(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;
    let mut seen = std::collections::HashSet::new();
    let mut hashes = Vec::new();
    for line in content.lines() {
        for token in line.split(|c: char| c.is_whitespace() || c == ',') {
            let h = token.trim().to_lowercase();
            if is_hash(&h) && seen.insert(h.clone()) {
                hashes.push(h);
            }
        }
    }
    Ok(hashes)
}

fn decode_qr_file(path: &str) -> Result<String, String> {
    let base = image::open(path)
        .map_err(|e| format!("Failed to open image: {}", e))?
        .to_luma8();
    let (w, h) = (base.width(), base.height());
    let mut last_err: Option<String> = None;
    for s in [1u32, 2, 3, 4] {
        let candidate = if s == 1 {
            base.clone()
        } else {
            image::imageops::resize(&base, w * s, h * s, image::imageops::FilterType::Lanczos3)
        };
        let mut prep = rqrr::PreparedImage::prepare(candidate);
        let grids = prep.detect_grids();
        if let Some(grid) = grids.first() {
            match grid.decode() {
                Ok((_meta, content)) => return Ok(content.trim().to_string()),
                Err(e) => last_err = Some(format!("decode: {}", e)),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "no QR code detected".to_string()))
}

async fn run_bulk(file_path: &str, args: &Args) -> Result<()> {
    let hashes = parse_hash_file(file_path)?;
    if hashes.is_empty() {
        eprintln!("No valid hashes found in {}", file_path);
        std::process::exit(1);
    }

    eprintln!("Processing {} hashes from {}", hashes.len(), file_path);

    let mut all_results: Vec<(String, Vec<(String, SourceResult)>)> = Vec::new();

    for (i, hash) in hashes.iter().enumerate() {
        let hash_type = HashType::detect(hash);
        if hash_type == HashType::Unknown {
            eprintln!("[{}/{}] Skipping invalid hash: {}", i + 1, hashes.len(), hash);
            continue;
        }

        let short = if hash.len() > 16 { format!("{}…", &hash[..16]) } else { hash.clone() };
        eprintln!("[{}/{}] Querying: {} ({})", i + 1, hashes.len(), short, hash_type.label());

        let source_ids = args.sources.clone().unwrap_or_else(default_source_ids);
        let sources = build_sources(&source_ids, hash_type, args.verbose_vt);

        let futures: Vec<_> = sources.into_iter().map(|src| {
            let h = hash.clone();
            async move {
                let name = src.short_name().to_string();
                let result = src.query(&h).await;
                (name, result)
            }
        }).collect();

        let mut results = join_all(futures).await;
        results.sort_by_key(|(name, _)| {
            source_ids.iter().position(|s| s.to_uppercase() == *name).unwrap_or(99)
        });

        if !args.json && !args.csv {
            println!("\n[{}/{}]", i + 1, hashes.len());
            output_matrix(hash, &hash_type.label().to_string(), &results);
        }

        all_results.push((hash.clone(), results));

        if i + 1 < hashes.len() {
            tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
        }
    }

    if args.json {
        let arr: Vec<serde_json::Value> = all_results.iter().map(|(hash, results)| {
            let res_arr: Vec<serde_json::Value> = results.iter()
                .map(|(_, r)| serde_json::to_value(r).unwrap_or_default())
                .collect();
            serde_json::json!({"hash": hash, "results": res_arr})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
    } else if args.csv {
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        wtr.write_record(["hash", "source", "status", "family", "detections", "file_name", "file_type", "first_seen", "link"])?;
        for (hash, results) in &all_results {
            for (name, r) in results {
                let status = r.status.as_ref().map(|s| status_label(s)).unwrap_or_default();
                wtr.write_record([
                    hash.as_str(), name.as_str(), &status,
                    r.family.as_deref().unwrap_or(""),
                    r.detections.as_deref().unwrap_or(""),
                    r.file_name.as_deref().unwrap_or(""),
                    r.file_type.as_deref().unwrap_or(""),
                    r.first_seen.as_deref().unwrap_or(""),
                    r.link.as_deref().unwrap_or(""),
                ])?;
            }
        }
        wtr.flush()?;
    }

    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Migrate any legacy api key files on startup (silent if nothing to migrate)
    common_config::migrate_api_keys();

    let args = Args::parse();

    // Bulk mode: read hashes from a file and query each one
    if let Some(ref path) = args.bulk.clone() {
        return run_bulk(path, &args).await;
    }

    // Resolve hash from argument, QR image, or interactive prompt
    let raw_input = if let Some(ref img_path) = args.qr {
        match decode_qr_file(img_path) {
            Ok(url) => {
                eprintln!("QR decoded: {}", url);
                url
            }
            Err(e) => {
                eprintln!("Error: QR decode failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match args.hash {
            Some(ref h) => h.trim().to_string(),
            None => {
                print!("Enter hash or URL to query: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                input.trim().to_string()
            }
        }
    };

    // Detect whether the input is a URL or a hash
    let is_url = raw_input.starts_with("http://") || raw_input.starts_with("https://");
    let (hash, hash_type, input_label) = if is_url {
        (raw_input.clone(), HashType::Unknown, "URL".to_string())
    } else {
        let lower = raw_input.to_lowercase();
        let ht = HashType::detect(&lower);
        if ht == HashType::Unknown {
            eprintln!("Error: unrecognized input (expected MD5/SHA1/SHA256 hash or http/https URL)");
            std::process::exit(1);
        }
        let label = ht.label().to_string();
        (lower, ht, label)
    };

    // Determine source IDs: explicit --sources flag, or auto-detect based on input type
    let source_ids: Vec<String> = args
        .sources
        .unwrap_or_else(|| {
            if is_url { default_url_source_ids() } else { default_source_ids() }
        });

    // If ObjectiveSee is requested and hash is SHA256, warm the cache sequentially first
    if source_ids.iter().any(|s| s == "os") && hash_type == HashType::Sha256 {
        let os_path = dirs::cache_dir()
            .unwrap_or_default()
            .join("malchela")
            .join("os-malware.json");
        if !os_path.exists() {
            // Cache will be fetched inside the source; prefetch message happens there
        }
    }

    // If saving to a case, ensure case.json exists so the GUI browser can open it.
    if let Some(ref case) = args.case {
        common_config::ensure_case_json(case);
    }

    let sources = build_sources(&source_ids, hash_type, args.verbose_vt);

    // Run all source queries concurrently
    let futures: Vec<_> = sources
        .into_iter()
        .map(|src| {
            let h = hash.clone();
            async move {
                let name = src.short_name().to_string();
                let result = src.query(&h).await;
                (name, result)
            }
        })
        .collect();

    let mut results: Vec<(String, SourceResult)> = join_all(futures).await;

    // Restore requested order
    results.sort_by_key(|(name, _)| {
        source_ids
            .iter()
            .position(|s| s.to_uppercase() == *name)
            .unwrap_or(99)
    });

    // Output
    if args.json {
        output_json(&results);
    } else if args.csv {
        output_csv(&results)?;
    } else {
        output_matrix(&hash, &input_label, &results);

        // Per-engine VT detections (verbose mode)
        if args.verbose_vt {
            for (name, r) in &results {
                if name != "VT" { continue; }
                if let Some(engines) = r.extra.get("engines").and_then(|v| v.as_array()) {
                    if engines.is_empty() { break; }
                    println!("  {} per-engine detections ({})\n{}", "VT".green().bold(), engines.len(), separator());
                    println!("  {:<35}  {:<12}  {}", "Engine".bold(), "Category".bold(), "Detection".bold());
                    println!("{}", separator());
                    for e in engines {
                        let eng = e.get("engine").and_then(|v| v.as_str()).unwrap_or("");
                        let cat = e.get("category").and_then(|v| v.as_str()).unwrap_or("");
                        let res = e.get("result").and_then(|v| v.as_str()).unwrap_or("");
                        let cat_colored = if cat == "malicious" { cat.red() } else { cat.yellow() };
                        println!("  {:<35}  {:<12}  {}", eng, cat_colored, res.dimmed());
                    }
                    println!("{}", separator());
                    println!();
                }
            }
        }
    }

    // Save report — runs regardless of output format (--json, --csv, or matrix).
    // This allows the MCP server to request --json for machine-readable output while
    // still writing a human-readable report to the case folder via -o -t or -o -m.
    if args.output && (args.text || args.markdown) {
        let (content, ext) = if args.markdown {
            (output_markdown(&hash, &input_label, &results), "md")
        } else {
            (output_text(&hash, &input_label, &results), "txt")
        };
        let output_dir = if let Some(ref case) = args.case {
            let p = std::path::Path::new("saved_output")
                .join("cases")
                .join(case)
                .join("tiquery");
            std::fs::create_dir_all(&p)?;
            p
        } else {
            let p = common_config::get_output_dir("tiquery");
            std::fs::create_dir_all(&p)?;
            p
        };
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let path = output_dir.join(format!("report_{}.{}", ts, ext));
        std::fs::write(&path, &content)?;
        eprintln!("Report saved to: {}", path.display());
    }

    // ── MB download (SHA256 only) ─────────────────────────────────────────────
    if args.download {
        if hash_type != HashType::Sha256 {
            eprintln!("--download requires SHA256 hash (got {})", hash_type.label());
        } else {
            // Only proceed if MB returned a hit
            let mb_found = results.iter().any(|(name, r)| {
                name == "MB" && matches!(r.status, Some(SourceStatus::Found))
            });

            if !mb_found {
                eprintln!("[download] Sample not found in MalwareBazaar — skipping.");
            } else {
                let cfg = config::TiQueryConfig::load().unwrap_or_default();
                let mb_key = cfg.source_api_key("mb")
                    .or_else(|| common_config::resolve_api_key("mb"));

                let dl_dir = if let Some(ref case) = args.case {
                    std::path::Path::new("saved_output")
                        .join("cases").join(case).join("tiquery").join("downloads")
                } else {
                    common_config::get_output_dir("tiquery").join("downloads")
                };

                let mb = sources::MalwareBazaar::new(mb_key);
                match mb.download_sample(&hash, &dl_dir).await {
                    Ok(path) => {
                        // Always write to stderr so the GUI can capture it without
                        // corrupting the JSON array on stdout.
                        eprintln!(
                            "[download] Sample saved: {} (extract password: infected)",
                            path.display()
                        );
                    }
                    Err(e) => eprintln!("[download] Failed: {}", e),
                }
            }
        }
    }

    Ok(())
}
