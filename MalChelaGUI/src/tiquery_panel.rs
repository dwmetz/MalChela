use eframe::egui::{self, Color32, RichText, ScrollArea};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::thread;

// ── Colour palette (matches rest of MalChela GUI) ─────────────────────────────
const CYAN:        Color32 = Color32::from_rgb(0,   255, 255);
const STONE_BEIGE: Color32 = Color32::from_rgb(225, 210, 180);
const ORANGE:      Color32 = Color32::from_rgb(200, 100,  50);
const GREEN:       Color32 = Color32::from_rgb(0,   200,   0);
const YELLOW:      Color32 = Color32::from_rgb(255, 220,   0);
const RED:         Color32 = Color32::from_rgb(220,  50,  50);
const AMBER:       Color32 = Color32::from_rgb(255, 191,   0);
const DIM_GRAY:    Color32 = Color32::from_rgb(120, 120, 120);

// ── Source registry ────────────────────────────────────────────────────────────

struct SourceDef {
    id:        &'static str,
    label:     &'static str,
    needs_key: bool,
    tier:      u8,
}

const SOURCES: &[SourceDef] = &[
    SourceDef { id: "mb",  label: "MalwareBazaar",  needs_key: true,  tier: 1 },
    SourceDef { id: "vt",  label: "VirusTotal",      needs_key: true,  tier: 1 },
    SourceDef { id: "otx", label: "AlienVault OTX",  needs_key: true,  tier: 1 },
    SourceDef { id: "md",  label: "MetaDefender",     needs_key: true,  tier: 1 },
    SourceDef { id: "mp",  label: "Malpedia",         needs_key: true,  tier: 2 },
    SourceDef { id: "ha",  label: "Hybrid Analysis",  needs_key: true,  tier: 2 },
    SourceDef { id: "mw",  label: "MWDB",             needs_key: true,  tier: 2 },
    SourceDef { id: "tr",  label: "Triage",           needs_key: true,  tier: 2 },
    SourceDef { id: "fs",  label: "FileScan.IO",      needs_key: true,  tier: 2 },
    SourceDef { id: "ms",  label: "Malshare",         needs_key: true,  tier: 2 },
];

// ── URL source registry ────────────────────────────────────────────────────────

struct UrlSourceDef {
    /// id passed to tiquery's --sources flag
    id:     &'static str,
    label:  &'static str,
    /// api key id to resolve (None = no key required)
    key_id: Option<&'static str>,
}

const URL_SOURCES: &[UrlSourceDef] = &[
    UrlSourceDef { id: "vt",      label: "VirusTotal",           key_id: Some("vt")  },
    UrlSourceDef { id: "urlscan", label: "urlscan.io",           key_id: None        },
    UrlSourceDef { id: "gsb",     label: "Google Safe Browsing", key_id: Some("gsb") },
];

// ── Panel mode (Single Hash / Bulk Lookup / URL) ──────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    SingleHash,
    Bulk,
    Url,
    Qr,
}

impl Default for Mode {
    fn default() -> Self { Mode::SingleHash }
}

// ── Deserialized result row from `tiquery --json` ─────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct ResultRow {
    source:     String,
    #[serde(default)]
    status:     serde_json::Value,   // "found" | "not_found" | "no_key" | {"error":"…"} | {"skipped":"…"}
    #[serde(default)]
    family:     Option<String>,
    #[serde(default)]
    detections: Option<String>,
    #[serde(default)]
    file_name:  Option<String>,
    #[serde(default)]
    file_type:  Option<String>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    tags:       Vec<String>,
    #[serde(default)]
    link:       Option<String>,
    #[serde(default)]
    extra:      std::collections::HashMap<String, serde_json::Value>,
}

fn status_display(val: &serde_json::Value) -> (String, Color32) {
    match val {
        serde_json::Value::String(s) => match s.as_str() {
            "found"     => ("FOUND".into(),     GREEN),
            "not_found" => ("NOT FOUND".into(), DIM_GRAY),
            "no_key"    => ("NO KEY".into(),    YELLOW),
            other       => (other.to_uppercase(), DIM_GRAY),
        },
        serde_json::Value::Object(m) => {
            if let Some(e) = m.get("error").and_then(|v| v.as_str()) {
                (format!("ERROR: {}", e), RED)
            } else if let Some(r) = m.get("skipped").and_then(|v| v.as_str()) {
                (format!("SKIPPED ({})", r), DIM_GRAY)
            } else {
                ("UNKNOWN".into(), DIM_GRAY)
            }
        }
        _ => ("?".into(), DIM_GRAY),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max.saturating_sub(1)).collect::<String>())
    }
}

// ── Runtime state shared with query thread ─────────────────────────────────────

#[derive(Default)]
struct QueryState {
    running:   bool,
    rows:      Vec<ResultRow>,
    stderr:    Vec<String>,
    dl_status: Option<String>,
}

// ── Bulk lookup state ─────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct BulkState {
    running:  bool,
    total:    usize,
    done:     usize,
    /// (hash, source_results)
    results:  Vec<(String, Vec<ResultRow>)>,
    error:    Option<String>,
    /// ordered list of source ids captured at query-start, for column headers
    columns:  Vec<String>,
}

// ── Panel ──────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TiQueryPanel {
    pub hash_input: String,
    pub url_input:  String,

    // per-source enabled flags, indexed parallel to SOURCES
    source_enabled: Vec<bool>,

    // per-URL-source enabled flags, indexed parallel to URL_SOURCES
    url_source_enabled: Vec<bool>,

    // ObjectiveSee (macOS malware catalogue)
    pub use_os: bool,

    // VT verbose (per-engine detections)
    pub vt_verbose: bool,

    // Options
    pub download_sample: bool,
    pub export_csv:      bool,
    pub save_to_case:    bool,
    pub case_name:       String,

    // Shared state with background thread
    state: Arc<Mutex<QueryState>>,

    // ── Mode (Single Hash / Bulk Lookup / URL / QR) ───────────────────────────
    pub mode:           Mode,
    bulk_file_path:     Option<String>,
    bulk_hashes:        Vec<String>,
    bulk_state:         Arc<Mutex<BulkState>>,

    // ── QR code decoding ──────────────────────────────────────────────────────
    qr_image_path:      Option<String>,
    qr_decode_error:    Option<String>,
}

impl Default for TiQueryPanel {
    fn default() -> Self {
        // Enable tier-1 sources by default; also enable any tier-2 source
        // that already has a key configured.
        let source_enabled = SOURCES
            .iter()
            .map(|s| s.tier == 1 || (!s.needs_key || common_config::resolve_api_key(s.id).is_some()))
            .collect();

        // URL sources: enabled if no key required, or the key is configured
        let url_source_enabled = URL_SOURCES
            .iter()
            .map(|s| match s.key_id {
                None => true,
                Some(kid) => common_config::resolve_api_key(kid).is_some(),
            })
            .collect();

        #[cfg(target_os = "macos")]
        let use_os = true;
        #[cfg(not(target_os = "macos"))]
        let use_os = false;

        TiQueryPanel {
            hash_input:         String::new(),
            url_input:          String::new(),
            source_enabled,
            url_source_enabled,
            use_os,
            vt_verbose:         false,
            download_sample:    false,
            export_csv:         false,
            save_to_case:       false,
            case_name:          String::new(),
            state:              Arc::new(Mutex::new(QueryState::default())),
            mode:               Mode::SingleHash,
            bulk_file_path:     None,
            bulk_hashes:        Vec::new(),
            bulk_state:         Arc::new(Mutex::new(BulkState::default())),
            qr_image_path:      None,
            qr_decode_error:    None,
        }
    }
}

impl TiQueryPanel {
    // ── Helpers ─────────────────────────────────────────────────────────────

    fn has_key(id: &str) -> bool {
        common_config::resolve_api_key(id).is_some()
    }

    fn os_cache_info() -> String {
        let cache = dirs::cache_dir()
            .unwrap_or_default()
            .join("malchela")
            .join("os-malware.json");

        if !cache.exists() {
            return "(no cache — fetched on first use)".to_string();
        }
        if let Ok(meta) = std::fs::metadata(&cache) {
            if let Ok(modified) = meta.modified() {
                if let Ok(age) = std::time::SystemTime::now().duration_since(modified) {
                    let h = age.as_secs() / 3600;
                    return if h == 0 {
                        format!("cache updated {}m ago", age.as_secs() / 60)
                    } else if h < 24 {
                        format!("cache updated {}h ago", h)
                    } else {
                        format!("cache stale ({}h) — will refresh on run", h)
                    };
                }
            }
        }
        "(cache status unknown)".to_string()
    }

    fn binary_path() -> std::path::PathBuf {
        std::path::PathBuf::from("./target/release/tiquery")
    }

    fn build_sources_arg(&self) -> String {
        if matches!(self.mode, Mode::Url | Mode::Qr) {
            let ids: Vec<&str> = URL_SOURCES
                .iter()
                .zip(self.url_source_enabled.iter())
                .filter(|(_, &en)| en)
                .map(|(s, _)| s.id)
                .collect();
            return ids.join(",");
        }
        let mut ids: Vec<&str> = SOURCES
            .iter()
            .zip(self.source_enabled.iter())
            .filter(|(_, &en)| en)
            .map(|(s, _)| s.id)
            .collect();
        if self.use_os { ids.push("os"); }
        ids.join(",")
    }

    // ── Run ─────────────────────────────────────────────────────────────────

    pub fn run_query(&self, ctx: egui::Context) {
        let (hash, is_url) = match self.mode {
            Mode::Url | Mode::Qr => (self.url_input.trim().to_string(), true),
            _ => (self.hash_input.trim().to_string(), false),
        };
        if hash.is_empty() {
            let msg = if is_url {
                "⚠ Enter a URL before running."
            } else {
                "⚠ Enter a hash before running."
            };
            self.state.lock().unwrap().stderr.push(msg.into());
            return;
        }

        if !Self::binary_path().exists() {
            self.state.lock().unwrap().stderr
                .push("✗ tiquery binary not found. Run ./release.sh first.".into());
            return;
        }

        let sources_arg = self.build_sources_arg();
        if sources_arg.is_empty() {
            self.state.lock().unwrap().stderr.push("⚠ Select at least one source.".into());
            return;
        }

        // Clear previous state
        {
            let mut st = self.state.lock().unwrap();
            st.running   = true;
            st.rows.clear();
            st.stderr.clear();
            st.dl_status = None;
        }

        let state       = Arc::clone(&self.state);
        let download    = self.download_sample && !is_url;
        let export_csv  = self.export_csv;
        let save_case   = self.save_to_case;
        let case_name   = self.case_name.clone();
        let binary      = Self::binary_path();
        let vt_idx      = SOURCES.iter().position(|s| s.id == "vt").unwrap_or(99);
        let verbose_vt  = self.vt_verbose
            && self.source_enabled.get(vt_idx).copied().unwrap_or(false);

        thread::spawn(move || {
            let mut cmd = std::process::Command::new(&binary);
            cmd.arg(&hash)
               .arg("--sources").arg(&sources_arg)
               .arg("--json")
               .env("NO_COLOR", "1")
               .env("TERM", "dumb")
               .stdout(std::process::Stdio::piped())
               .stderr(std::process::Stdio::piped());

            if verbose_vt  { cmd.arg("--verbose-vt"); }
            if download    { cmd.arg("--download"); }
            if save_case && !case_name.is_empty() {
                cmd.arg("--case").arg(&case_name).arg("-o").arg("-t");
            }

            match cmd.output() {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

                    let mut st = state.lock().unwrap();

                    // Parse JSON array from stdout
                    match serde_json::from_str::<Vec<ResultRow>>(&stdout) {
                        Ok(rows) => {
                            // CSV export: build from parsed rows so it doesn't conflict
                            // with --json on stdout.
                            if export_csv {
                                let output_dir = if save_case && !case_name.is_empty() {
                                    let p = common_config::get_output_dir("tiquery")
                                        .parent().unwrap_or(std::path::Path::new("saved_output"))
                                        .join("cases").join(&case_name).join("tiquery");
                                    let _ = std::fs::create_dir_all(&p);
                                    p
                                } else {
                                    let p = common_config::get_output_dir("tiquery");
                                    let _ = std::fs::create_dir_all(&p);
                                    p
                                };
                                let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
                                let csv_path = output_dir.join(format!("report_{}.csv", ts));
                                if let Ok(mut wtr) = csv::Writer::from_path(&csv_path) {
                                    let _ = wtr.write_record(["source","status","family","detections","file_name","file_type","first_seen","tags","link"]);
                                    for r in &rows {
                                        let status = match &r.status {
                                            serde_json::Value::String(s) => s.clone(),
                                            serde_json::Value::Object(m) => {
                                                if let Some(e) = m.get("error").and_then(|v| v.as_str()) {
                                                    format!("error: {}", e)
                                                } else { "unknown".into() }
                                            }
                                            _ => String::new(),
                                        };
                                        let _ = wtr.write_record([
                                            r.source.as_str(),
                                            &status,
                                            r.family.as_deref().unwrap_or(""),
                                            r.detections.as_deref().unwrap_or(""),
                                            r.file_name.as_deref().unwrap_or(""),
                                            r.file_type.as_deref().unwrap_or(""),
                                            r.first_seen.as_deref().unwrap_or(""),
                                            &r.tags.join("; "),
                                            r.link.as_deref().unwrap_or(""),
                                        ]);
                                    }
                                    let _ = wtr.flush();
                                    st.stderr.push(format!("CSV saved: {}", csv_path.display()));
                                }
                            }
                            st.rows = rows;
                        }
                        Err(e) => {
                            st.stderr.push(format!("JSON parse error: {}", e));
                            // Show raw stdout as fallback
                            for line in stdout.lines() {
                                if !line.trim().is_empty() {
                                    st.stderr.push(line.to_string());
                                }
                            }
                        }
                    }

                    // Collect stderr lines (migration notices, OS cache messages, download status)
                    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
                        if line.starts_with("[download]") {
                            st.dl_status = Some(line.to_string());
                        } else {
                            st.stderr.push(line.to_string());
                        }
                    }

                    st.running = false;
                }
                Err(e) => {
                    let mut st = state.lock().unwrap();
                    st.stderr.push(format!("Failed to run tiquery: {}", e));
                    st.running = false;
                }
            }

            ctx.request_repaint();
        });
    }

    // ── Bulk run ─────────────────────────────────────────────────────────────

    pub fn run_bulk(&self, ctx: egui::Context) {
        if self.bulk_hashes.is_empty() {
            self.bulk_state.lock().unwrap().error = Some("No hashes loaded. Pick a file first.".into());
            return;
        }
        if !Self::binary_path().exists() {
            self.bulk_state.lock().unwrap().error =
                Some("tiquery binary not found. Run ./release.sh first.".into());
            return;
        }

        let sources_arg = self.build_sources_arg();
        if sources_arg.is_empty() {
            self.bulk_state.lock().unwrap().error = Some("Select at least one source.".into());
            return;
        }

        // Capture column order from sources_arg
        let columns: Vec<String> = sources_arg.split(',').map(|s| s.to_uppercase()).collect();

        {
            let mut st = self.bulk_state.lock().unwrap();
            st.running  = true;
            st.total    = self.bulk_hashes.len();
            st.done     = 0;
            st.results.clear();
            st.error    = None;
            st.columns  = columns;
        }

        let bulk_state  = Arc::clone(&self.bulk_state);
        let hashes      = self.bulk_hashes.clone();
        let binary      = Self::binary_path();
        let vt_idx      = SOURCES.iter().position(|s| s.id == "vt").unwrap_or(99);
        let verbose_vt  = self.vt_verbose
            && self.source_enabled.get(vt_idx).copied().unwrap_or(false);

        thread::spawn(move || {
            for hash in &hashes {
                let mut cmd = std::process::Command::new(&binary);
                cmd.arg(hash)
                   .arg("--sources").arg(&sources_arg)
                   .arg("--json")
                   .env("NO_COLOR", "1")
                   .env("TERM", "dumb")
                   .stdout(std::process::Stdio::piped())
                   .stderr(std::process::Stdio::piped());
                if verbose_vt { cmd.arg("--verbose-vt"); }

                let rows: Vec<ResultRow> = match cmd.output() {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        serde_json::from_str(&stdout).unwrap_or_default()
                    }
                    Err(_) => vec![],
                };

                let mut st = bulk_state.lock().unwrap();
                st.results.push((hash.clone(), rows));
                st.done += 1;
                ctx.request_repaint();
                drop(st); // release lock before sleeping
                std::thread::sleep(std::time::Duration::from_millis(3000));
            }

            bulk_state.lock().unwrap().running = false;
            ctx.request_repaint();
        });
    }

    // ── UI ──────────────────────────────────────────────────────────────────

    pub fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, case_name: Option<&String>) {
        if let Some(cn) = case_name {
            if self.case_name.is_empty() {
                self.case_name = cn.clone();
            }
        }

        let running = self.state.lock().unwrap().running;

        // ── Header ──────────────────────────────────────────────────────────
        let input_label = match self.mode {
            Mode::Url => "url",
            Mode::Qr  => "qr → url",
            _         => "hash",
        };
        ui.label(
            RichText::new(format!(
                "Selected Tool: Threat Intel Query (Input: {})",
                input_label
            ))
            .color(CYAN).strong(),
        );
        let subtitle = match self.mode {
            Mode::Url => "Multi-source URL lookup: VirusTotal · urlscan.io · Google Safe Browsing",
            Mode::Qr  => "QR code decode → URL lookup: VirusTotal · urlscan.io · Google Safe Browsing",
            _         => "Multi-source hash lookup: MalwareBazaar · VirusTotal · AlienVault OTX · MetaDefender · and more",
        };
        ui.label(RichText::new(subtitle).color(STONE_BEIGE));
        ui.add_space(6.0);

        // ── Input row (hash or URL) ─────────────────────────────────────────
        if self.mode == Mode::SingleHash {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Hash:").strong());
                ui.add_enabled_ui(!running, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.hash_input)
                            .hint_text("MD5 / SHA1 / SHA256")
                            .desired_width(380.0),
                    );
                });
                ui.add_enabled_ui(!running, |ui| {
                    if ui.button("Browse…")
                        .on_hover_text("Pick a file and hash it (SHA256)")
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            match hash_file_sha256(&path) {
                                Ok(h) => {
                                    self.hash_input = h;
                                    self.state.lock().unwrap().stderr
                                        .push(format!("Hashed: {}", path.display()));
                                }
                                Err(e) => {
                                    self.state.lock().unwrap().stderr
                                        .push(format!("✗ Failed to hash file: {}", e));
                                }
                            }
                        }
                    }
                });
                ui.add_enabled_ui(!running, |ui| {
                    if ui.button(RichText::new("  Run Query  ").color(Color32::BLACK))
                        .on_hover_text("Query all enabled sources")
                        .clicked()
                    {
                        self.run_query(ctx.clone());
                    }
                });
                if running {
                    ui.label(RichText::new("⏳  Running…").color(YELLOW).strong());
                    ctx.request_repaint_after(std::time::Duration::from_millis(100));
                }
            });
        } else if self.mode == Mode::Url {
            ui.horizontal(|ui| {
                ui.label(RichText::new("URL:").strong());
                ui.add_enabled_ui(!running, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.url_input)
                            .hint_text("https://example.com/path")
                            .desired_width(380.0),
                    );
                });
                ui.add_enabled_ui(!running, |ui| {
                    if ui.button(RichText::new("  Run Query  ").color(Color32::BLACK))
                        .on_hover_text("Query all enabled URL sources")
                        .clicked()
                    {
                        self.run_query(ctx.clone());
                    }
                });
                if running {
                    ui.label(RichText::new("⏳  Running…").color(YELLOW).strong());
                    ctx.request_repaint_after(std::time::Duration::from_millis(100));
                }
            });
        }

        // ── Mode toggle (4-way) ─────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.mode, Mode::SingleHash, "Single Hash");
            ui.selectable_value(&mut self.mode, Mode::Bulk,       "Bulk Lookup");
            ui.selectable_value(&mut self.mode, Mode::Url,        "URL");
            ui.selectable_value(&mut self.mode, Mode::Qr,         "QR Code");
        });
        ui.add_space(6.0);

        // ── Input area for bulk / QR modes ──────────────────────────────────
        if self.mode == Mode::Bulk {
            self.render_bulk_input(ui, ctx);
        } else if self.mode == Mode::Qr {
            self.render_qr_input(ui, ctx);
        }

        ui.add_space(8.0);

        // ── Source checkboxes ────────────────────────────────────────────────
        if matches!(self.mode, Mode::Url | Mode::Qr) {
            self.render_url_source_section(ui);
        } else {
            self.render_source_section(ui, 1, "SOURCES — TIER 1 (FREE KEY)");
            ui.add_space(4.0);
            self.render_source_section(ui, 2, "SOURCES — TIER 2 (REGISTRATION REQUIRED)");
            ui.add_space(4.0);

            // ObjectiveSee
            ui.label(RichText::new("MACOS SOURCES (SHA256 ONLY · CACHED)").small().color(AMBER));
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.use_os, "");
                ui.label(RichText::new("ObjectiveSee").color(AMBER));
                ui.label(RichText::new("  os").color(DIM_GRAY).small());
                ui.label(RichText::new(format!("  {}", Self::os_cache_info())).color(DIM_GRAY).small());
            });
        }

        ui.add_space(6.0);

        // ── Options ──────────────────────────────────────────────────────────
        ui.label(RichText::new("OPTIONS").small().color(DIM_GRAY));
        ui.horizontal(|ui| {
            if !matches!(self.mode, Mode::Url | Mode::Qr) {
                ui.checkbox(&mut self.download_sample, "Download sample (MB only)");
                ui.separator();
            }
            ui.checkbox(&mut self.export_csv, "Export CSV");
            ui.separator();
            ui.checkbox(&mut self.save_to_case, "Save to case");
            if self.save_to_case {
                ui.add(egui::TextEdit::singleline(&mut self.case_name).desired_width(120.0));
            }
        });

        ui.add_space(4.0);

        // ── Unconfigured sources ─────────────────────────────────────────────
        let unconfigured: Vec<&str> = if matches!(self.mode, Mode::Url | Mode::Qr) {
            URL_SOURCES
                .iter()
                .enumerate()
                .filter(|(i, s)| {
                    self.url_source_enabled[*i]
                        && matches!(s.key_id, Some(kid) if common_config::resolve_api_key(kid).is_none())
                })
                .map(|(_, s)| s.label)
                .collect()
        } else {
            SOURCES
                .iter()
                .enumerate()
                .filter(|(i, s)| s.needs_key && self.source_enabled[*i] && !Self::has_key(s.id))
                .map(|(_, s)| s.label)
                .collect()
        };

        if !unconfigured.is_empty() {
            ui.label(RichText::new("UNCONFIGURED SOURCES (KEYS MISSING)").small().color(ORANGE));
            ui.horizontal(|ui| {
                for label in &unconfigured {
                    ui.label(
                        RichText::new(format!("{} — no key", label))
                            .color(ORANGE).small(),
                    );
                    ui.label(RichText::new("  ·  ").color(DIM_GRAY));
                }
            });
            ui.add_space(4.0);
        }

        ui.separator();

        // ── Results ──────────────────────────────────────────────────────────
        if self.mode == Mode::Bulk {
            // ── Bulk results ─────────────────────────────────────────────────
            let bulk = self.bulk_state.lock().unwrap().clone();
            if bulk.running || !bulk.results.is_empty() || bulk.error.is_some() {
                if bulk.running {
                    ui.label(
                        RichText::new(format!("⏳  Running… {}/{}", bulk.done, bulk.total))
                            .color(YELLOW).strong(),
                    );
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                }
                if let Some(e) = &bulk.error {
                    ui.label(RichText::new(e).color(RED));
                }
                if !bulk.results.is_empty() {
                    ScrollArea::vertical().id_source("tiquery_bulk_results").show(ui, |ui| {
                        render_bulk_table(ui, &bulk);
                    });
                }
            } else {
                ui.label(RichText::new("Load a file and run bulk query.").color(DIM_GRAY));
            }
        } else {
            // ── Single-hash results ───────────────────────────────────────────
            let (rows, stderr, dl_status) = {
                let st = self.state.lock().unwrap();
                (st.rows.clone(), st.stderr.clone(), st.dl_status.clone())
            };

            if rows.is_empty() && stderr.is_empty() {
                ui.label(RichText::new("Results will appear here after running a query.").color(DIM_GRAY));
            } else {
                ScrollArea::vertical().id_source("tiquery_results").show(ui, |ui| {
                    if let Some(dl) = &dl_status {
                        ui.add_space(4.0);
                        ui.label(RichText::new(dl).color(GREEN).strong());
                        ui.add_space(4.0);
                    }
                    if !rows.is_empty() {
                        render_results_table(ui, &rows);
                    }
                    if !stderr.is_empty() {
                        ui.add_space(6.0);
                        ui.separator();
                        for line in &stderr {
                            let color = if line.contains("error") || line.contains("✗") {
                                RED
                            } else if line.contains("⚠") || line.contains("warn") {
                                YELLOW
                            } else {
                                DIM_GRAY
                            };
                            ui.label(RichText::new(line).small().color(color).monospace());
                        }
                    }
                });
            }
        }
    }

    fn render_qr_input(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let running = self.state.lock().unwrap().running;

        ui.horizontal(|ui| {
            ui.label(RichText::new("Image:").strong());
            if let Some(path) = &self.qr_image_path {
                ui.label(RichText::new(path).color(STONE_BEIGE).monospace());
            } else {
                ui.label(RichText::new("No image selected").color(DIM_GRAY));
            }
            ui.add_enabled_ui(!running, |ui| {
                if ui.button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Images", &["png", "jpg", "jpeg", "gif", "bmp", "webp"])
                        .pick_file()
                    {
                        self.qr_decode_error = None;
                        self.qr_image_path = Some(path.display().to_string());
                        match decode_qr(&path) {
                            Ok(decoded) => { self.url_input = decoded; }
                            Err(e) => {
                                self.qr_decode_error = Some(e);
                                self.url_input.clear();
                            }
                        }
                    }
                }
            });
        });

        ui.add_space(4.0);

        if let Some(err) = &self.qr_decode_error {
            ui.label(RichText::new(format!("✗ QR decode failed: {}", err)).color(RED));
            ui.add_space(4.0);
        }

        // Decoded URL — editable so the analyst can confirm / edit before submitting
        ui.horizontal(|ui| {
            ui.label(RichText::new("URL:").strong());
            ui.add_enabled_ui(!running, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.url_input)
                        .hint_text("Decoded URL will appear here")
                        .desired_width(380.0),
                );
            });
            let can_run = !self.url_input.trim().is_empty();
            ui.add_enabled_ui(!running && can_run, |ui| {
                if ui.button(RichText::new("  Run Query  ").color(Color32::BLACK))
                    .on_hover_text("Query all enabled URL sources")
                    .clicked()
                {
                    self.run_query(ctx.clone());
                }
            });
            if running {
                ui.label(RichText::new("⏳  Running…").color(YELLOW).strong());
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
        });
    }

    fn render_bulk_input(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let bulk_running = self.bulk_state.lock().unwrap().running;

        ui.horizontal(|ui| {
            ui.label(RichText::new("File:").strong());
            if let Some(path) = &self.bulk_file_path {
                ui.label(RichText::new(path).color(STONE_BEIGE).monospace());
            } else {
                ui.label(RichText::new("No file selected").color(DIM_GRAY));
            }
            ui.add_enabled_ui(!bulk_running, |ui| {
                if ui.button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Hash lists", &["txt", "csv"])
                        .pick_file()
                    {
                        let path_str = path.display().to_string();
                        let hashes = parse_hash_file(&path);
                        self.bulk_hashes = hashes;
                        self.bulk_file_path = Some(path_str);
                    }
                }
            });
            if !self.bulk_hashes.is_empty() {
                ui.label(
                    RichText::new(format!("{} hashes loaded", self.bulk_hashes.len()))
                        .color(GREEN),
                );
            }
        });

        ui.add_space(4.0);
        ui.add_enabled_ui(!bulk_running && !self.bulk_hashes.is_empty(), |ui| {
            if ui.button(RichText::new("  Run Bulk Query  ").color(Color32::BLACK))
                .on_hover_text("Query all hashes against enabled sources")
                .clicked()
            {
                self.run_bulk(ctx.clone());
            }
        });
    }

    fn render_url_source_section(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("URL SOURCES").small().color(DIM_GRAY));

        egui::Grid::new("tiquery_url_sources")
            .num_columns(2)
            .spacing([20.0, 3.0])
            .show(ui, |ui| {
                for (idx, src) in URL_SOURCES.iter().enumerate() {
                    let avail = match src.key_id {
                        None => true,
                        Some(kid) => common_config::resolve_api_key(kid).is_some(),
                    };
                    let color = if avail { Color32::WHITE } else { DIM_GRAY };

                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(avail, |ui| {
                            ui.checkbox(&mut self.url_source_enabled[idx], "");
                        });
                        ui.label(RichText::new(src.label).color(color));
                        ui.label(RichText::new(format!(" {}", src.id)).color(DIM_GRAY).small());
                        if src.key_id.is_none() {
                            ui.label(RichText::new("  (no key required)").small().color(DIM_GRAY));
                        }
                    });

                    if (idx + 1) % 2 == 0 { ui.end_row(); }
                }
                if URL_SOURCES.len() % 2 != 0 { ui.label(""); ui.end_row(); }
            });
    }

    fn render_source_section(&mut self, ui: &mut egui::Ui, tier: u8, label: &str) {
        ui.label(RichText::new(label).small().color(DIM_GRAY));

        let indices: Vec<usize> = SOURCES
            .iter()
            .enumerate()
            .filter(|(_, s)| s.tier == tier)
            .map(|(i, _)| i)
            .collect();

        egui::Grid::new(format!("tiquery_tier{}", tier))
            .num_columns(2)
            .spacing([20.0, 3.0])
            .show(ui, |ui| {
                for (pos, &idx) in indices.iter().enumerate() {
                    let src   = &SOURCES[idx];
                    let avail = !src.needs_key || Self::has_key(src.id);
                    let color = if avail { Color32::WHITE } else { DIM_GRAY };

                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(avail, |ui| {
                            ui.checkbox(&mut self.source_enabled[idx], "");
                        });
                        ui.label(RichText::new(src.label).color(color));
                        ui.label(RichText::new(format!(" {}", src.id)).color(DIM_GRAY).small());

                        // VT-specific: per-engine verbose toggle
                        if src.id == "vt" && self.source_enabled[idx] {
                            ui.add_space(6.0);
                            ui.checkbox(&mut self.vt_verbose, "");
                            ui.label(RichText::new("per-engine").small().color(DIM_GRAY));
                        }
                    });

                    if (pos + 1) % 2 == 0 { ui.end_row(); }
                }
                if indices.len() % 2 != 0 { ui.label(""); ui.end_row(); }
            });
    }
}

// ── Table renderer ────────────────────────────────────────────────────────────

fn render_results_table(ui: &mut egui::Ui, rows: &[ResultRow]) {
    let frame = egui::Frame::default()
        .fill(Color32::from_rgb(25, 25, 30))
        .inner_margin(egui::Margin::same(8.0));

    frame.show(ui, |ui| {
        egui::Grid::new("tiquery_results_grid")
            .striped(true)
            .num_columns(5)
            .min_col_width(60.0)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                // Header row
                for col in &["Source", "Status", "Family / Tags", "Detections", "Reference"] {
                    ui.label(RichText::new(*col).strong().color(CYAN).monospace());
                }
                ui.end_row();

                for row in rows {
                    let (status_txt, status_color) = status_display(&row.status);
                    let is_found = status_txt == "FOUND";

                    // Source name
                    ui.label(
                        RichText::new(&row.source)
                            .monospace()
                            .color(if is_found { GREEN } else { DIM_GRAY })
                            .strong(),
                    );

                    // Status badge
                    ui.label(
                        RichText::new(&status_txt)
                            .monospace()
                            .color(status_color)
                            .strong(),
                    );

                    // Family / Tags (combined)
                    let family_tags = build_family_tags(row);
                    ui.label(
                        RichText::new(truncate(&family_tags, 28))
                            .monospace()
                            .color(if is_found { STONE_BEIGE } else { DIM_GRAY }),
                    );

                    // Detections (red if non-zero, dim otherwise)
                    let det = row.detections.as_deref().unwrap_or("–");
                    let det_color = if is_found && det != "–" && !det.starts_with("0/") {
                        RED
                    } else {
                        DIM_GRAY
                    };
                    ui.label(RichText::new(det).monospace().color(det_color));

                    // Reference — clickable hyperlink
                    if let Some(link) = &row.link {
                        ui.add(egui::Hyperlink::from_label_and_url("🔗 open", link)
                            .open_in_new_tab(true));
                    } else {
                        ui.label(RichText::new("–").color(DIM_GRAY));
                    }

                    ui.end_row();

                    // Extra detail row: file name · file type · first seen (when found)
                    if is_found {
                        let detail = build_detail_line(row);
                        if !detail.is_empty() {
                            ui.label(""); // source col blank
                            ui.label(""); // status col blank
                            ui.label(
                                RichText::new(truncate(&detail, 70))
                                    .small()
                                    .color(DIM_GRAY)
                                    .monospace(),
                            );
                            ui.label("");
                            ui.label("");
                            ui.end_row();
                        }

                        // Per-engine rows (VT verbose mode)
                        if let Some(engines) = row.extra.get("engines").and_then(|v| v.as_array()) {
                            for engine in engines {
                                let eng  = engine.get("engine").and_then(|v| v.as_str()).unwrap_or("");
                                let cat  = engine.get("category").and_then(|v| v.as_str()).unwrap_or("");
                                let res  = engine.get("result").and_then(|v| v.as_str()).unwrap_or("");
                                let cat_color = if cat == "malicious" { RED } else { YELLOW };

                                ui.label(RichText::new(format!("  {}", eng)).small().monospace().color(DIM_GRAY));
                                ui.label(RichText::new(cat).small().monospace().color(cat_color));
                                ui.label(RichText::new(truncate(res, 28)).small().monospace().color(STONE_BEIGE));
                                ui.label("");
                                ui.label("");
                                ui.end_row();
                            }
                        }
                    }
                }
            });
    });
}

fn build_family_tags(row: &ResultRow) -> String {
    let f = row.family.as_deref().unwrap_or("");
    let t = if !row.tags.is_empty() {
        row.tags.join(", ")
    } else {
        String::new()
    };
    match (f.is_empty(), t.is_empty()) {
        (false, false) => format!("{} · {}", f, t),
        (false, true)  => f.to_string(),
        (true,  false) => t,
        (true,  true)  => String::new(),
    }
}

fn build_detail_line(row: &ResultRow) -> String {
    let mut parts = vec![];
    if let Some(n) = &row.file_name  { if !n.is_empty() { parts.push(format!("name: {}", n)); } }
    if let Some(t) = &row.file_type  { if !t.is_empty() { parts.push(format!("type: {}", t)); } }
    if let Some(d) = &row.first_seen { if !d.is_empty() { parts.push(format!("first seen: {}", d)); } }
    parts.join("  ·  ")
}

// ── File hasher (SHA256) ──────────────────────────────────────────────────────

fn hash_file_sha256(path: &std::path::Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
}

// ── QR code decoder ───────────────────────────────────────────────────────────

fn decode_qr(path: &std::path::Path) -> Result<String, String> {
    let base = image::open(path).map_err(|e| format!("open image: {}", e))?.to_luma8();

    // Try the original first, then progressively upscaled copies (2×, 3×, 4×).
    // rqrr needs a sufficient module size to lock on; small or bordered QRs
    // (common in phishing emails) often fail without this.
    let (w, h) = (base.width(), base.height());
    let scales: &[u32] = &[1, 2, 3, 4];
    let mut last_err: Option<String> = None;

    for &s in scales {
        let candidate = if s == 1 {
            base.clone()
        } else {
            image::imageops::resize(
                &base,
                w * s,
                h * s,
                image::imageops::FilterType::Lanczos3,
            )
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

// ── Hash file parser ──────────────────────────────────────────────────────────

fn is_hash(s: &str) -> bool {
    let t = s.trim();
    matches!(t.len(), 32 | 40 | 64) && t.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_hash_file(path: &std::path::Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else { return vec![]; };
    let mut seen = std::collections::HashSet::new();
    let mut hashes = Vec::new();

    // Try CSV: scan every field in every row
    if path.extension().map(|e| e == "csv").unwrap_or(false) {
        for line in content.lines() {
            for field in line.split(',') {
                let h = field.trim().to_lowercase();
                if is_hash(&h) && seen.insert(h.clone()) {
                    hashes.push(h);
                }
            }
        }
    } else {
        // TXT: one hash per line (also handles CSV-ish files without .csv extension)
        for line in content.lines() {
            // Try each whitespace/comma-separated token
            for token in line.split(|c: char| c.is_whitespace() || c == ',') {
                let h = token.trim().to_lowercase();
                if is_hash(&h) && seen.insert(h.clone()) {
                    hashes.push(h);
                }
            }
        }
    }
    hashes
}

// ── Bulk results table ────────────────────────────────────────────────────────

/// Returns (short label, color, optional hover detail for errors/skips).
fn bulk_status_short(val: &serde_json::Value) -> (&'static str, Color32, Option<String>) {
    match val {
        serde_json::Value::String(s) => match s.as_str() {
            "found"     => ("FOUND",  GREEN,    None),
            "not_found" => ("–",      DIM_GRAY, None),
            "no_key"    => ("NO KEY", YELLOW,   None),
            other       => ("?",      DIM_GRAY, Some(other.to_string())),
        },
        serde_json::Value::Object(m) => {
            if let Some(e) = m.get("error").and_then(|v| v.as_str()) {
                ("ERR", RED, Some(e.to_string()))
            } else if let Some(r) = m.get("skipped").and_then(|v| v.as_str()) {
                ("–", DIM_GRAY, Some(format!("skipped: {}", r)))
            } else {
                ("?", DIM_GRAY, None)
            }
        }
        _ => ("?", DIM_GRAY, None),
    }
}

fn render_bulk_table(ui: &mut egui::Ui, bulk: &BulkState) {
    let frame = egui::Frame::default()
        .fill(Color32::from_rgb(25, 25, 30))
        .inner_margin(egui::Margin::same(8.0));

    frame.show(ui, |ui| {
        // Number of columns: hash + one per source + family summary
        let ncols = 2 + bulk.columns.len();

        egui::Grid::new("tiquery_bulk_grid")
            .striped(true)
            .num_columns(ncols)
            .min_col_width(50.0)
            .spacing([10.0, 5.0])
            .show(ui, |ui| {
                // Header
                ui.label(RichText::new("Hash").strong().color(CYAN).monospace());
                for col in &bulk.columns {
                    ui.label(RichText::new(col).strong().color(CYAN).monospace());
                }
                ui.label(RichText::new("Family / Tags").strong().color(CYAN).monospace());
                ui.end_row();

                for (hash, rows) in &bulk.results {
                    // Short hash display
                    let short = if hash.len() >= 16 {
                        format!("{}…", &hash[..16])
                    } else {
                        hash.clone()
                    };
                    ui.label(RichText::new(&short).monospace().color(STONE_BEIGE))
                        .on_hover_text(hash);

                    // Per-source status cell
                    let mut family_tags = String::new();
                    for col in &bulk.columns {
                        if let Some(row) = rows.iter().find(|r| r.source.to_uppercase() == *col) {
                            let (label, color, detail) = bulk_status_short(&row.status);
                            let cell = ui.label(RichText::new(label).monospace().color(color).strong());
                            if let Some(msg) = detail {
                                cell.on_hover_text(msg);
                            }
                            if family_tags.is_empty() {
                                family_tags = build_family_tags(row);
                            }
                        } else {
                            ui.label(RichText::new("–").color(DIM_GRAY));
                        }
                    }

                    // Family / tags (first found source wins)
                    ui.label(
                        RichText::new(truncate(&family_tags, 30))
                            .monospace()
                            .small()
                            .color(STONE_BEIGE),
                    );
                    ui.end_row();
                }
            });

        // Progress note if still running
        if bulk.running {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("  {}/{} complete", bulk.done, bulk.total))
                    .small()
                    .color(DIM_GRAY),
            );
        }
    });
}
