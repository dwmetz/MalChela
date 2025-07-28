
use eframe::egui::{ScrollArea, Ui, ComboBox, RichText, Color32, Label};
use eframe::egui::{Layout, Align};
use crate::AppState;
use common_ui::parse_colored_output;

use eframe::egui::Id;
use lazy_static::lazy_static;
lazy_static! {
    static ref ID_APP_STATE: Id = Id::new("app_state");
}
use std::sync::{Arc, Mutex};
use std::io::Write;
use walkdir::WalkDir;
use std::path::PathBuf;


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileMinerResult {
    #[serde(default)]
    pub filename: String,
    #[serde(rename = "filepath")]
    pub path: String,
    pub filetype: String,
    pub size: u64,
    pub sha256: String,
    pub md5: Option<String>,
    #[serde(alias = "extension", alias = "extension_label")]
    pub extension: String,
    #[serde(rename = "extension_inferred", default)]
    pub inferred: String,
    #[serde(rename = "extension_mismatch", default)]
    pub mismatch: bool,
    /// The suggested tool for this file, if any. Should be a single tool name (not a Vec).
    pub suggested_tool: Option<String>,
    #[serde(skip)]
    pub selected_tool_outputs: Vec<(String, String)>, // (tool name, format)
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub name: String,
    pub path: String,
    pub extension: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub suggested_tool: Option<String>,
}

pub fn scan_directory_for_files(path: &std::path::Path) -> Vec<FileMetadata> {
    let mut results = vec![];

    if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
            if entry.path().is_file() {
                let file_path = entry.path().to_path_buf();
                results.push(FileMetadata {
                    name: file_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    path: file_path.display().to_string(),
                    extension: file_path.extension().map(|e| e.to_string_lossy().to_string()),
                    size: 0,
                    sha256: String::new(),
                    suggested_tool: None,
                });
            }
        }
    }

    results
}

#[derive(Clone)]
pub struct FileMinerPanel {
    pub visible: bool,
    pub results: Vec<FileMinerResult>,
    pub selected_index: Option<usize>,
    pub input_dir: String,
    pub save_report: bool,
    pub output_format: String,
    pub show_mismatches_only: bool,
    pub is_running: bool,
    pub subtool_output: String,
    pub pending_output: Arc<Mutex<Option<String>>>,
    pub is_minimized: bool,
    pub has_run: bool,
    pub last_scan_timestamp: String,
}

impl Default for FileMinerPanel {
    fn default() -> Self {
        FileMinerPanel {
            results: Vec::new(),
            selected_index: None,
            input_dir: String::new(),
            save_report: false,
            output_format: "TXT".to_string(),
            show_mismatches_only: false,
            is_running: false,
            subtool_output: String::new(),
            pending_output: Arc::new(Mutex::new(None)),
            is_minimized: false,
            has_run: false,
            visible: false,
            last_scan_timestamp: String::new(),
        }
    }
}

impl FileMinerPanel {
    pub fn reset_panel(&mut self) {
        self.visible = false;
        self.input_dir = String::new();
        self.save_report = false;
        self.output_format = "TXT".to_string();
        self.show_mismatches_only = false;
        self.is_running = false;
        self.subtool_output.clear();
        self.pending_output = Arc::new(Mutex::new(None));
        self.is_minimized = false;
        self.has_run = false;
        self.last_scan_timestamp = String::new();
        self.results.clear();
        self.selected_index = None;
    }
    

    pub fn run_fileminer_scan_and_save(&mut self, case_name: &str) {
        self.save_report = true;
        self.output_format = "JSON".to_string();
        self.run_fileminer_scan_with_case(Some(case_name.to_string()));
    }


    pub fn run_fileminer_scan(&mut self) {
        self.run_fileminer_scan_with_case(None);
    }


    pub fn run_fileminer_scan_with_case(&mut self, case_name_opt: Option<String>) {
        if self.input_dir.trim().is_empty() {
            return;
        }

        let path = std::path::Path::new(&self.input_dir);
        if path.exists() && path.is_dir() {
            let metadata_results = scan_directory_for_files(path);
            self.results = metadata_results
                .into_iter()
                .map(|meta| FileMinerResult {
                    filename: meta.name,
                    path: meta.path,
                    filetype: meta.extension.clone().unwrap_or_default(), // fallback
                    size: meta.size,
                    sha256: meta.sha256,
                    md5: None,
                    extension: meta.extension.unwrap_or_default(),
                    inferred: "".to_string(),
                    mismatch: false,
                    suggested_tool: meta.suggested_tool,
                    selected_tool_outputs: vec![],
                })
                .collect();
            self.subtool_output.clear();


            if self.save_report {
                use chrono::Local;
                let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
                self.last_scan_timestamp = timestamp.clone();
                let output_path = if let Some(case_name) = case_name_opt {
                    format!("saved_output/cases/{}/fileminer/fileminer_report_{}.json", case_name, timestamp)
                } else {
                    format!("saved_output/fileminer/fileminer_report_{}.json", timestamp)
                };
                let output_str = serde_json::to_string_pretty(&self.results).unwrap_or_default();
                let parent_dir = std::path::Path::new(&output_path).parent().unwrap_or_else(|| std::path::Path::new("saved_output"));
                if let Err(e) = std::fs::create_dir_all(parent_dir) {
                    eprintln!("❌ Failed to create output directory: {e}");
                }
                if let Err(e) = std::fs::write(&output_path, output_str.as_bytes()) {
                    eprintln!("❌ Failed to write report to file: {e}");
                }
            }
        }
    }
    pub fn load_from_json(&mut self, json_data: &str) -> Result<(), String> {
        let json_start = json_data.find('{').ok_or("No JSON object found in input")?;
        let json_cleaned = &json_data[json_start..];
        let json: serde_json::Value = serde_json::from_str(json_cleaned)
            .map_err(|e| format!("Failed to parse JSON: {e}"))?;
        let entries: Vec<FileMinerResult> = if let Some(results) = json.get("results") {
            match serde_json::from_value(results.clone()) {
                Ok(results) => {
                    results
                }
                Err(e) => {
                    return Err(format!("Failed to parse 'results' array: {e}"));
                }
            }
        } else {
            let raw_entries: Vec<serde_json::Value> =
                match serde_json::from_str(json_cleaned) {
                    Ok(entries) => entries,
                    Err(e) => {
                        return Err(format!("Failed to parse FileMiner output: {e}"));
                    }
                };

            let mut parsed_results = Vec::new();
            for (i, entry) in raw_entries.into_iter().enumerate() {
                let mut map = entry.as_object().cloned().unwrap_or_default();
                map.entry("index").or_insert(serde_json::Value::from(i));
                map.entry("path").or_insert_with(|| serde_json::Value::String(String::new()));
                map.entry("filename").or_insert_with(|| serde_json::Value::String(String::new()));
                map.entry("filetype").or_insert_with(|| serde_json::Value::String(String::new()));
                map.entry("size").or_insert(serde_json::Value::from(0));
                map.entry("sha256").or_insert_with(|| serde_json::Value::String(String::new()));
                let ext_value = map.get("extension_label")
                    .and_then(|v| v.as_str())
                    .map(|s| serde_json::Value::String(s.to_string()))
                    .or_else(|| {
                        let fname = map.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                        std::path::Path::new(fname)
                            .extension()
                            .and_then(|e| e.to_str())
                            .map(|s| serde_json::Value::String(s.to_string()))
                    })
                    .unwrap_or_else(|| serde_json::Value::String(String::new()));
                map.insert("extension".to_string(), ext_value);
                map.entry("inferred").or_insert_with(|| serde_json::Value::String(String::new()));
                map.entry("mismatch").or_insert(serde_json::Value::from(false));
                map.entry("suggested_tool").or_insert_with(|| {
                    serde_json::Value::Array(vec![])
                });
                let filepath = map.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let index = map.get("index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(i as u64) as usize;
                map.insert("path".to_string(), serde_json::Value::String(filepath.clone()));
                map.insert("index".to_string(), serde_json::Value::Number(serde_json::Number::from(index)));

                let result: FileMinerResult = match serde_json::from_value(serde_json::Value::Object(map)) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(format!("Failed to deserialize FileMinerResult: {e}"));
                    }
                };
                parsed_results.push(result);
            }
            parsed_results
        };
        self.results = entries;
        Ok(())
    }

    pub fn show(&mut self, ui: &mut Ui, app_state: &crate::AppState) {
        if app_state.current_panel != crate::ActivePanel::FileMiner {
            return;
        }
        let current_case = app_state.case_name.clone().unwrap_or_default();
        if !self.has_run && !self.input_dir.trim().is_empty()
            && self.results.iter().all(|r| r.sha256.is_empty())
            && !self.is_running {
            self.output_format = "JSON".to_string();
            self.is_running = true;
            let case_name = app_state.case_name.clone().unwrap_or_default();
            let input_dir = self.input_dir.clone();
            let save_report = true;
            let output_format = self.output_format.clone();
            let show_mismatches_only = self.show_mismatches_only;
            let pending_output = Arc::clone(&self.pending_output);

            std::thread::spawn(move || {
                let mut cmd = if cfg!(debug_assertions) {
                    let mut c = std::process::Command::new("cargo");
                    c.args(["run", "-p", "fileminer", "--"]);
                    c
                } else {
                    std::process::Command::new("./target/release/fileminer")
                };
                if let Ok(exe_path) = std::env::current_exe() {
                    if let Some(project_root) = exe_path.parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.parent())
                        .map(|p| p.to_path_buf()) {
                        cmd.current_dir(project_root);
                    }
                }

                if save_report {
                    cmd.arg("-o");
                    match output_format.as_str() {
                        "TXT" => { cmd.arg("-t"); },
                        "JSON" => { cmd.arg("-j"); },
                        "Markdown" => { cmd.arg("-m"); },
                        _ => {}
                    }
                }

                if show_mismatches_only {
                    cmd.arg("--mismatch");
                }

                cmd.arg("--no-prompt");
                cmd.arg(&input_dir);

                std::io::stderr().flush().ok();

                let output = cmd.output().expect("Failed to execute fileminer");
                if !output.status.success() {
                    eprintln!("❌ fileminer process exited with non-zero status: {}", output.status);
                }
                let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr);

                if save_report {
                    if !case_name.is_empty() {
                        let case_output_dir = PathBuf::from(format!("saved_output/cases/{}/fileminer", case_name));
                        std::fs::create_dir_all(&case_output_dir).ok();
                        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                        let ext = match output_format.to_lowercase().as_str() {
                            "json" => "json",
                            "markdown" | "md" => "md",
                            _ => "txt",
                        };
                        let filename = format!("fileminer_report_{}.{}", timestamp, ext);
                        let final_path = case_output_dir.join(filename);
                        if let Err(e) = std::fs::write(&final_path, stdout.as_bytes()) {
                            eprintln!("❌ Failed to write report to file: {e}");
                        }

                        let file_content = std::fs::read_to_string(&final_path);
                        stdout = match file_content {
                            Ok(content) => content,
                            Err(e) => {
                                eprintln!("❌ Failed to read FileMiner output file: {e}");
                                String::new()
                            }
                        };
                    }
                }

                let mut result = pending_output.lock().unwrap();
                if !stdout.trim().is_empty() {
                    *result = Some(stdout);
                } else if !stderr.trim().is_empty() {
                    *result = Some(format!("⚠️ STDERR:\n{stderr}"));
                } else {
                    *result = Some("⚠️ No output received from fileminer.".to_string());
                }
            });

            self.has_run = true;
        }

        ui.label(
            eframe::egui::RichText::new("Selected Tool: FileMiner (Input: folder)")
                .color(eframe::egui::Color32::from_rgb(0, 255, 255)),
        );
        ui.label(
            eframe::egui::RichText::new("Scans a folder and identifies files of forensic interest.")
                .color(eframe::egui::Color32::from_rgb(200, 200, 200)),
        );

        ui.horizontal(|ui| {
            ui.label("Folder Path:");
            ui.text_edit_singleline(&mut self.input_dir);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.input_dir = path.display().to_string();
                }
            }
        });

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_mismatches_only, "Show mismatches only");
            ui.checkbox(&mut self.save_report, "💾 Save Report");

            if self.save_report {
                ui.label("Output format:");
                ComboBox::from_id_source("output_format_combo")
                    .selected_text(&self.output_format)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.output_format, "TXT".to_string(), "TXT");
                        ui.selectable_value(&mut self.output_format, "JSON".to_string(), "JSON");
                        ui.selectable_value(&mut self.output_format, "Markdown".to_string(), "Markdown");
                    });
            }
        });

        ui.add_space(10.0);

        if ui.button("Run").clicked() {
            if !self.input_dir.trim().is_empty() {
                self.is_running = true;
                let path = self.input_dir.clone();
                let save_report = self.save_report;
                let output_format = self.output_format.clone();
                let show_mismatches_only = self.show_mismatches_only;
                let pending_output = Arc::clone(&self.pending_output);
                let current_case = current_case.clone();

                std::thread::spawn(move || {
                    if let Ok(_cwd) = std::env::current_dir() {

                    }

                    let mut output_override_path: Option<String> = None;
                    if save_report && !current_case.is_empty() {
                        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                        let ext = match output_format.to_lowercase().as_str() {
                            "json" => "json",
                            "markdown" | "md" => "md",
                            _ => "txt",
                        };
                        let filename = format!("fileminer_report_{}.{}", timestamp, ext);
                        let final_path = PathBuf::from(format!("saved_output/cases/{}/fileminer", current_case)).join(filename);
                        std::fs::create_dir_all(final_path.parent().unwrap_or_else(|| std::path::Path::new(""))).ok();
                        output_override_path = Some(final_path.to_string_lossy().to_string());
                    }


                    let mut cmd = if cfg!(debug_assertions) {
                        let mut c = std::process::Command::new("cargo");
                        c.args(["run", "-p", "fileminer", "--"]);
                        c
                    } else {
                        let c = std::process::Command::new("./target/release/fileminer");
                        c
                    };
                    if let Ok(exe_path) = std::env::current_exe() {
                        if let Some(project_root) = exe_path.parent()
                            .and_then(|p| p.parent())
                            .and_then(|p| p.parent())
                            .map(|p| p.to_path_buf()) {
                            cmd.current_dir(project_root);
                        }
                    }


                    if save_report {
                        cmd.arg("-o");
                        if let Some(ref path) = output_override_path {
                            cmd.arg(path);
                        }
                        match output_format.as_str() {
                            "TXT" => { cmd.arg("-t"); },
                            "JSON" => { cmd.arg("-j"); },
                            "Markdown" => { cmd.arg("-m"); },
                            _ => {}
                        }
                    }


                    if show_mismatches_only {
                        cmd.arg("--mismatch");
                    }

                    cmd.arg("--no-prompt");
                    cmd.arg(&path);

                    std::io::stderr().flush().ok();

                    let output = cmd.output().expect("Failed to execute fileminer");
                    if !output.status.success() {
                        eprintln!("❌ fileminer process exited with non-zero status: {}", output.status);
                    }
                    let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr);


                    if save_report {
                        if let Some(ref override_path) = output_override_path {
                            // --- Insert logic to read the file content back into stdout ---
                            let file_content = std::fs::read_to_string(override_path);
                            stdout = match file_content {
                                Ok(content) => content,
                                Err(e) => {
                                    eprintln!("❌ Failed to read FileMiner output file: {e}");
                                    String::new()
                                }
                            };
                        } else if current_case.is_empty() {
                            eprintln!("⚠️ No case name set — skipping report save.");
                        }
                    }

                    let mut result = pending_output.lock().unwrap();
                    if !stdout.trim().is_empty() {
                        *result = Some(stdout);
                    } else if !stderr.trim().is_empty() {
                        *result = Some(format!("⚠️ STDERR:\n{stderr}"));
                    } else {
                        *result = Some("⚠️ No output received from fileminer.".to_string());
                    }
                });
            }
        }

        ui.separator();


        let maybe_json = self.pending_output.lock().unwrap().take();
        if let Some(json) = maybe_json {
            if let Err(_err) = self.load_from_json(&json) {

            }
            self.is_running = false;
            ui.ctx().request_repaint();
        }

        if self.is_running {
            ui.label(eframe::egui::RichText::new("🏃 Running...").color(eframe::egui::Color32::from_rgb(0, 255, 255)).strong());
        }


        if !self.subtool_output.trim().is_empty() {
            ui.label(eframe::egui::RichText::new("Subtool Output").heading().color(eframe::egui::Color32::from_rgb(215, 100, 30)));
            ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                for (line, color) in parse_colored_output(&self.subtool_output) {
                    ui.colored_label(color, line);
                }
            });
            ui.separator();
        }

        ui.horizontal(|ui| {
            ui.label(
                eframe::egui::RichText::new("📁 FileMiner Results")
                    .color(eframe::egui::Color32::from_rgb(215, 100, 30))
                    .heading(),
            );
            ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
                if ui.button("📁 View Reports").clicked() {

                    let case_output_folder = if let Some(case_name) = app_state.case_name.clone() {
                        std::path::Path::new("saved_output")
                            .join("cases")
                            .join(&case_name)
                            .join("fileminer")
                    } else {
                        std::path::Path::new("saved_output").to_path_buf()
                    };
                    if let Err(e) = opener::open(&case_output_folder) {
                        eprintln!("❌ Failed to open reports directory: {e}");
                    }
                }
                if ui.button("❌ Clear Results").clicked() {
                    self.subtool_output.clear();
                }

                if ui.button("📁 Case").clicked() {
                    let ctx = ui.ctx();
                    ctx.data_mut(|d| {
                        let app_state = d.get_temp_mut_or(*ID_APP_STATE, AppState::default());
                        app_state.case_modal.show_modal = true;
                        app_state.fileminer_panel.visible = false;
                    });
                }
                // --- Insert "Select All Tools" button here ---
                if ui.button("✅ Select All Tools").clicked() {
                    for result in self.results.iter_mut() {
                        let mut selectable_tools = Vec::new();
                        if result.filetype.contains("portable-executable") {
                            selectable_tools.push("fileanalyzer");
                            selectable_tools.push("mstrings");
                            selectable_tools.push("malhash");
                            selectable_tools.push("nsrlquery");
                        } else if result.filetype == "Unknown" && result.size > 10_000 {
                            selectable_tools.push("fileanalyzer");
                            selectable_tools.push("malhash");
                            selectable_tools.push("nsrlquery");
                        }
                        for tool_name in selectable_tools {
                            if !result.selected_tool_outputs.iter().any(|(t, _)| t == tool_name) {
                                result.selected_tool_outputs.push((tool_name.to_string(), "TXT".to_string()));
                            }
                        }
                    }
                }
                if ui.button("▶ Run Selected Tools").clicked() {

                    let use_case = app_state.case_name.is_some();
                    let case_name = app_state.case_name.clone().unwrap_or_default();
                    let _current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
                    for result in self.results.iter_mut() {
                        for (tool_name, _format) in &result.selected_tool_outputs {
                            let lowercase_tool = tool_name.to_lowercase();
                            // Output folder for this tool, case-based or default
                            let case_output_folder = if use_case {
                                std::path::Path::new("saved_output")
                                    .join("cases")
                                    .join(&case_name)
                                    .join(&lowercase_tool)
                            } else {
                                std::path::Path::new("saved_output")
                                    .join(&lowercase_tool)
                            };
                            std::fs::create_dir_all(&case_output_folder).ok();
                            let (input, _is_hash_tool) = match tool_name.as_str() {
                                "malhash" => (result.sha256.clone(), true),
                                "nsrlquery" => (result.md5.clone().unwrap_or_default(), true),
                                _ => (result.path.clone(), false),
                            };

                            let output_filename = format!(
                                "{}_{}.txt",
                                std::path::Path::new(&result.path)
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy(),
                                chrono::Local::now().format("%Y%m%d_%H%M%S")
                            );

                            let mut args = Vec::new();
                            args.push(input.clone());
                            args.push("-o".to_string());
                            args.push("-t".to_string());
                            if use_case {
                                args.push("--case".to_string());
                                args.push(case_name.clone());
                            }
                            args.push("--output-file".to_string());
                            args.push(output_filename.clone());

                            let mut cmd = if cfg!(debug_assertions) {
                                let mut c = std::process::Command::new("cargo");
                                c.args(["run", "-p", &lowercase_tool, "--"]);
                                for arg in &args {
                                    c.arg(arg);
                                }
                                c
                            } else {
                                let mut c = std::process::Command::new(format!("./target/release/{}", &lowercase_tool));
                                for arg in &args {
                                    c.arg(arg);
                                }
                                c
                            };

                            if let Ok(exe_path) = std::env::current_exe() {
                                if let Some(project_root) = exe_path.parent()
                                    .and_then(|p| p.parent())
                                    .and_then(|p| p.parent())
                                    .map(|p| p.to_path_buf()) {
                                    cmd.current_dir(project_root);
                                }
                            }
                            match cmd.output() {
                                Ok(output) => {
                                    let stdout = String::from_utf8_lossy(&output.stdout);
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    self.subtool_output.push_str(&format!(
                                        "\n\n--- Output from {} on {} ---\n{}\n",
                                        lowercase_tool, result.filename, stdout
                                    ));
                                    if !stderr.trim().is_empty() {
                                        self.subtool_output.push_str(&format!(
                                            "--- STDERR from {} on {} ---\n{}\n",
                                            lowercase_tool, result.filename, stderr
                                        ));
                                    }

                                    let tracking_path = if use_case {
                                        format!(
                                            "saved_output/cases/{}/tracking/{}_{}.txt",
                                            case_name,
                                            tool_name,
                                            result.sha256
                                        )
                                    } else {
                                        format!(
                                            "saved_output/{}/tracking/{}_{}.txt",
                                            lowercase_tool,
                                            tool_name,
                                            result.sha256
                                        )
                                    };
                                    if let Some(parent) = std::path::Path::new(&tracking_path).parent() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                    let _ = std::fs::write(&tracking_path, "completed");
                                }
                                Err(e) => {
                                    self.subtool_output.push_str(&format!(
                                        "--- Failed to run {} on {}: {} ---\n",
                                        lowercase_tool, result.filename, e
                                    ));
                                }
                            }
                        }
                    }
                    ui.ctx().request_repaint();
                }
            });
        });
        ui.separator();

        ui.allocate_ui_with_layout(
            ui.available_size_before_wrap(),
            Layout::top_down(Align::Min),
            |ui| {
                ScrollArea::vertical()
                    .max_height(ui.available_height())
                    .min_scrolled_height(200.0)
                    .show(ui, |ui| {
                        // Header row
                        ui.horizontal(|ui| {
                            ui.add_sized([160.0, 0.0], Label::new(RichText::new("Filename").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([280.0, 0.0], Label::new(RichText::new("Path").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([80.0, 0.0], Label::new(RichText::new("Type").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([80.0, 0.0], Label::new(RichText::new("Size").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([280.0, 0.0], Label::new(RichText::new("SHA256").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([50.0, 0.0], Label::new(RichText::new("Ext").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([60.0, 0.0], Label::new(RichText::new("Inferred").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([60.0, 0.0], Label::new(RichText::new("Mismatch").color(Color32::from_rgb(0, 255, 255)).strong()));
                            ui.add_sized([160.0, 0.0], Label::new(RichText::new("Suggested Tools").color(Color32::from_rgb(0, 255, 255)).strong()));
                        });

                        ui.separator();

                        for (row_index, result) in self.results.iter_mut().enumerate() {
                            let bg_color = if row_index % 2 == 0 {
                                Color32::from_rgb(30, 30, 30)
                            } else {
                                Color32::from_rgb(20, 20, 20)
                            };

                            let sanitized_hash = result.sha256.replace("/", "_");
                            let lowercase_tool = result.filetype.to_lowercase();

                            let case_name = app_state.case_name.clone().unwrap_or_else(|| String::from("default_case"));
                            let case_output_folder = std::path::Path::new("saved_output")
                                .join("cases")
                                .join(&case_name)
                                .join("fileminer");
                            let meta_path = case_output_folder
                                .join(&lowercase_tool)
                                .join("tracking")
                                .join(format!("{}.meta.json", sanitized_hash));

                            let row_rect = ui.available_rect_before_wrap();
                            ui.painter().rect_filled(row_rect, 0.0, bg_color);

                            ui.horizontal_top(|ui| {
                                ui.add_sized([160.0, 0.0], Label::new(&result.filename).wrap(true));
                                ui.add_sized([280.0, 0.0], Label::new(&result.path).wrap(true));

                                let simple_type = if result.filetype.contains("portable-executable") {
                                    "PE-EXE"
                                } else if result.filetype.contains("pdf") {
                                    "PDF"
                                } else {
                                    &result.filetype
                                };
                                ui.add_sized([80.0, 0.0], Label::new(simple_type).wrap(true));
                                ui.add_sized([80.0, 0.0], Label::new(format_bytes(result.size)).wrap(true));
                                ui.add_sized([280.0, 0.0], Label::new(&result.sha256).wrap(true));
                                ui.add_sized([50.0, 0.0], Label::new(&result.extension).wrap(true));
                                ui.add_sized([60.0, 0.0], Label::new(&result.inferred).wrap(true));
                                ui.add_sized([60.0, 0.0], Label::new(if result.mismatch { "Yes" } else { "No" }).wrap(true));


                        let mut selectable_tools = Vec::new();
                        if result.filetype.contains("portable-executable") {
                            selectable_tools.push("fileanalyzer");
                            selectable_tools.push("mstrings");
                            selectable_tools.push("malhash");
                            selectable_tools.push("nsrlquery");
                        } else if result.filetype == "Unknown" && result.size > 10_000 {
                            selectable_tools.push("fileanalyzer");
                            selectable_tools.push("malhash");
                            selectable_tools.push("nsrlquery");
                        }

                        let preselect_tool = result.suggested_tool.as_ref();
                        ui.vertical(|ui| {
                            for tool_name in &selectable_tools {
                                // If this is the suggested tool and nothing selected yet, pre-select it
                                let mut is_selected = result
                                    .selected_tool_outputs
                                    .iter()
                                    .any(|(t, _)| t == tool_name);
                                // If nothing selected, and this is the suggested tool, pre-select
                                if !is_selected && preselect_tool.is_some() && preselect_tool.unwrap().eq_ignore_ascii_case(tool_name) {
                                    // Only auto-select if not already selected
                                    result.selected_tool_outputs.push(((*tool_name).to_string(), "TXT".to_string()));
                                    is_selected = true;
                                }

                                let format = result
                                    .selected_tool_outputs
                                    .iter()
                                    .find(|(t, _)| t == tool_name)
                                    .map(|(_, f)| f.clone())
                                    .unwrap_or_else(|| "TXT".to_string());

                                ui.horizontal(|ui| {
                                    ui.add_space(20.0); 
                                let _tool_run = std::fs::read_to_string(&meta_path)
                                    .ok()
                                    .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
                                    .and_then(|meta| {
                                        meta.get("tools").and_then(|tools| tools.as_array())
                                            .map(|arr| arr.iter().any(|t| t.as_str().map(|s| s.to_lowercase()) == Some(tool_name.to_lowercase())))
                                    })
                                    .unwrap_or(false);
                
                                let label = {
                                    let tracking_path = if let Some(case_name) = &app_state.case_name {
                                        format!(
                                            "saved_output/cases/{}/tracking/{}_{}.txt",
                                            case_name,
                                            tool_name,
                                            result.sha256
                                        )
                                    } else {
                                        format!(
                                            "saved_output/{}/tracking/{}_{}.txt",
                                            tool_name.to_lowercase(),
                                            tool_name,
                                            result.sha256
                                        )
                                    };
                                    if std::path::Path::new(&tracking_path).exists() {
                                        RichText::new(*tool_name).color(Color32::LIGHT_GREEN)
                                    } else {
                                        RichText::new(*tool_name)
                                    }
                                };
                                ui.checkbox(&mut is_selected, label);

                                    let mut selected_format = format.clone();
                                    ComboBox::from_id_source(format!("{}_format", tool_name))
                                    .selected_text(selected_format.clone())
                                        .width(70.0)
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut selected_format, "TXT".to_string(), "txt");
                                            ui.selectable_value(&mut selected_format, "JSON".to_string(), "json");
                                            ui.selectable_value(&mut selected_format, "Markdown".to_string(), "md");
                                        });

                                    if is_selected {
                                        if let Some(existing) = result.selected_tool_outputs.iter_mut().find(|(t, _)| t == tool_name) {
                                            existing.1 = selected_format;
                                        } else {
                                            result.selected_tool_outputs.push(((*tool_name).to_string(), selected_format));
                                        }
                                    } else {
                                        result.selected_tool_outputs.retain(|(t, _)| t != tool_name);
                                    }
                                });
                            }
                        });
                            });

                            ui.add_space(8.0);
                        }

                    });
            },
        );


        let _ctx = ui.ctx();

        if let Some(_index) = self.selected_index {
            ui.separator();

            ScrollArea::vertical().show(ui, |ui| {
                if ui.add_sized([120.0, 28.0], eframe::egui::Button::new("🔁 Show Case")).clicked() {
                    let ctx = ui.ctx();
                    ctx.data_mut(|d| {
                        let app_state = d.get_temp_mut_or(*ID_APP_STATE, AppState::default());

                        app_state.case_modal.show_modal = true;
                    });
                }
                if ui.button("🔍 Run Tool on Selected File").clicked() {
                    if let Some(index) = self.selected_index {
                        let filepath = &self.results[index].filename;

                        let Some(tool_name) = rfd::FileDialog::new()
                            .set_title("Select Subtool to Run")
                            .pick_file()
                            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string()) else {
                                eprintln!("❌ No subtool selected.");
                                return;
                            };

                        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                        let ext = match self.output_format.to_lowercase().as_str() {
                            "json" => "json",
                            "markdown" | "md" => "md",
                            _ => "txt",
                        };
                        let filename = format!("{}_{}.{}", filepath.replace('/', "_"), timestamp, ext);
                        let report_path = format!("saved_output/fileminer/{}", filename);


                        let mut cmd = std::process::Command::new(tool_name);
                        cmd.arg(filepath);
                        match self.output_format.to_lowercase().as_str() {
                            "json" => { cmd.arg("-j"); },
                            "markdown" | "md" => { cmd.arg("-m"); },
                            _ => { cmd.arg("-t"); }
                        }
                        cmd.arg("--case");
                        cmd.arg(current_case.clone());
                        cmd.arg("--output-file");
                        cmd.arg(&report_path);
                        if self.show_mismatches_only {
                            cmd.arg("--mismatch");
                        }

                        match cmd.output() {
                            Ok(output) => {
                                let tool_output = String::from_utf8_lossy(&output.stdout);
                                for (line, color) in parse_colored_output(&tool_output) {
                                    ui.colored_label(color, line);
                                }
                                ui.ctx().request_repaint();
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to launch subtool: {e}");
                            }
                        }
                    }
                }
            });
        }

    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format!("{:.2} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.2} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.2} KB", bytes_f / KB)
    } else {
        format!("{} B", bytes)
    }
}

impl FileMinerPanel {

    pub fn run_scan(&mut self) {
        self.run_fileminer_scan();
    }


    pub fn ui(&mut self, ui: &mut eframe::egui::Ui, _ctx: &eframe::egui::Context, app_state: &crate::AppState) {
        self.show(ui, app_state);
    }

}
