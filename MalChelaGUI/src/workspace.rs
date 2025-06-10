use crate::egui::ComboBox;

use sha2::{Sha256, Digest};
use std::fs;
use walkdir::WalkDir;
use std::path::PathBuf;
use std::process::Command;

use crate::egui::CursorIcon;
use crate::egui::TextEdit;
use crate::egui::Window;


#[derive(Serialize, Deserialize)]
pub struct CaseMetadata {
    pub name: Option<String>,
    pub input_path: Option<String>,
    pub sha256: Option<String>,
    pub notes: String,
}

use crate::egui::RichText;
use crate::egui::Ui;
use crate::egui::Label;
use crate::egui::Sense;
use common_ui::{CYAN, STONE_BEIGE, OXIDE_ORANGE};

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspacePanel {
    pub is_visible: bool,
    pub minimized: bool,
    pub active_case_name: Option<String>,
    pub input_path: Option<std::path::PathBuf>,
    pub input_type: Option<String>,
    pub selected_tool: Option<String>,
    pub selected_file: Option<String>,
    pub selected_results: Vec<String>,
    pub notes: String,
    pub file_hash: Option<String>,
    pub save_requested: bool,
    pub save_status: Option<String>,
    #[serde(skip)]
    pub save_status_timestamp: Option<std::time::Instant>,
    #[serde(skip)]
    pub case_reports: std::collections::BTreeMap<String, Vec<PathBuf>>,
    /// Suggested tools for file-based cases
    pub suggested_tools: Vec<String>,
    #[serde(skip)]
    pub show_notes_modal: bool,
    #[serde(skip)]
    pub notes_save_confirmed: Option<std::time::Instant>,
    // New fields for tool selection and output format
    #[serde(skip)]
    pub selected_tools: std::collections::HashMap<String, bool>,
    #[serde(skip)]
    pub tool_output_formats: std::collections::HashMap<String, String>,
    #[serde(skip)]
    pub show_command_output: bool,
    #[serde(skip)]
    pub preview_file: Option<PathBuf>,
    #[serde(skip)]
    pub show_preview_modal: bool,
    #[serde(skip)]
    pub preview_contents: String,
}

impl Default for WorkspacePanel {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspacePanel {
    pub fn new() -> Self {
        Self {
            is_visible: false,
            minimized: false,
            active_case_name: None,
            input_path: None,
            input_type: None,
            selected_tool: None,
            selected_file: None,
            selected_results: Vec::new(),
            notes: String::new(),
            file_hash: None,
            save_requested: false,
            save_status: None,
            save_status_timestamp: None,
            case_reports: std::collections::BTreeMap::new(),
            suggested_tools: Vec::new(),
            show_notes_modal: false,
            notes_save_confirmed: None,
            selected_tools: std::collections::HashMap::new(),
            tool_output_formats: std::collections::HashMap::new(),
            show_command_output: false,
            preview_file: None,
            show_preview_modal: false,
            preview_contents: String::new(),
        }
    }

    pub fn render_scrollable_content(&mut self, ui: &mut Ui) {
        if self.preview_contents.is_empty() {
            println!("⚠️ Preview contents is empty at render start");
        }
        if let Some(t) = self.save_status_timestamp {
            if t.elapsed().as_secs() > 3 {
                self.save_status = None;
                self.save_status_timestamp = None;
            }
        }

        use crate::egui::ScrollArea;
        ScrollArea::vertical()
            .id_source("workspace_scroll")
            .show(ui, |ui| {
                // Case Control Bar: Move this block above the case heading
                // Add vertical space before the Case Management heading
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    use crate::egui::Color32;
                    let button_text = |label: &str| RichText::new(label).size(16.0).color(Color32::from_rgb(144, 238, 144));
                    if ui.button(button_text("📝 Case Notes")).clicked() {
                        self.show_notes_modal = true;
                    }
                    ui.add_space(8.0);
                    if ui.button(button_text("💾 Save Case")).clicked() {
                        self.save_case_metadata();
                    }
                    ui.add_space(8.0);
                    if ui.button(button_text("➖ Minimize")).clicked() {
                        self.minimized = true;
                    }
                    ui.add_space(8.0);
                    if ui.button(button_text("🔄 Refresh Case")).clicked() {
                        self.selected_results.clear();
                        self.show_command_output = false;
                        self.refresh_case_reports();
                    }
                    ui.add_space(8.0);
                    // 📂 Open Case Folder button
                    if ui.button(button_text("📂 Open Case Folder")).clicked() {
                        if let Some(case_name) = &self.active_case_name {
                            let case_path = std::env::current_dir()
                                .unwrap_or_else(|_| PathBuf::from("."))
                                .join("saved_output")
                                .join("cases")
                                .join(case_name);
                            #[cfg(target_os = "macos")]
                            let _ = std::process::Command::new("open")
                                .arg(case_path.clone())
                                .spawn();
                            #[cfg(target_os = "linux")]
                            let _ = std::process::Command::new("xdg-open")
                                .arg(case_path.clone())
                                .spawn();
                            #[cfg(target_os = "windows")]
                            let _ = std::process::Command::new("explorer")
                                .arg(case_path)
                                .spawn();
                        }
                    }
                });
                ui.separator();
                // Insert separator above the Case Management heading for visual separation (per instructions)
                ui.separator();
                // Removed: ui.heading(RichText::new("📂 Case Management").color(OXIDE_ORANGE));
                if let Some(case) = &self.active_case_name {
                    ui.heading(RichText::new(format!("📁 Case: {}", case)).color(OXIDE_ORANGE));
                } else {
                    ui.heading("📁 Workspace");
                }

                if let Some(path) = &self.input_path {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Input Path: ").strong().color(CYAN));
                        ui.label(RichText::new(path.display().to_string()).color(STONE_BEIGE));
                    });
                }

                if let Some(path) = &self.input_path {
                    if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("File Name: ").strong().color(CYAN));
                            ui.label(RichText::new(file_name).color(STONE_BEIGE));
                        });
                    }
                }

                if let Some(hash) = &self.file_hash {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("SHA256: ").strong().color(CYAN));
                        ui.label(RichText::new(hash).color(STONE_BEIGE));
                    });
                }
                // Insert suggested tools block here
                if !self.suggested_tools.is_empty() {
                    use crate::egui::{CollapsingHeader, Color32};
                    ui.separator();
                    CollapsingHeader::new(RichText::new("🔎 Suggested Tools:").strong().size(16.0).color(OXIDE_ORANGE))
                        .default_open(true)
                        .show(ui, |ui| {
                            for tool in &self.suggested_tools {
                                let checked = self.selected_tools.get_mut(tool).unwrap();
                                ui.horizontal(|ui| {
                                    ui.checkbox(checked, "");
                                    let has_run = self.case_reports.contains_key(tool);
                                    let color = if has_run {
                                        Color32::from_rgb(144, 238, 144)  // light green
                                    } else {
                                        CYAN
                                    };
                                    ui.label(RichText::new(tool).color(color));
                                    ui.label("Output:");
                                    if let Some(current_format) = self.tool_output_formats.get_mut(tool) {
                                        let selected_format = current_format.clone();
                                        ComboBox::from_id_source(format!("{}_format", tool))
                                            .selected_text(selected_format)
                                            .show_ui(ui, |ui| {
                                                for fmt in &["txt", "json", "md"] {
                                                    ui.selectable_value(current_format, fmt.to_string(), *fmt);
                                                }
                                            });
                                    }
                                });
                            }
                            ui.add_space(6.0); // Small space between tool list and run button
                            if ui.button(RichText::new("▶ Run Selected Tools").size(14.0)).clicked() {
                                self.show_command_output = true;
                                self.save_status = Some("▶️ Running selected tools...".to_string());
                                self.save_status_timestamp = Some(std::time::Instant::now());
                                self.selected_results.clear();
                                for (tool, selected) in &self.selected_tools {
                                    if *selected {
                                        if let Some(input_path) = &self.input_path {
                                            let case_folder = std::env::current_dir()
                                                .unwrap_or_else(|_| PathBuf::from("."))
                                                .join("saved_output")
                                                .join("cases")
                                                .join(self.active_case_name.as_ref().unwrap())
                                                .join(tool);

                                            let _ = std::fs::create_dir_all(&case_folder);

                                            let format_value = self.tool_output_formats.get(tool).unwrap_or(&"txt".to_string()).clone();
                                            // Convert format_value into CLI flag
                                            let format_flag = match format_value.as_str() {
                                                "txt" => "-t",
                                                "json" => "-j",
                                                "md" => "-m",
                                                _ => "-t",
                                            };
                                            let _output_path = case_folder.join(format!("output.{}", format_value));
                                            // Compute input argument based on tool
                                            let input_arg = if tool == "nsrlquery" {
                                                // nsrlquery requires MD5
                                                let bytes = std::fs::read(input_path).unwrap_or_default();
                                                format!("{:x}", md5::compute(bytes))
                                            } else if tool == "malhash" {
                                                // malhash uses SHA256
                                                self.file_hash.clone().unwrap_or_default()
                                            } else {
                                                input_path.to_string_lossy().to_string()
                                            };
                                            let result = Command::new("cargo")
                                                .env("MALCHELA_WORKSPACE_MODE", "1")
                                                .args(&["run", "-p", tool, "--"])
                                                .arg(input_arg)
                                                .arg("-o")
                                                .arg(format_flag)
                                                .arg("--case")
                                                .arg(self.active_case_name.as_ref().unwrap())
                                                .output();

                                            match result {
                                                Ok(output) => {
                                                    if !output.stdout.is_empty() {
                                                        self.selected_results.push(String::from_utf8_lossy(&output.stdout).to_string());
                                                    }
                                                    if !output.stderr.is_empty() {
                                                        self.selected_results.push(String::from_utf8_lossy(&output.stderr).to_string());
                                                    } else {
                                                        self.selected_results.push(format!("✅ {} ran successfully", tool));
                                                    }
                                                }
                                                Err(e) => {
                                                    self.selected_results.push(format!("❌ Error running {}: {}", tool, e));
                                                }
                                            }
                                        }
                                    }
                                }
                                self.selected_results.push("✅ Complete.".to_string());
                                self.save_case_metadata();
                                self.refresh_case_reports();
                            }
                            // Add a spacer after the Run Selected Tools button for visual separation before results
                            ui.add_space(10.0);
                        });
                }

                if let Some(input_type) = &self.input_type {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Input Type: ").strong().color(CYAN));
                        ui.label(RichText::new(input_type).color(STONE_BEIGE));
                    });
                }

                if let Some(tool) = &self.selected_tool {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Selected Tool: ").strong().color(CYAN));
                        ui.label(RichText::new(tool).color(STONE_BEIGE));
                    });
                }

                if let Some(file) = &self.selected_file {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Selected File: ").strong().color(CYAN));
                        ui.label(RichText::new(file).color(STONE_BEIGE));
                    });
                }

                if self.show_command_output && !self.selected_results.is_empty() {
                    ui.label("Results:");
                    for result in &self.selected_results {
                        ui.monospace(result);
                    }
                }

                ui.separator();
                if let Some(status) = &self.save_status {
                    ui.label(RichText::new(status).color(CYAN));
                }

                if self.case_reports.iter().any(|(_, files)| !files.is_empty()) {
                    use crate::egui::{CollapsingHeader, Color32};
                    ui.label(RichText::new("📄 Case Files:").strong().size(16.0).color(OXIDE_ORANGE));
                    for (tool, files) in &self.case_reports {
                        if files.is_empty() {
                            continue;
                        }
                        if tool == "misc" && files.is_empty() {
                            continue;
                        }
                        CollapsingHeader::new(RichText::new(format!("{}:", tool)).strong().color(STONE_BEIGE))
                            .default_open(true)
                            .show(ui, |ui| {
                                let mut sorted_files = files.clone();
                                sorted_files.sort();
                                for file in sorted_files {
                                    if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
                                        if name == ".DS_Store" || name == "case.json" {
                                            continue;
                                        }
                                    }
                                    let display_name = file.strip_prefix(
                                        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                                            .join("saved_output")
                                            .join("cases")
                                            .join(self.active_case_name.as_ref().unwrap())
                                    ).unwrap_or(&file);

                                    let relative_path = display_name.strip_prefix(tool).unwrap_or(display_name);
                                    let label_text = format!("{}", relative_path.display());
                                    let is_previewable = file.clone().extension()
                                        .and_then(|e| e.to_str())
                                        .map(|ext| matches!(ext, "txt" | "json" | "md"))
                                        .unwrap_or(false);

                                    if is_previewable {
                                        let label = Label::new(RichText::new(label_text).color(CYAN)).sense(Sense::click());
                                        let response = ui.add(label).on_hover_cursor(CursorIcon::PointingHand);
                                        if response.clicked() {
                                            self.preview_file = Some(file.clone());
                                            self.show_preview_modal = true;

                                            match std::fs::read(&file) {
                                                Ok(bytes) => {
                                                    self.preview_contents = String::from_utf8_lossy(&bytes).into_owned();
                                                }
                                                Err(e) => {
                                                    self.preview_contents = format!("❌ Failed to read: {}", e);
                                                }
                                            }

                                            println!("🔍 Preview loaded for {}:\n{}", file.display(), self.preview_contents);
                                        }
                                    } else {
                                        ui.label(RichText::new(label_text).color(Color32::from_rgb(144, 238, 144)));
                                    }
                                }
                                ui.add_space(8.0);
                            });
                    }
                }
            });

        // Modal-style file preview window (shown below file listing)
        // Replaced with logic from the working preview code (per instructions)
        if self.show_preview_modal {
            let mut modal_is_open = true;
            if let Some(preview_path) = &self.preview_file {
                let display_path = preview_path.display().to_string();
                let _preview_data = match std::fs::read_to_string(preview_path) {
                    Ok(contents) => contents,
                    Err(e) => format!("❌ Failed to read file: {}", e),
                };
                Window::new("📄 File Preview")
                    .open(&mut modal_is_open)
                    .resizable(true)
                    .vscroll(true)
                    .default_width(700.0)
                    .default_height(400.0)
                    .show(ui.ctx(), |ui| {
                        ui.label(RichText::new(display_path).color(STONE_BEIGE));
                        ui.add_space(6.0);
                        ui.separator();
                        ui.add(
                            TextEdit::multiline(&mut self.preview_contents)
                                .desired_rows(20)
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(12.0);
                        ui.separator();
                        // Removed "❌ Close Preview" button block
                    });
            }
            self.show_preview_modal = modal_is_open;
        }
    }

    // render_footer removed; modal moved to show()

    pub fn show(&mut self, ui: &mut Ui) {
        // Example: Split the UI into two columns for main workspace
        ui.columns(2, |columns| {
            let (left, right) = columns.split_at_mut(1);

            // Left panel: Tool selection and output formats
            self.render_tool_selection_panel(&mut left[0]);

            // Right panel: Command output and reports
            self.render_output_and_reports_panel(&mut right[0]);
        });
        if self.show_notes_modal {
            // Avoid double mutable borrow by copying state into a local variable
            let mut show = self.show_notes_modal;
            Window::new(RichText::new("📓 Case Notes").color(OXIDE_ORANGE))
                .collapsible(false)
                .resizable(true)
                .default_width(600.0)
                .default_height(300.0)
                .open(&mut show)
                .show(ui.ctx(), |ui| {
                    ui.label(RichText::new("Notes:").strong().color(CYAN));
                    ui.add(
                        TextEdit::multiline(&mut self.notes)
                            .desired_rows(20)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);
                    if ui.button("💾 Save Notes").clicked() {
                        self.save_case_metadata();
                    }
                    if let Some(t) = self.notes_save_confirmed {
                        if t.elapsed().as_secs() < 2 {
                            ui.label(RichText::new("✅ Notes saved").color(CYAN));
                        } else {
                            self.notes_save_confirmed = None;
                        }
                    }
                });
            self.show_notes_modal = show;
        }
    }

    pub fn save_case_metadata(&mut self) {
        let metadata = CaseMetadata {
            name: self.active_case_name.clone(),
            input_path: self.input_path.as_ref().map(|p| p.display().to_string()),
            sha256: self.file_hash.clone(),
            notes: self.notes.clone(),
        };

        if let Some(name) = &self.active_case_name {
            let case_folder = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("saved_output")
                .join("cases")
                .join(name);

            let _ = fs::create_dir_all(&case_folder);
            let metadata_path = case_folder.join("case.json");

            if let Ok(json) = serde_json::to_string_pretty(&metadata) {
                let _ = fs::write(&metadata_path, json);
                self.save_status = Some(format!("✅ Case metadata saved to: {}", metadata_path.display()));
                self.save_status_timestamp = Some(std::time::Instant::now());
                self.notes_save_confirmed = Some(std::time::Instant::now());
                // println!("✅ Case metadata saved to: {}", metadata_path.display());
            }
        }
    }

    pub fn load_case_metadata(&mut self, path: PathBuf) {
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<CaseMetadata>(&contents) {
                Ok(metadata) => {
                    self.active_case_name = metadata.name;
                    self.input_path = metadata.input_path.map(PathBuf::from);
                    self.file_hash = metadata.sha256;
                    self.notes = metadata.notes;
                    if self.input_path.as_ref().map(|p| p.is_file()).unwrap_or(false) {
                        self.suggested_tools = vec![
                            "mstrings".to_string(),
                            "malhash".to_string(),
                            "fileanalyzer".to_string(),
                            "nsrlquery".to_string(),
                        ];
                    }
                    // Insert: reset selected_tools and tool_output_formats based on suggested_tools
                    self.selected_tools.clear();
                    self.tool_output_formats.clear();
                    for tool in &self.suggested_tools {
                        self.selected_tools.insert(tool.clone(), false);
                        self.tool_output_formats.insert(tool.clone(), "txt".to_string());
                    }
                    self.save_status = Some(format!("📂 Loaded case from: {}", path.display()));
                    self.save_status_timestamp = Some(std::time::Instant::now());
                    // println!("📂 Loaded case from: {}", path.display());

                    self.case_reports.clear();
                    if let Some(name) = &self.active_case_name {
                        let case_root = std::env::current_dir()
                            .unwrap_or_else(|_| PathBuf::from("."))
                            .join("saved_output")
                            .join("cases")
                            .join(name);

                        if let Ok(entries) = fs::read_dir(&case_root) {
                            for entry in entries.flatten() {
                                if let Ok(metadata) = entry.metadata() {
                                    if metadata.is_dir() {
                                        let tool_name = entry.file_name().to_string_lossy().into_owned();
                                        let mut files = Vec::new();
                                        for walk_entry in WalkDir::new(entry.path())
                                            .into_iter()
                                            .filter_map(Result::ok)
                                            .filter(|e| e.file_type().is_file())
                                        {
                                            files.push(walk_entry.into_path());
                                        }
                                        if !files.is_empty() {
                                            self.case_reports.insert(tool_name, files);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    self.save_status = Some(format!("❌ Failed to parse case.json: {}", e));
                    self.save_status_timestamp = Some(std::time::Instant::now());
                    eprintln!("❌ Failed to parse case.json: {}", e);
                }
            },
            Err(e) => {
                self.save_status = Some(format!("❌ Failed to read case.json: {}", e));
                self.save_status_timestamp = Some(std::time::Instant::now());
                eprintln!("❌ Failed to read case.json: {}", e);
            }
        }
    }
    pub fn refresh_case_reports(&mut self) {
        self.case_reports.clear();
        if let Some(name) = &self.active_case_name {
            let case_root = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("saved_output")
                .join("cases")
                .join(name);

            if let Ok(entries) = std::fs::read_dir(&case_root) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_dir() {
                            let tool_name = entry.file_name().to_string_lossy().into_owned();
                            let mut files = Vec::new();
                            for walk_entry in WalkDir::new(entry.path())
                                .into_iter()
                                .filter_map(Result::ok)
                                .filter(|e| e.file_type().is_file())
                            {
                                files.push(walk_entry.into_path());
                            }
                            if !files.is_empty() {
                                self.case_reports.insert(tool_name, files);
                            }
                        } else if metadata.is_file() {
                            let file_path = entry.path();
                            if let Some(name) = file_path.file_name().and_then(|n| n.to_str()) {
                                if name != ".DS_Store" {
                                    self.case_reports
                                        .entry("misc".to_string())
                                        .or_default()
                                        .push(file_path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    /// Programmatically minimize (collapse) the workspace panel.
    pub fn minimize(&mut self) {
        self.minimized = true;
    }

    /// Reset the workspace state for starting a new case
    pub fn reset(&mut self) {
        self.is_visible = false;
        self.minimized = false;
        self.active_case_name = None;
        self.input_path = None;
        self.input_type = None;
        self.selected_tool = None;
        self.selected_file = None;
        self.selected_results.clear();
        self.notes.clear();
        self.file_hash = None;
        self.save_requested = false;
        self.save_status = None;
        self.save_status_timestamp = None;
        self.case_reports.clear();
        self.suggested_tools = vec![
            "mstrings".to_string(),
            "malhash".to_string(),
            "fileanalyzer".to_string(),
            "nsrlquery".to_string(),
        ];
        self.show_notes_modal = false;
        self.notes_save_confirmed = None;
        self.selected_tools.clear();
        self.tool_output_formats.clear();
        self.show_command_output = false;
        // Ensure selected_tools and tool_output_formats are initialized for new case
        for tool in &self.suggested_tools {
            self.selected_tools.insert(tool.clone(), false);
            self.tool_output_formats.insert(tool.clone(), "txt".to_string());
        }
    }


    /// Start a new case, resetting workspace and repopulating suggested tools.
    pub fn new_case(&mut self, path: PathBuf, case_name: String, input_type: String) {
        self.reset(); // Ensure full workspace state is cleared
        self.input_path = Some(path);
        // If input type is file, compute the SHA256
        if let Some(ref path) = self.input_path {
            if path.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    let mut hasher = Sha256::new();
                    hasher.update(bytes);
                    let hash_result = hasher.finalize();
                    self.file_hash = Some(format!("{:x}", hash_result));
                }
            }
        }
        self.active_case_name = Some(case_name);
        self.input_type = Some(input_type);

        // Restore suggested tools and default selections
        self.suggested_tools = vec![
            "mstrings".to_string(),
            "malhash".to_string(),
            "fileanalyzer".to_string(),
            "nsrlquery".to_string(),
        ];
        self.selected_tools.clear();
        self.tool_output_formats.clear();
        for tool in &self.suggested_tools {
            self.selected_tools.insert(tool.clone(), false);
            self.tool_output_formats.insert(tool.clone(), "txt".to_string());
        }

        // Activate panel visibility and other flags
        self.is_visible = true;
        self.minimized = false;
        self.show_command_output = false;
        self.refresh_case_reports();
    }
}
impl WorkspacePanel {
    /// Render the tool selection panel (left column)
    pub fn render_tool_selection_panel(&mut self, ui: &mut Ui) {
        // For now, keep the original content in the left column for demonstration:
        ui.vertical(|ui| {
            self.render_scrollable_content(ui);
            ui.add_space(12.0);
        });
    }

    /// Render the output and reports panel (right column)
    pub fn render_output_and_reports_panel(&mut self, _ui: &mut Ui) {
        // Implementation for the right panel would go here.
        // For now, nothing is rendered.
    }
}