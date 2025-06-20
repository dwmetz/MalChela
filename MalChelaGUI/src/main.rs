mod tshark_panel;
mod case_modal;
mod fileminer;
use case_modal::CaseModal;
// use crate::case_modal::NewCaseModal;
use crate::case_modal::show_case_modal;
use tshark_panel::TsharkPanel;
use fileminer::{FileMinerPanel};
mod vol3_panel;
use vol3_panel::{Vol3Panel, Vol3Plugin};
use egui::TextureOptions;
use serde::Deserialize;
mod workspace;
use workspace::WorkspacePanel;
use eframe::{
    egui::{self, CentralPanel, Color32, Context, FontId, RichText, ScrollArea, SidePanel, TextEdit, TopBottomPanel, Visuals, Vec2},
    App,
};

use egui::viewport::IconData;
fn load_icon() -> Option<IconData> {
    use std::path::PathBuf;
    let icon_path: PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("images")
        .join("icon.png");
    if !icon_path.exists() {
        return None;
    }
    let image = image::open(icon_path).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    let pixels = image.into_raw();
    Some(IconData { rgba: pixels, width, height })
}
use rfd::FileDialog;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufReader, Read};
use rand::prelude::*;

#[derive(Debug, Deserialize)]
struct Koans {
    koans: Vec<String>,
}
 
use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};


const RUST_ORANGE: Color32 = Color32::from_rgb(200, 100, 50);
const STONE_BEIGE: Color32 = Color32::from_rgb(225, 210, 180);
const LIGHT_CYAN: Color32 = Color32::from_rgb(0, 255, 255);
const RED: Color32 = Color32::from_rgb(255, 0, 0);
const GREEN: Color32 = Color32::from_rgb(0, 255, 0);
const YELLOW: Color32 = Color32::from_rgb(255, 255, 0);
const LIGHT_GREEN: Color32 = Color32::from_rgb(144, 238, 144);

#[derive(Debug, Deserialize, Clone)]
struct ToolConfig {
    name: String,
    command: Vec<String>,
    input_type: String,
    category: String,
    #[serde(default)]
    gui_mode_args: Vec<String>,
    #[serde(default)]
    optional_args: Vec<String>,
    #[serde(default)]
    exec_type: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePanel {
    Workspace,
    FileMiner,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputType {
    File,
    Folder,
    Unknown,
    None,
}

#[derive(Clone)]
pub struct AppState {
    
    pub update_status: Option<String>,
    malchela_logo: Option<egui::TextureHandle>,
    pub case_sha256: Option<String>,
    categorized_tools: BTreeMap<String, Vec<ToolConfig>>,
    selected_tool: Option<ToolConfig>,
    pub case_name: Option<String>,
    pub input_path: Option<std::path::PathBuf>,
    command_output: Arc<Mutex<String>>,
    output_lines: Arc<Mutex<Vec<String>>>,
    show_scratchpad: bool,
    scratchpad_content: Arc<Mutex<String>>,
    scratchpad_path: String,
    string_source_path: String,
    selected_format: String,
    banner_displayed: bool,
    show_home: bool,
    rule_name: String,
    author_name: String,
    zip_password: String,
    show_config: bool,
    vt_api_key: String,
    mb_api_key: String,
    hide_vt: bool,
    hide_mb: bool,
    save_report: (bool, String),
    custom_args: String,
    workspace_root: std::path::PathBuf,
    is_running: Arc<std::sync::atomic::AtomicBool>,
    tshark_panel: TsharkPanel,
    collapsed_categories: BTreeMap<String, bool>,
    edition: String,
    show_tools_modal: bool,
    tools_restore_success: bool,
    restore_status_message: String,
    vol3_panel: Vol3Panel,
    vol3_plugins: BTreeMap<String, Vec<Vol3Plugin>>,
    current_progress: Arc<Mutex<usize>>,
    total_progress: Arc<Mutex<usize>>,
    selected_algorithms: Vec<String>,
    show_new_case_modal: bool,
    pub workspace: WorkspacePanel,
    case_modal: CaseModal,
    fileminer_panel: FileMinerPanel,
    pub current_panel: ActivePanel,
    pub input_type: InputType,
    pub fileminer_minimized: bool,
}
fn resolve_env_vars(s: &str) -> String {
    let replaced = if s.contains("${MALCHELA_ROOT}") {
        if let Ok(root) = std::env::current_dir() {
            s.replace("${MALCHELA_ROOT}", root.to_string_lossy().as_ref())
        } else {
            s.to_string()
        }
    } else {
        s.to_string()
    };

    // Canonicalize to ensure absolute path, if it looks like a file path
    if replaced.contains('/') {
        std::fs::canonicalize(&replaced)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or(replaced)
    } else {
        replaced
    }
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            malchela_logo: None,
            update_status: None,
            current_panel: ActivePanel::None,
            case_sha256: None,
            categorized_tools: BTreeMap::new(),
            selected_tool: None,
            case_name: None,
            input_path: None,
            command_output: Arc::new(Mutex::new(String::new())),
            output_lines: Arc::new(Mutex::new(Vec::new())),
            show_scratchpad: false,
            scratchpad_content: Arc::new(Mutex::new(String::new())),
            scratchpad_path: String::new(),
            string_source_path: String::new(),
            selected_format: String::from("file"),
            banner_displayed: false,
            show_home: true,
            rule_name: String::new(),
            author_name: String::new(),
            zip_password: String::new(),
            show_config: false,
            vt_api_key: String::new(),
            mb_api_key: String::new(),
            hide_vt: false,
            hide_mb: false,
            save_report: (false, ".txt".to_string()),
            custom_args: String::new(),
            workspace_root: std::env::current_dir().unwrap_or_default(),
            is_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tshark_panel: TsharkPanel::default(),
            collapsed_categories: BTreeMap::new(),
            edition: String::new(),
            show_tools_modal: false,
            tools_restore_success: false,
            restore_status_message: String::new(),
            vol3_panel: Vol3Panel::default(),
            vol3_plugins: BTreeMap::new(),
            current_progress: Arc::new(Mutex::new(0)),
            total_progress: Arc::new(Mutex::new(0)),
            selected_algorithms: Vec::new(),
            show_new_case_modal: false,
            workspace: WorkspacePanel::default(),
            case_modal: CaseModal::default(),
            fileminer_panel: FileMinerPanel::default(),
            // Set a valid default input_type (File is common default, or Folder if preferred)
            input_type: InputType::File,
            fileminer_minimized: false,
        }
    }
}

impl AppState {
    /// Reset all application state to defaults for a new case or workspace.
    pub fn reset(&mut self) {
        // Reset panels and relevant state
        self.workspace.reset();
        self.fileminer_panel.reset_panel();
        // Add additional resets here if needed for other panels
        self.selected_tool = None;
        self.input_path = None;
        self.case_name = None;
        self.case_sha256 = None;
        self.custom_args.clear();
        self.save_report = (false, ".txt".to_string());
        self.zip_password.clear();
        self.scratchpad_path.clear();
        self.string_source_path.clear();
        self.selected_format = "file".to_string();
        self.current_panel = ActivePanel::None;
        self.input_type = InputType::File;
        self.fileminer_minimized = false;
        self.show_home = true;
        self.banner_displayed = false;
        self.show_new_case_modal = false;
        self.case_modal.visible = false;
        self.show_scratchpad = false;
        self.rule_name.clear();
        self.author_name.clear();
        self.command_output.lock().unwrap().clear();
        self.output_lines.lock().unwrap().clear();
        // Add more resets as appropriate for your application
    }
    

    pub fn load_existing_case(&mut self, path: &std::path::PathBuf) {
        let case_path = path;
        let case_name = case_path.file_name().and_then(|n| n.to_str()).map(|s| s.to_string());
        self.case_name = case_name;
        self.input_path = Some(case_path.clone());
        self.command_output.lock().unwrap().clear();
        self.output_lines.lock().unwrap().clear();
    }
    fn load_tools_from_yaml() -> (Vec<ToolConfig>, String) {
        let yaml = include_str!("../../tools.yaml");
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).expect("Failed to parse tools.yaml");
        let edition = value.get("edition").and_then(|e| e.as_str()).unwrap_or("").to_string();
        let tools = if let Some(tools_val) = value.get("tools") {
            serde_yaml::from_value::<Vec<ToolConfig>>(tools_val.clone()).unwrap_or_else(|_| vec![])
        } else {
            // fallback: try whole YAML as Vec<ToolConfig>
            serde_yaml::from_str(yaml).unwrap_or_else(|_| vec![])
        };
        (tools, edition)
    }

    fn categorize_tools(tools: &[ToolConfig]) -> BTreeMap<String, Vec<ToolConfig>> {
        let mut categorized: BTreeMap<String, Vec<ToolConfig>> = BTreeMap::new();
        for tool in tools.iter().cloned() {
            let category = if tool.category == "External" {
                "~External".to_string()
            } else {
                tool.category.clone()
            };
            categorized.entry(category).or_default().push(tool);
        }
        for tools in categorized.values_mut() {
            tools.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        }
        categorized
    }
    

    fn run_tool(&mut self, ctx: &eframe::egui::Context) {
        if let Some(tool) = &self.selected_tool {
            // Determine if we're running in workspace mode (workspace panel is visible and not minimized)
            let is_workspace_mode = self.workspace.is_visible && !self.workspace.minimized;
            // Clone/move all used self fields into local variables to move into thread
            let selected_tool = tool.clone();
            let input_path = self.input_path.clone();
            let custom_args = self.custom_args.clone();
            let save_report = self.save_report.clone();
            let zip_password = self.zip_password.clone();
            let workspace_root = self.workspace_root.clone();
            let command_output = Arc::clone(&self.command_output);
            let output_lines = Arc::clone(&self.output_lines);
            let is_running = Arc::clone(&self.is_running);
            let selected_algorithms = self.selected_algorithms.clone();
            let scratchpad_path = self.scratchpad_path.clone();
            let string_source_path = self.string_source_path.clone();
            let selected_format = self.selected_format.clone();
            let author_name = self.author_name.clone();
            let rule_name = self.rule_name.clone();

            let allow_overwrite = custom_args.contains("MZHASH_ALLOW_OVERWRITE=1");
            // Resolve environment variables in command and tool_optional_args
            let command: Vec<String> = selected_tool.command.iter().map(|s| resolve_env_vars(s)).collect();
            let tool_optional_args: Vec<String> = selected_tool.optional_args.iter().map(|s| resolve_env_vars(s)).collect();
            let output = Arc::clone(&command_output);
            if command.get(0).map(|s| s.ends_with("floss")).unwrap_or(false) {
                if input_path.as_ref().map_or(true, |p| !p.exists()) {
                    let mut out = output.lock().unwrap();
                    out.clear();
                    out.push_str("[red]❌ Selected file does not exist or is invalid.\n");
                    return;
                }
            }
            // Use the actual selected plugin name from the Vol3Panel for Vol3
            ctx.request_repaint();

            // Reset output state when running a new tool
            command_output.lock().unwrap().clear();
            output_lines.lock().unwrap().clear();
            is_running.store(false, std::sync::atomic::Ordering::Relaxed);

            // Reset arguments when running a new tool
            // self.custom_args.clear();  // <-- Removed per instructions
            // self.save_report = (false, ".txt".to_string()); // <-- Removed to preserve Save Report setting
            // zip_password.clear(); // Now using zip_password local variable
            // self.scratchpad_path.clear(); // <-- Removed to allow rule file persistence across runs
            // self.string_source_path.clear(); // <-- Removed to preserve selected string source file
            // self.selected_format = ".txt".to_string(); // <-- Removed to prevent overwriting Description for strings_to_yara

            // Special case for YARA-X (yr)
            if command.get(0).map(|s| s == "yr").unwrap_or(false) {
                if scratchpad_path.is_empty() || input_path.as_ref().map_or(true, |p| p.as_os_str().is_empty()) {
                    let mut out = command_output.lock().unwrap();
                    out.clear();
                    out.push_str("Missing rule or target file.\n");
                    return;
                }
            }

            // Special case: Launch Vol/Vol3 in external terminal (outside of thread)
            let is_external = selected_tool.exec_type.as_deref() != Some("cargo");
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if is_external && command.get(0).map(|s| s.contains("vol")).unwrap_or(false) && !cfg!(windows) {
                // Compose command using custom_args exactly as passed from the panel
                // This is now handled at line 1318 using the Vol3Panel::build_vol3_command logic.
                // We skip early command generation here to prevent conflicts with later override.
                return;
            }

            self.show_running_command(ctx);
            std::env::set_var("MALCHELA_GUI_MODE", "1");
            let gui_mode_args = selected_tool.gui_mode_args.clone();
            let current_progress = Arc::new(Mutex::new(0));
            let total_progress = Arc::new(Mutex::new(0));
            // ... pass current_progress and total_progress as needed ...
            let current_progress_clone = Arc::clone(&current_progress);
            let total_progress_clone = Arc::clone(&total_progress);
            thread::spawn(move || {
                is_running.store(true, std::sync::atomic::Ordering::Relaxed);
                // Clear the output and output_lines at the start of tool run
                {
                    let mut out = output.lock().unwrap();
                    out.clear();
                    let mut lines = output_lines.lock().unwrap();
                    lines.clear();
                }
                use std::io::{BufRead, BufReader};
                // Special handling for Python tools (like pdf-parser.py)
                let is_python = command.get(0).map(|s| {
                    s.ends_with("python3") || s.ends_with("python") || s.contains("python")
                }).unwrap_or(false);
                if is_python {
                    let tool_output_name = tool_optional_args.get(0)
                        .map(|s| std::path::Path::new(s))
                        .and_then(|p| p.file_name())
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.strip_suffix(".py"))
                        .unwrap_or("python_tool");

                    let output_dir = workspace_root.join("saved_output").join(tool_output_name);
                    let _ = std::fs::create_dir_all(&output_dir);

                    let mut args: Vec<String> = Vec::new();
                    args.extend(tool_optional_args.clone());
                    if let Some(ref path) = input_path {
                        args.push(path.display().to_string());
                    }
                    args.extend(gui_mode_args.clone());
                    if !custom_args.trim().is_empty() {
                        let parsed_custom_args = shell_words::split(&custom_args).unwrap_or_default();
                        args.extend(parsed_custom_args);
                    }

                    let mut command_builder = Command::new(&command[0]);
                    command_builder.args(&args);
                    command_builder.current_dir(&output_dir);
                    command_builder.env("MALCHELA_GUI_MODE", "1");

                    let mut child = command_builder
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .expect("Failed to run python tool");

                    if let Some(stdout) = child.stdout.take() {
                        let out_clone = Arc::clone(&output);
                        let output_lines_clone = Arc::clone(&output_lines);
                        thread::spawn(move || {
                            let mut out = out_clone.lock().unwrap();
                            out.clear();
                            let mut lines = output_lines_clone.lock().unwrap();
                            lines.clear();
                            drop(lines); // Explicitly drop, so we can reacquire below
                            drop(out);   // Explicitly drop, so we can reacquire below
                            let stdout_reader = BufReader::new(stdout);
                            for line in stdout_reader.lines().flatten() {
                                {
                                    let mut lines = output_lines_clone.lock().unwrap();
                                    lines.push(line.clone());
                                }
                                {
                                    let mut out = out_clone.lock().unwrap();
                                    out.push_str(&line);
                                    out.push('\n');
                                }
                            }
                        });
                    }
                    if let Some(stderr) = child.stderr.take() {
                        let out_clone = Arc::clone(&output);
                        let output_lines_clone = Arc::clone(&output_lines);
                        thread::spawn(move || {
                            let mut out = out_clone.lock().unwrap();
                            out.clear();
                            let mut lines = output_lines_clone.lock().unwrap();
                            lines.clear();
                            drop(lines);
                            drop(out);
                            let stderr_reader = BufReader::new(stderr);
                            for line in stderr_reader.lines().flatten() {
                                {
                                    let mut lines = output_lines_clone.lock().unwrap();
                                    lines.push(format!("[red]{}", line));
                                }
                                {
                                    let mut out = out_clone.lock().unwrap();
                                    out.push_str("[red]");
                                    out.push_str(&line);
                                    out.push('\n');
                                }
                            }
                        });
                    }

                    let _ = child.wait();
                    is_running.store(false, std::sync::atomic::Ordering::Relaxed);

                    if save_report.0 {
                        let tool_output_name = tool_optional_args.get(0)
                            .map(|s| std::path::Path::new(s))
                            .and_then(|p| p.file_stem())
                            .and_then(|s| s.to_str())
                            .unwrap_or("python_tool");
                        let output_dir = workspace_root.join("saved_output").join(tool_output_name);
                        let _ = std::fs::create_dir_all(&output_dir);
                        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
                        let report_path = output_dir.join(format!("report_{}{}", timestamp, save_report.1));
                        if let Ok(mut file) = File::create(&report_path) {
                            let final_output = output.lock().unwrap();
                            let _ = write!(
                                file,
                                "{}",
                                final_output
                                    .replace("[reset]", "")
                                    .replace("[bold]", "")
                                    .replace("[green]", "")
                                    .replace("[yellow]", "")
                                    .replace("[cyan]", "")
                                    .replace("[gray]", "")
                            );
                        }
                        {
                            let mut out = output.lock().unwrap();
                            let saved_line = format!("\n[green]The results have been saved to: {}\n", report_path.display());
                            out.push_str(&saved_line);
                        }
                    }
                    return;
                }

                // --- Original logic for Rust/internal tools and other external tools ---
                let output_dir = workspace_root
                    .join("saved_output")
                    .join(
                        std::path::Path::new(&command[0])
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or_else(|| std::path::Path::new(&command[0]).file_stem().and_then(|s| s.to_str()).unwrap_or(&command[0]))
                    );
                let _ = std::fs::create_dir_all(&output_dir);

                // Step 1: Build the binary (if not external)
                if !is_external {
                    let build_status = Command::new("cargo")
                        .arg("build")
                        .arg("-p")
                        .arg(&command[0])
                        .current_dir(&workspace_root)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();

                    if !matches!(build_status, Ok(status) if status.success()) {
                        let mut out = output.lock().unwrap();
                        out.clear();
                        out.push_str("Failed to build the tool.\n");
                        is_running.store(false, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }

                // Step 2: Construct path to binary
                let binary_name = if cfg!(windows) {
                    format!("{}.exe", command[0])
                } else {
                    command[0].clone()
                };

                let binary_path = if is_external {
                    match which::which(&command[0]) {
                        Ok(path) => path,
                        Err(_) => {
                            let mut out = output.lock().unwrap();
                            let mut lines = output_lines.lock().unwrap();
                            let msg = format!("[red]Binary '{}' not found in PATH\n", command[0]);
                            out.push_str(&msg);
                            lines.push(msg);
                            is_running.store(false, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    }
                } else {
                    workspace_root
                        .join("target")
                        .join("debug")
                        .join(&binary_name)
                };

                // Step 3: Parse and filter custom_args for env vars and CLI args
                let mut env_vars: Vec<(String, String)> = Vec::new();
                let mut parsed_custom_args: Vec<String> = Vec::new();
                if !custom_args.trim().is_empty() {
                    if let Ok(parsed) = shell_words::split(&custom_args) {
                        for arg in parsed {
                            if let Some((key, value)) = arg.split_once('=') {
                                if key.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                                    env_vars.push((key.to_string(), value.to_string()));
                                    continue;
                                }
                            }
                            parsed_custom_args.push(arg);
                        }
                    }
                }

                // Begin reintroduced "first"/"last" logic for file input positioning
                let mut args: Vec<String> = vec![];
                let mut arg_insert_index = None;
                if let Some(pos) = command.iter().position(|s| s == "first") {
                    arg_insert_index = Some(pos);
                } else if let Some(pos) = command.iter().position(|s| s == "last") {
                    arg_insert_index = Some(pos);
                }
                let mut base_args: Vec<String> = if command.get(0).map(|s| s == "yr").unwrap_or(false) {
                    let mut args = vec!["scan".to_string()];
                    if !custom_args.trim().is_empty() {
                        args.extend(shell_words::split(&custom_args).unwrap_or_default());
                    }
                    args.push(scratchpad_path.clone());
                    if let Some(ref p) = input_path {
                        args.push(p.display().to_string());
                    }
                    args
                } else {
                    command.iter()
                        .filter(|&s| s != "first" && s != "last")
                        .skip(1)
                        .cloned()
                        .collect()
                };
                if let Some(idx) = arg_insert_index {
                    let insert_idx = if command.get(idx) == Some(&"first".to_string()) {
                        idx - 1
                    } else {
                        base_args.len()
                    };
                    if let Some(p) = input_path.clone() {
                        base_args.insert(insert_idx, p.display().to_string());
                    }
                } else if command[0] == "strings_to_yara" {
                    if let Some(p) = input_path.clone() {
                        base_args.push(p.display().to_string());
                    }
                    base_args.push(rule_name);
                    base_args.extend(vec![
                        author_name.clone(),
                        selected_format.clone(),
                        scratchpad_path.clone(),
                        string_source_path.clone(),
                    ]);
                } else if command[0] == "hashcheck" {
                    args.clear();
                    if let Some(p) = input_path.clone() {
                        args.push(p.display().to_string());
                    }
                    args.extend(parsed_custom_args.clone());
                } else if !command.get(0).map(|s| s == "yr").unwrap_or(false) {
                    if let Some(p) = input_path.clone() {
                        base_args.insert(0, p.display().to_string());
                    }
                    if command.get(0).map(|s| s == "combine_yara").unwrap_or(false) {
                        // Only path
                    }
                    if command.get(0).map(|s| s == "extract_samples").unwrap_or(false) {
                        base_args.push(zip_password.clone());
                    }
                }
                args.extend(base_args);
                // ---- PATCH FOR FILEMINER CLI ARGS ----
                // Update: Replace any "-m" with "--mismatch"
                for arg in args.iter_mut() {
                    if arg == "-m" {
                        *arg = "--mismatch".to_string();
                    }
                }
                // Add -o, -t, -j, -m flags if enabled in GUI (as per instructions)
                // These should be added after initial args vector is created, but before command is run.
                // We only add if save_report.0 is true (i.e., saving report)
                if save_report.0 {
                    // Only add -o for save_report if NOT mzhash/xmzhash
                    if !command.get(0).map(|s| s == "mzhash" || s == "xmzhash").unwrap_or(false) {
                        args.push("-o".to_string());
                    }
                    match save_report.1.as_str() {
                        ".txt" => args.push("-t".to_string()),
                        ".json" => args.push("-j".to_string()),
                        ".md" => args.push("-m".to_string()),
                        _ => {}
                    }
                }
                // If the user has enabled "show mismatches" (for FileMiner), add "--mismatch"
                // This requires you to have a config or field indicating show_mismatches.
                // For demonstration, let's suppose it's in a variable called show_mismatches.
                #[allow(unused_variables)]
                {
                    // You may need to wire this up to your actual config/UI state.
                    let show_mismatches = false; // <-- replace with actual field if available
                    if show_mismatches {
                        args.push("--mismatch".to_string());
                    }
                }
                // ---- END PATCH ----
                if command.get(0).map(|s| s == "mzhash").unwrap_or(false) {
                    for algo in &selected_algorithms {
                        args.push("-a".to_string());
                        args.push(algo.to_string());
                    }
                    // Only pass overwrite flag if checkbox enabled in GUI
                    if allow_overwrite {
                        args.push("-o".to_string());
                    }
                } else if command.get(0).map(|s| s == "xmzhash").unwrap_or(false) {
                    for algo in &selected_algorithms {
                        args.push("-a".to_string());
                        args.push(algo.to_string());
                    }
                    if allow_overwrite {
                        args.push("-o".to_string());
                    }
                }
                args.extend(gui_mode_args.clone());
                args.extend(tool_optional_args.clone());
                if command.get(0).map(|s| s == "mzcount").unwrap_or(false) {
                    for (key, value) in &env_vars {
                        if key == "MZCOUNT_TABLE_DISPLAY" {
                            std::env::set_var(key, value);
                        }
                    }
                }
                if command.get(0).map(|s| s != "yr" && s != "hashcheck").unwrap_or(true) {
                    args.extend(parsed_custom_args);
                }

                if save_report.0 {
                    std::env::set_var("MALCHELA_SAVE_OUTPUT", "1");
                } else {
                    std::env::remove_var("MALCHELA_SAVE_OUTPUT");
                }

                let mut command_builder = {
                    let mut cmd = Command::new(&binary_path);
                    cmd.args(&args);
                    if let Some(ref p) = input_path {
                        cmd.env("MALCHELA_INPUT", p.display().to_string());
                    }
                    // Only set MALCHELA_GUI_MODE=1 if NOT running in workspace mode
                    if !is_workspace_mode {
                        cmd.env("MALCHELA_GUI_MODE", "1");
                    }
                    cmd
                };
                command_builder.current_dir(&workspace_root);
                command_builder.stdout(Stdio::piped());
                command_builder.stderr(Stdio::piped());

                match command_builder.spawn() {
                    Ok(mut child) => {
                        // Debug: write output to file for inspection
                        // (We can't get output here synchronously, so we will do this after collecting)
                        if let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) {
                            let stderr_reader = BufReader::new(stderr);

                            let out_clone_stdout = Arc::clone(&output);
                            let output_lines_clone_stdout = Arc::clone(&output_lines);
                            let save_report = save_report.clone();
                            let workspace_root = workspace_root.clone();
                            let command = command.clone();
                            let is_running_clone = Arc::clone(&is_running);
                            let current_progress = Arc::clone(&current_progress_clone);
                            let total_progress = Arc::clone(&total_progress_clone);
                            thread::spawn(move || {
                                use std::io::{BufRead, BufReader};
                                let stdout = stdout; // take ownership here for the thread
                                let mut reader = BufReader::new(stdout);
                                let mut buffer = String::new();
                                let mut is_first_line = true;
                                let mut output_string = String::new();
                                loop {
                                    match reader.read_line(&mut buffer) {
                                        Ok(0) => break, // EOF
                                        Ok(_) => {
                                            if is_first_line && command[0] == "hashcheck" {
                                                {
                                                    let mut out = out_clone_stdout.lock().unwrap();
                                                    out.push('\n');
                                                }
                                                {
                                                    let mut lines = output_lines_clone_stdout.lock().unwrap();
                                                    lines.push("".to_string());
                                                }
                                                is_first_line = false;
                                            }
                                            let trimmed_line = buffer.trim_end().to_string();
                                            // --- PATCH: For xmz256, only show per-file line with hash, not "Starting scan of ..." ---
                                            let is_xmzhash = command.get(0).map(|s| s == "xmzhash").unwrap_or(false);
                                            let is_starting_scan = trimmed_line.starts_with("Starting scan of ");
                                            let trimmed_line = if trimmed_line.contains("Hash value FOUND") {
                                                "[green]Hash value FOUND in the file.".to_string()
                                            } else if trimmed_line.starts_with("Hash: ") {
                                                format!("[cyan]{}", trimmed_line)
                                            } else if trimmed_line.contains("Associated file path:") {
                                                format!("[rust]{}", trimmed_line)
                                            } else if trimmed_line.contains("The results have been saved to:") {
                                                format!("[green]{}", trimmed_line)
                                            // PATCH: xmzhash "Writing hash to file: ..." lines, show hash
                                            } else if is_xmzhash && trimmed_line.starts_with("Writing hash to file: ") {
                                                // Extract the hash from the line, e.g., "Writing hash to file: <hash>"
                                                let hash = trimmed_line.trim_start_matches("Writing hash to file: ").to_string();
                                                format!("[cyan]Hash: {}", hash)
                                            } else if is_xmzhash && is_starting_scan {
                                                // Suppress from GUI output
                                                String::new()
                                            } else {
                                                trimmed_line
                                            };
                                            // Collect output for fileminer debug
                                            output_string.push_str(&buffer);
                                            if trimmed_line.starts_with("[PROGRESS]") {
                                                if let Some((scanned, total)) = trimmed_line
                                                    .trim_start_matches("[PROGRESS]")
                                                    .trim()
                                                    .split_once('/')
                                                    .and_then(|(a, b)| Some((a.trim().parse::<usize>().ok()?, b.trim().parse::<usize>().ok()?)))
                                                {
                                                    *current_progress.lock().unwrap() = scanned;
                                                    *total_progress.lock().unwrap() = total;
                                                }
                                                // suppress from GUI console output
                                            } else {
                                                {
                                                    let mut lines = output_lines_clone_stdout.lock().unwrap();
                                                    lines.push(trimmed_line.clone());
                                                }
                                                {
                                                    let mut out = out_clone_stdout.lock().unwrap();
                                                    out.push_str(&trimmed_line);
                                                    out.push('\n');
                                                }
                                            }
                                            buffer.clear();
                                        }
                                        Err(_) => break,
                                    }
                                }
                                // After stdout loop, save report if needed
                                if save_report.0 && std::env::var("MALCHELA_GUI_MODE").unwrap_or_default() != "1" {
                                    let output_dir = workspace_root
                                        .join("saved_output")
                                        .join(
                                            std::path::Path::new(&command[0])
                                                .file_stem()
                                                .and_then(|s| s.to_str())
                                                .unwrap_or_else(|| std::path::Path::new(&command[0]).file_stem().and_then(|s| s.to_str()).unwrap_or(&command[0]))
                                        );
                                    let _ = std::fs::create_dir_all(&output_dir);
                                    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
                                    let report_path = output_dir.join(format!("report_{}{}", timestamp, save_report.1));
                                    if let Ok(mut file) = File::create(&report_path) {
                                        let final_output = out_clone_stdout.lock().unwrap();
                                        let cleaned_output = final_output
                                            .lines()
                                            .filter_map(|line| {
                                                let mut trimmed = line.trim_start();
                                                let tags = ["[reset]", "[bold]", "[green]", "[yellow]", "[cyan]", "[gray]", "[stone]", "[highlight]", "[red]", "[NOTE]"];
                                                for tag in &tags {
                                                    if trimmed.starts_with(tag) {
                                                        trimmed = trimmed.strip_prefix(tag).unwrap_or(trimmed);
                                                    }
                                                }
                                                let trimmed = trimmed.trim_start();
                                                if trimmed == "Output was not saved." || trimmed.is_empty() {
                                                    None
                                                } else {
                                                    Some(trimmed)
                                                }
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        let _ = write!(file, "{}", cleaned_output);
                                    }
                                    {
                                        let mut out = out_clone_stdout.lock().unwrap();
                                        let saved_line = format!("\n[green]The results have been saved to: {}\n", report_path.display());
                                        out.push_str(&saved_line);
                                    }
                                }
                                is_running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                            });

                            let out_clone_stderr = Arc::clone(&output);
                            let output_lines_clone_stderr = Arc::clone(&output_lines);
                            thread::spawn(move || {
                                for line in stderr_reader.lines().flatten() {
                                    {
                                        let mut lines = output_lines_clone_stderr.lock().unwrap();
                                        lines.push(line.clone());
                                    }
                                    {
                                        let mut out = out_clone_stderr.lock().unwrap();
                                        out.push_str(&line);
                                        out.push('\n');
                                    }
                                }
                            });
                        }

                        let wait_result = child.wait();
                        let _ = wait_result;
                    }
                    Err(e) => {
                        let mut out = output.lock().unwrap();
                        out.push_str(&format!("[red]Command spawn failed: {}\n", e));
                        return;
                    }
                }


                // No longer save_report or set is_running here for non-Python tools.
            });
        }
    }

    // Show the running command string after clearing output
    fn show_running_command(&self, ctx: &eframe::egui::Context) {
        // Optionally trigger a repaint or do nothing if not needed.
        ctx.request_repaint();
    }


    fn check_for_updates_in_thread(command_output: Arc<Mutex<String>>, output_lines: Arc<Mutex<Vec<String>>>) {
        thread::spawn(move || {
            // Define the ASCII art
            let crab_art = "    ▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒
  ▒▒▒▒▒▒                ▒▒▒▒▒▒
  ▒▒▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒            ▒▒▒▒▒▒▒▒▒▒
▒▒▒▒      ██        ██      ▒▒▒▒
▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒
      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
    ▒▒▒▒    ▒▒▒▒▒▒▒▒    ▒▒▒▒";

            let url = "https://bakerstreetforensics.com";

            // Check for updates
            let root = std::env::current_dir().unwrap();
            let update = Command::new("git")
                .arg("remote")
                .arg("update")
                .current_dir(&root)
                .output();

            let status_message = match update {
                Ok(_) => {
                    let status = Command::new("git")
                        .arg("status")
                        .arg("-uno")
                        .current_dir(&root)
                        .output()
                        .unwrap();
                    let status_str = String::from_utf8_lossy(&status.stdout);
                    if status_str.contains("branch is behind") {
                        ("[STATUS]Update available. Please run `git pull`.".to_string(), Color32::YELLOW)
                    } else {
                        ("[OK]MalChela is up to date!".to_string(), Color32::GREEN)
                    }
                }
                Err(e) => {
                    let msg = format!("[STATUS]Update check failed: {}", e);
                    (msg, Color32::RED)
                },
            };

            // Load a random Crabby Koan from YAML
            let koan_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("koans/crabby_koans.yaml");

            let selected_koan = std::fs::read_to_string(koan_path)
                .ok()
                .and_then(|content| serde_yaml::from_str::<Koans>(&content).ok())
                .and_then(|k| k.koans.choose(&mut rand::rng()).cloned())
                .unwrap_or_else(|| "🦀 No koan today.".to_string());

            // Update the output
            let mut output = command_output.lock().unwrap();
            output.clear();
            output.push_str("[CRAB]\n");
            for line in crab_art.lines() {
                output.push_str(&format!("[CRAB]{}\n", line));
            }
            output.push_str("\n");
            output.push_str(&format!("[URL]{}\n\n", url));
            output.push_str(&format!("{}\n\n", status_message.0));
            output.push_str(&format!("[KOAN_COLOR]{}\n", selected_koan));
            // Also write to output_lines so banner appears in GUI
            let mut lines = output_lines.lock().unwrap();
            lines.clear();
            for line in output.lines() {
                lines.push(line.to_string());
            }
        }); 
    }

} 

impl App for AppState {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if self.show_home && !self.banner_displayed {
            AppState::check_for_updates_in_thread(Arc::clone(&self.command_output), Arc::clone(&self.output_lines));
            self.banner_displayed = true;
        }

        ctx.set_visuals(Visuals::dark());

        // --- BEGIN: Load malchela_logo and assign to self if not already loaded ---
        if self.malchela_logo.is_none() {
            let logo_bytes = include_bytes!("../../images/malchela.png");
            let logo_image = image::load_from_memory(logo_bytes).expect("Failed to load logo").to_rgba8();
            let logo_size = [logo_image.width() as usize, logo_image.height() as usize];
            let logo_pixels = logo_image.into_vec();
            let logo_color_image = egui::ColorImage::from_rgba_unmultiplied(logo_size, &logo_pixels);
            let malchela_logo = ctx.load_texture("malchela_logo", logo_color_image, TextureOptions::default());
            self.malchela_logo = Some(malchela_logo);
        }

        // --- Malchela logo rendering with dynamic aspect ratio ---
        if let Some(ref malchela_logo) = self.malchela_logo {
            let logo_texture = malchela_logo;
            let logo_size = logo_texture.size();
            let logo_aspect = logo_size[0] as f32 / logo_size[1] as f32;
            let width = 150.0;
            let height = width / logo_aspect;
            egui::CentralPanel::default().show(ctx, |ui| {
                let image = egui::Image::from_texture(&*logo_texture)
                    .shrink_to_fit()
                    .max_size(Vec2::new(width, height));
                ui.add(image);
            });
        }


        // --- New Case Modal ---
        // (Moved to just before TopBottomPanel below)

        // Note: set_window_icon must be set via NativeOptions::icon_data before run_native.
        // The current method is invalid in eframe and will cause a compile error.
        // frame.set_window_icon(
        //     load_icon(
        //         &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/icon.png")
        //     ).as_ref()
        // );

        // --- New Case Modal (moved from CentralPanel to here, before TopBottomPanel) ---
        if self.show_new_case_modal {
            egui::Window::new(RichText::new("Start New Case").color(RUST_ORANGE))
                .default_width(500.0)
                .default_height(220.0)
                .resizable(false)
                .collapsible(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    // --- Begin: Compact horizontal row for Case Name and Input Type ---
                    ui.horizontal(|ui| {
                        ui.label("Case Name:");
                        if self.case_name.is_none() {
                            self.case_name = Some(String::new());
                        }
                        if let Some(name) = &mut self.case_name {
                            ui.add_sized([250.0, 20.0], egui::TextEdit::singleline(name));
                        }

                        ui.label("Input Type:");
                        let mut input_type_str = self.selected_format.clone();
                        if input_type_str.is_empty() {
                            input_type_str = "file".to_string();
                        }
                        if ui.radio_value(&mut input_type_str, "file".to_string(), "File").clicked() {
                            self.selected_format = "file".to_string();
                            self.input_path = None;
                            self.scratchpad_path.clear();
                        }
                        if ui.radio_value(&mut input_type_str, "folder".to_string(), "Folder").clicked() {
                            self.selected_format = "folder".to_string();
                            self.input_path = None;
                            self.scratchpad_path.clear();
                        }
                        // Removed "hash" input type from New Case modal
                    });
                    // --- End: Compact row ---
                    ui.separator();

                    match self.selected_format.as_str() {
                        "file" => {
                            ui.horizontal(|ui| {
                                if ui.button("Browse File").clicked() {
                                    if let Some(path) = FileDialog::new().pick_file() {
                                        self.input_path = Some(path);
                                    }
                                }
                                if let Some(ref p) = self.input_path {
                                    let path_str = p.display().to_string();
                                    let max_len = 60;
                                    let display_str = if path_str.len() > max_len {
                                        format!("...{}", &path_str[path_str.len() - max_len..])
                                    } else {
                                        path_str.clone()
                                    };
                                    ui.horizontal(|ui| {
                                        ui.label("Selected:");
                                        ui.label(egui::RichText::new(display_str.clone()).monospace())
                                            .on_hover_text(path_str);
                                    });
                                    // Compute SHA256 when a file is selected
                                    let input_type = self.selected_format.as_str();
                                    let selected_path = self.input_path.clone();
                                    if input_type == "file" && selected_path.is_some() {
                                        if let Some(input_path) = selected_path.clone() {
                                            let sha256 = compute_sha256(&input_path);
                                            if let Some(hash) = sha256 {
                                                self.case_sha256 = Some(hash.clone());
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        "folder" => {
                            ui.horizontal(|ui| {
                                if ui.button("Browse Folder").clicked() {
                                    if let Some(path) = FileDialog::new().pick_folder() {
                                        self.input_path = Some(path);
                                    }
                                }
                                if let Some(ref p) = self.input_path {
                                    let path_str = p.display().to_string();
                                    let max_len = 60;
                                    let display_str = if path_str.len() > max_len {
                                        format!("...{}", &path_str[path_str.len() - max_len..])
                                    } else {
                                        path_str.clone()
                                    };
                                    ui.horizontal(|ui| {
                                        ui.label("Selected:");
                                        ui.label(egui::RichText::new(display_str.clone()).monospace())
                                            .on_hover_text(path_str);
                                    });
                                }
                            });
                        }
                        _ => {}
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Start Case").clicked() {
                            self.show_new_case_modal = false;
                            self.show_home = false;
                            self.banner_displayed = false;
                            self.case_modal.visible = false;
                            // Set input_type enum based on selected_format
                            self.input_type = match self.selected_format.as_str() {
                                "folder" => InputType::Folder,
                                "file" => InputType::File,
                                _ => InputType::File, // fallback to File if unknown
                            };
                            match self.input_type {
                                InputType::Folder => {
                                    self.fileminer_panel.input_dir = self.input_path.clone().unwrap_or_default().to_string_lossy().to_string();
                                    self.fileminer_panel.run_fileminer_scan_and_save(self.case_name.as_ref().unwrap());
                                    self.current_panel = ActivePanel::FileMiner;
                                    self.case_modal.visible = false;
                                    self.show_new_case_modal = false;
                                    self.fileminer_panel.visible = true;
                                    ctx.request_repaint();
                                },
                                InputType::File => {
                                    self.current_panel = ActivePanel::Workspace;
                                    self.case_modal.visible = false;
                                    self.show_new_case_modal = false;
                                },
                                InputType::None | InputType::Unknown => {}
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_new_case_modal = false;
                        }
                    });
                });
        }

        TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let mut title = "MalChela Analysis Toolkit v3.0".to_string();
                if !self.edition.trim().is_empty() {
                    title.push_str(&format!(" ({})", self.edition));
                }
                ui.label(
                    RichText::new(title)
                        .font(FontId::proportional(22.0))
                        .color(RUST_ORANGE),
                );

            });
        });

        let _selected_command = self.selected_tool.as_ref().and_then(|tool| tool.command.get(0).cloned());

        SidePanel::left("tool_panel")
            .resizable(false)
            .show(ctx, |ui| {
                // --- Case Management Section (moved above Tools) ---
                ui.add_space(8.0);
                ui.heading(RichText::new("Case Management").color(RUST_ORANGE));

                if ui.button(RichText::new("📁 Cases").color(STONE_BEIGE)).clicked() {
                    self.case_modal.visible = true;
                    self.workspace.minimized = true;
                    self.fileminer_panel.is_minimized = true;
                    self.current_panel = ActivePanel::None;
                }



                ui.separator();

                ui.heading(RichText::new("Tools").color(RUST_ORANGE));
                ScrollArea::vertical().show(ui, |ui| {
                    // Expand/Collapse All buttons
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("🔽")).on_hover_text("Expand All").clicked() {
                            for val in self.collapsed_categories.values_mut() {
                                *val = false;
                            }
                        }
                        if ui.button(RichText::new("🔼")).on_hover_text("Collapse All").clicked() {
                            for val in self.collapsed_categories.values_mut() {
                                *val = true;
                            }
                        }
                    });

                    // --- Tool List Section ---
                    for (category, tools) in &self.categorized_tools {
                        let clean_category = category.trim_start_matches('~');
                        let collapsed = self.collapsed_categories.get(category).copied().unwrap_or(false);
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                // Use clickable label for category header (no button box)
                                use egui::{Label, Sense};
                                let cat_label = clean_category.to_string();
                                let resp = ui.add(Label::new(RichText::new(cat_label).color(RUST_ORANGE).strong().font(FontId::proportional(15.0))).sense(Sense::click()));
                                if resp.clicked() {
                                    let entry = self.collapsed_categories.entry(category.clone()).or_insert(false);
                                    *entry = !*entry;
                                }
                            });
                            if !collapsed {
                                for tool in tools {
                                    let tool_color = STONE_BEIGE;
                                    let mut btn = ui.button(RichText::new(&tool.name).color(tool_color).strong());
                                    if let Some(desc) = &tool.description {
                                        btn = btn.on_hover_text(desc);
                                    }
                                    if btn.clicked() {
                                        // Special handling for FileMiner tool selection
                                        if tool.command.get(0).map(|s| s == "fileminer").unwrap_or(false) {
                                            self.current_panel = ActivePanel::FileMiner;
                                            self.selected_tool = None;
                                            self.fileminer_panel.visible = true;
                                            self.fileminer_panel.is_minimized = false;
                                        } else {
                                            self.selected_tool = Some(tool.clone());
                                            self.custom_args.clear();
                                            self.show_home = false;
                                            self.workspace.minimize();
                                            self.current_panel = ActivePanel::None;
                                            self.fileminer_panel.visible = false;
                                        }
                                        // Reset all input paths and values based on input_type
                                        match tool.input_type.as_str() {
                                            "file" | "folder" => {
                                                self.input_path = None;
                                                self.scratchpad_path.clear();
                                            }
                                            "hash" => {
                                                self.input_path = None;
                                            }
                                            _ => {}
                                        }

                                        // Clear fields that may carry over between tools
                                        self.scratchpad_path.clear();
                                        self.string_source_path.clear();
                                        self.rule_name.clear();
                                        self.author_name.clear();
                                    }
                                }
                            }
                        });
                    }

                    ui.separator();
                    ui.label(
                        RichText::new("Toolkit")
                            .color(RUST_ORANGE)
                            .strong()
                            .font(FontId::proportional(15.0))
                    );

                    if ui.button(RichText::new("🏠 Home").color(STONE_BEIGE)).clicked() {
                        self.show_home = true;
                        self.banner_displayed = false;
                        self.selected_tool = None;
                        self.input_path = None;
                        self.workspace.minimize();
                        self.workspace_root = std::path::PathBuf::new();
                        self.fileminer_panel.visible = false;
                        self.current_panel = ActivePanel::None;
                    }
                    if ui.button(RichText::new("📄 About").color(STONE_BEIGE)).on_hover_text("About MalChela and included tools").clicked() {
                        {
                            let mut out = self.command_output.lock().unwrap();
                            let mut lines = self.output_lines.lock().unwrap();
                            out.clear();
                            lines.clear();
                        }
                        self.workspace.minimize();
                        self.fileminer_panel.visible = false;
                        self.current_panel = ActivePanel::None;
                        let output = Arc::clone(&self.command_output);
                        let output_lines = Arc::clone(&self.output_lines);
                        thread::spawn(move || {
                            let mut child = Command::new("cargo")
                                .args(&["run", "-q", "-p", "about"])
                                .env("MALCHELA_GUI_MODE", "1")
                                .stdout(Stdio::piped())
                                .stderr(Stdio::piped())
                                .spawn()
                                .expect("Failed to run about");

                            if let Some(stdout) = child.stdout.take() {
                                let out_clone = Arc::clone(&output);
                                let output_lines_clone = Arc::clone(&output_lines);
                                thread::spawn(move || {
                                    use std::io::{BufRead, BufReader};
                                    let stdout_reader = BufReader::new(stdout);
                                    for line in stdout_reader.lines().flatten() {
                                        {
                                            let mut lines = output_lines_clone.lock().unwrap();
                                            lines.push(line.clone());
                                        }
                                        {
                                            let mut out = out_clone.lock().unwrap();
                                            out.push_str(&line);
                                            out.push('\n');
                                        }
                                    }
                                });
                            }

                            if let Some(stderr) = child.stderr.take() {
                                let out_clone = Arc::clone(&output);
                                let output_lines_clone = Arc::clone(&output_lines);
                                thread::spawn(move || {
                                    use std::io::{BufRead, BufReader};
                                    let stderr_reader = BufReader::new(stderr);
                                    for line in stderr_reader.lines().flatten() {
                                        {
                                            let mut lines = output_lines_clone.lock().unwrap();
                                            lines.push(format!("[red]{}", line));
                                        }
                                        {
                                            let mut out = out_clone.lock().unwrap();
                                            out.push_str("[red]");
                                            out.push_str(&line);
                                            out.push('\n');
                                        }
                                    }
                                });
                            }

                            let _ = child.wait();
                        });
                    }
                    ui.horizontal(|ui| {
                        ui.menu_button(RichText::new("🛠 Configuration").color(STONE_BEIGE), |ui| {
                            if ui.button("API Keys & Settings").clicked() {
                                self.show_config = true;
                                ui.close_menu();
                            }
                            if ui.button("Tools.yaml").clicked() {
                                self.show_tools_modal = true;
                                self.tools_restore_success = false;
                                ui.close_menu();
                            }
                        });
                    });

                    if ui.button(RichText::new("📖 User Guide").color(STONE_BEIGE)).on_hover_text("Open MalChela User Guide").clicked() {
                        let mut guide_path = std::env::current_exe().unwrap();
                        while let Some(parent) = guide_path.parent() {
                            if parent.join("Cargo.toml").exists() {
                                guide_path = parent.join("docs/MalChela_User_Guide.pdf");
                                break;
                            }
                            guide_path = parent.to_path_buf();
                        }
                        #[cfg(target_os = "macos")]
                        let _ = std::process::Command::new("open").arg(&guide_path).spawn();
                        #[cfg(target_os = "linux")]
                        let _ = std::process::Command::new("xdg-open").arg(&guide_path).spawn();
                        #[cfg(target_os = "windows")]
                        let _ = std::process::Command::new("explorer").arg(&guide_path).spawn();
                    }

                    if ui.button(RichText::new("📝 Scratchpad").color(STONE_BEIGE)).on_hover_text("Open in-app notepad").clicked() {
                        self.show_scratchpad = !self.show_scratchpad;
                        self.fileminer_panel.visible = false;
                        self.current_panel = ActivePanel::None;
                    }

                    if ui.button(RichText::new("📁 View Reports").color(STONE_BEIGE)).on_hover_text("Open saved_output folder").clicked() {
                        self.current_panel = ActivePanel::None;
                        if let Ok(mut exe_path) = std::env::current_exe() {
                            while let Some(parent) = exe_path.parent() {
                                if parent.ends_with("MalChela") {
                                    exe_path = parent.to_path_buf();
                                    break;
                                }
                                exe_path = parent.to_path_buf();
                            }
                            let reports_path = exe_path.join("saved_output");
                            #[cfg(target_os = "macos")]
                            let _ = Command::new("open").arg(&reports_path).spawn();
                            #[cfg(target_os = "windows")]
                            let _ = Command::new("explorer").arg(reports_path).spawn();
                            #[cfg(target_os = "linux")]
                            let _ = Command::new("xdg-open").arg(reports_path).spawn();
                        }
                    }
                });
            });

        // Avoid simultaneous immutable and mutable borrows of self:
        let tool_clone = self.selected_tool.clone();
        let _tool_command = tool_clone.as_ref().and_then(|t| t.command.get(0)).cloned();



use crate::workspace::render_update_check;
CentralPanel::default().show(ctx, |ui| {
            // Ensure update check banner renders at the top of CentralPanel
            render_update_check(ui, self);
            // --- Show New Case Modal if requested ---
            if self.show_new_case_modal {
                show_case_modal(ctx, self);
            }
            // --- Show minimized workspace bar as floating panel in top-right ---
            if self.workspace.is_visible && self.workspace.minimized {
                egui::Window::new("Workspace Minimized")
                    .anchor(egui::Align2::RIGHT_TOP, [-10.0, 10.0])
                    .resizable(false)
                    .collapsible(false)
                    .title_bar(false)
                    .frame(egui::Frame::popup(&ctx.style()).fill(Color32::DARK_GRAY))
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("🔬 Workspace minimized").color(LIGHT_CYAN));
                            if ui.button("Restore").clicked() {
                                self.workspace.minimized = false;
                            }
                        });
                    });
            }
            // --- FULL TAKEOVER CASE WORKSPACE PANEL ---
            if self.workspace.is_visible && !self.workspace.minimized {
                self.workspace.show(ui);
                return;
            }
            // --- Render FileMiner panel if FileMiner is the current panel ---
            if self.current_panel == ActivePanel::FileMiner {
                let app_ptr = self as *const AppState;
                let panel = &mut self.fileminer_panel;
                // SAFETY: `app_ptr` is valid for the duration of this call
                panel.ui(ui, ctx, unsafe { &*app_ptr });
                return;
            }
            // --- Show Case Modal ---
            // Only show the case modal if it is marked visible.
            if self.case_modal.visible && !matches!(self.current_panel, ActivePanel::FileMiner) {
                // Use a safe raw pointer workaround to avoid double mutable borrow:
                let app_ptr: *mut AppState = self;
                let case_modal = &mut self.case_modal;
                case_modal.show(ctx, unsafe { &mut *app_ptr });
            }
            {
                let scanned = *self.current_progress.lock().unwrap();
                let total = *self.total_progress.lock().unwrap();
                if total > 0 {
                    ui.label(RichText::new(format!("Scanned: {} / {}", scanned, total)).color(LIGHT_GREEN).strong());
                }
            }
            if self.is_running.load(std::sync::atomic::Ordering::Relaxed) {
                ui.label(egui::RichText::new("🏃  Running...").color(YELLOW).strong());
            }

            // --- PATCH: Auto-run FileMiner scan if panel is visible, input_dir is set, and results are empty ---
            let app_state_ptr = self as *mut AppState;
            if unsafe { &mut *app_state_ptr }.fileminer_panel.visible
                && !unsafe { &mut *app_state_ptr }.fileminer_panel.input_dir.is_empty()
                && unsafe { &mut *app_state_ptr }.fileminer_panel.results.is_empty()
            {
                unsafe { &mut *app_state_ptr }.fileminer_panel.run_scan();
            }

            // --- Show FileMiner panel if visible and not minimized ---
            {
                let app_ptr = self as *const AppState;
                let panel = &mut self.fileminer_panel;
                if panel.visible && !panel.is_minimized {
                    // SAFETY: `app_ptr` is valid for the duration of this call
                    panel.ui(ui, ctx, unsafe { &*app_ptr });
                }
            }

            if let Some(tool) = &tool_clone {
                // FileMiner panel: show if selected tool is fileminer
                if self.selected_tool.as_ref().map(|t| &t.name) == Some(&tool.name) && tool.command.get(0).map(|s| s == "fileminer").unwrap_or(false) {
                    // --- PATCH: Parse and load FileMiner output as JSON before showing panel ---
                    if let Some(case_name) = &self.case_name {
                        let json_path = format!(
                            "saved_output/cases/{}/fileminer/fileminer_report_{}.json",
                            case_name,
                            self.fileminer_panel.last_scan_timestamp
                        );

                        match std::fs::read_to_string(&json_path) {
                            Ok(content) => {
                                let parsed = self.fileminer_panel.load_from_json(&content);
                                if parsed.is_err() {
                                    *self.command_output.lock().unwrap() = format!(
                                        "❌ Failed to parse FileMiner output: {}\n",
                                        parsed.unwrap_err()
                                    );
                                }
                            }
                            Err(_e) => {
                                *self.command_output.lock().unwrap() = format!(
                                    "❌ Failed to read FileMiner output file.\nPath: {}",
                                    json_path
                                );
                            }
                        }
                    } else {
                        *self.command_output.lock().unwrap() = "❌ No case name provided — cannot load FileMiner output.".to_string();
                    }
                    {
                        let app_ptr = self as *const AppState;
                        let panel = &mut self.fileminer_panel;
                        // SAFETY: `app_ptr` is valid for the duration of this call
                        panel.ui(ui, ctx, unsafe { &*app_ptr });
                    }
                    return;
                }
                // --- Begin fileminer config UI block ---
                // mzhash/xmzhash config panel is now rendered only once in the CentralPanel.
                if tool.command.get(0).map(|s| s == "tshark").unwrap_or(false) {
                    self.tshark_panel.ui(ui);
                    return;
                } else if tool.command.get(0).map(|s| s.contains("vol")).unwrap_or(false) {
                    // Clear console output when selecting Vol3
                    self.command_output.lock().unwrap().clear();
                    self.output_lines.lock().unwrap().clear();

                    // --- Handle malhash and nsrlquery preview command ---
                    if tool.command.get(0).map(|s| s.contains("malhash") || s.contains("nsrlquery")).unwrap_or(false) {
                        if let Some(p) = &self.input_path {
                            let hash_val = p.to_string_lossy();
                            let cmd_str = format!("cargo run -p {} {}", tool.command[0], hash_val);
                            self.vol3_panel.launch_command = Some(cmd_str);
                        }
                    }

                    // --- Vol3 command construction and preview: always update every frame ---
                    if tool.command.get(0).map(|s| s.contains("vol")).unwrap_or(false) {
                        let plugin_name = self.vol3_panel.get_selected_plugin();
                        let mem_path = self.vol3_panel.get_memory_image_path().unwrap_or_default();
                        // Only generate preview here; actual writing is done on Run button click.
                        let preview_output_path = if self.vol3_panel.save_to_case {
                            None
                        } else {
                            self.vol3_panel.arg_values.iter()
                                .filter(|(_, v)| !v.trim().is_empty())
                                .find(|(k, _)| k.contains("output") || k.contains("dump") || k.contains("path"))
                                .map(|(_, v)| v.as_str())
                        };
                        let preview_custom_args = self.vol3_panel.arg_values.iter()
                            .filter(|(k, _)| !k.contains("output") && !k.contains("dump") && !k.contains("path"))
                            .map(|(k, v)| format!("--{} \"{}\"", k, v))
                            .collect::<Vec<String>>()
                            .join(" ");

                        let full_command_str = self.vol3_panel.build_vol3_command(
                            &mem_path,
                            &plugin_name,
                            &preview_custom_args,
                            preview_output_path,
                        );
                        self.vol3_panel.launch_command = Some(full_command_str.clone());
                    }

                    self.vol3_panel.ui(ui, &self.vol3_plugins, &mut self.input_path, &mut self.custom_args, &mut self.save_report);

                    // Removed: Save Report checkbox and format selection for Vol3.

                    ui.horizontal(|ui| {
                        if ui.button("Run").clicked() {
                            // Compute output_path and custom_args here, after all .ui() and closures that borrow self mutably.
                            let output_path = if self.vol3_panel.save_to_case {
                                None
                            } else {
                                self.vol3_panel.arg_values.iter()
                                    .filter(|(_, v)| !v.trim().is_empty())
                                    .find(|(k, _)| k.contains("output") || k.contains("dump") || k.contains("path"))
                                    .map(|(_, v)| v.as_str())
                            };
                            let custom_args = self.vol3_panel.arg_values.iter()
                                .filter(|(k, _)| !k.contains("output") && !k.contains("dump") && !k.contains("path"))
                                .map(|(k, v)| format!("--{} \"{}\"", k.trim_start_matches('-'), v))
                                .collect::<Vec<String>>()
                                .join(" ");
                            // Correct PathBuf to string conversion for vol3 command
                            let mem_path = self.input_path.clone().unwrap_or_default();
                            let mem_path_str = mem_path.to_string_lossy().to_string();
                            println!("🧠 Memory path being passed to build_vol3_command: {:?}", mem_path_str);
                            // Debug print for output_path value
                            println!("🔍 Output path being passed to build_vol3_command: {:?}", output_path);
                            // Ensure output directory is created before writing launch script
                            self.vol3_panel.ensure_vol3_case_output_dir();
                            // Fix: define plugin_name before use
                            let plugin_name = self.vol3_panel.get_selected_plugin();
                            // Write launch_vol3.command only when Run is clicked, using the exact command string
                            let full_command_str = self.vol3_panel.build_vol3_command(
                                &mem_path_str,
                                &plugin_name,
                                &custom_args,
                                output_path,
                            );
                            write_launch_script("launch_vol3.command", &full_command_str);

                            // --- Restored launch logic for Vol3 (exactly as in production) ---
                            let launch_path = std::env::current_dir().unwrap().join("launch_vol3.command");
                            let _ = std::process::Command::new("chmod").arg("+x").arg(&launch_path).status();

                            // Output the script path to the console area for clarity and copy-paste use
                            {
                                let mut out = self.command_output.lock().unwrap();
                                out.push_str(&format!("Launch script created at: {}\n", launch_path.display()));
                                self.output_lines.lock().unwrap().push(format!("Launch script created at: {}", launch_path.display()));
                            }

                            // Platform-specific terminal launch logic
                            #[cfg(target_os = "macos")]
                            let terminal_launch = std::process::Command::new("osascript")
                                .arg("-e")
                                .arg(format!("tell app \"Terminal\" to do script \"{}\"", launch_path.display()))
                                .spawn();

                            #[cfg(target_os = "linux")]
                            let terminal_launch = std::process::Command::new("x-terminal-emulator")
                                .arg("-e")
                                .arg(&launch_path)
                                .spawn();

                            let _ = terminal_launch;

                            self.is_running.store(false, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        ui.label(RichText::new("(Vol3 command will launch in a separate terminal)").color(Color32::GRAY));
                    });

                    ui.separator();
                    ui.heading(RichText::new("Console Output").color(LIGHT_CYAN));
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            let output_lines = self.output_lines.lock().unwrap();
                            let lines = output_lines.clone();
                            for line in lines.iter() {
                                ui.label(line);
                            }
                        });
                    return;
                }
                ui.label(
                    RichText::new(format!(
                        "Selected Tool: {} (Input: {})",
                        tool.name, tool.input_type
                    ))
                    .color(LIGHT_CYAN)
                    .strong(),
                );
                if let Some(desc) = &tool.description {
                    ui.label(RichText::new(desc).strong().color(STONE_BEIGE));
                }
                // Only show the standard input config and command line preview if NOT mzhash or xmzhash
                if tool.command.get(0).map(|s| s != "mzhash" && s != "xmzhash").unwrap_or(true) {
                    use std::fmt::Write as _;
                    // Determine exec_type
                    #[derive(PartialEq)]
                    enum ExecType { Cargo, Binary }
                    let exec_type = match tool.exec_type.as_deref() {
                        Some("binary") | Some("Binary") => ExecType::Binary,
                        _ => ExecType::Cargo,
                    };
                    if tool.command.get(0).map(|s| s == "strings_to_yara").unwrap_or(false) {
                        let mut preview = format!(
                            "cargo run -p strings_to_yara -- \"{}\" \"{}\" \"{}\" \"{}\" \"{}\"",
                            &self.rule_name,
                            &self.author_name,
                            &self.selected_format,
                            &self.scratchpad_path,
                            &self.string_source_path
                        );
                        if !self.custom_args.trim().is_empty() {
                            preview.push(' ');
                            preview.push_str(self.custom_args.trim());
                        }
                        ui.label(RichText::new(preview).color(GREEN).strong());
                    } else if let Some(ref p) = self.input_path {
                        let input_path_str = p.display().to_string();
                        let command_line = if tool.command.get(0).map(|s| s == "hashcheck").unwrap_or(false) {
                            match exec_type {
                                ExecType::Binary => {
                                    let mut s = String::new();
                                    write!(
                                        &mut s,
                                        "{} {}",
                                        tool.command.join(" "),
                                        input_path_str
                                    ).unwrap();
                                    if !self.custom_args.trim().is_empty() {
                                        s.push(' ');
                                        s.push_str(self.custom_args.trim());
                                    }
                                    s
                                }
                                ExecType::Cargo => {
                                    format!("cargo run -p hashcheck -- {} {}", input_path_str, self.custom_args.trim())
                                }
                            }
                        } else if tool.command.get(0).map(|s| s.contains("vol")).unwrap_or(false) {
                            let case_name = self.case_name.clone().unwrap_or_else(|| "unnamed_case".to_string());
                            let _output_dir = format!("saved_output/cases/{}/vol3", case_name);
                            let output_dir_str = _output_dir.clone();
                            let selected_plugin = self.vol3_panel.get_selected_plugin();
                            let plugin_name = selected_plugin.trim();
                            let _custom_args = self.custom_args.trim();
                            let command_string = self.vol3_panel.build_vol3_command(
                                &output_dir_str,
                                plugin_name,
                                &_custom_args,
                                Some(&output_dir_str),
                            );
                            command_string
                        } else {
                            match exec_type {
                                ExecType::Binary => {
                                    // Determine file position for input_path_str
                                    let mut cmd_vec = tool.command.clone();
                                    let mut file_pos = None;
                                    if let Some(idx) = cmd_vec.iter().position(|s| s == "first") {
                                        file_pos = Some(idx - 1);
                                        cmd_vec.retain(|s| s != "first" && s != "last");
                                    } else if let Some(_) = cmd_vec.iter().position(|s| s == "last") {
                                        file_pos = Some(cmd_vec.len());
                                        cmd_vec.retain(|s| s != "first" && s != "last");
                                    } else if tool.input_type != "hash" {
                                        file_pos = Some(1);
                                    }
                                    let mut arg_vec = cmd_vec.clone();
                                    if let Some(idx) = file_pos {
                                        if idx <= arg_vec.len() {
                                            arg_vec.insert(idx, input_path_str.clone());
                                        }
                                    }
                                    let mut s = arg_vec.join(" ");
                                    if !self.custom_args.trim().is_empty() {
                                        s.push(' ');
                                        s.push_str(self.custom_args.trim());
                                    }
                                    s
                                }
                                ExecType::Cargo => {
                                    let mut base = format!("cargo run -p {}", tool.command[0]);
                                    if tool.command.len() > 1 {
                                        base.push(' ');
                                        base.push_str(&tool.command[1..].join(" "));
                                    }

                                    // Skip -- if input_type is hash
                                    if tool.input_type != "hash" {
                                        base.push_str(" --");
                                        base.push(' ');
                                        base.push_str(&input_path_str);
                                    } else {
                                        base.push(' ');
                                        base.push_str(&input_path_str);
                                    }
                                    if !self.custom_args.trim().is_empty() {
                                        base.push(' ');
                                        base.push_str(&self.custom_args.trim());
                                    }
                                    base
                                }
                            }
                        };
                        ui.label(RichText::new(command_line).color(GREEN).strong());
                    }
                }
                // --- Begin mzhash/xmzhash configuration block ---
                if tool.command.get(0).map(|s| s == "mzhash" || s == "xmzhash").unwrap_or(false) {
                    // --- Begin mzhash/xmzhash configuration block ---
                    ui.horizontal(|ui| {
                        ui.label("Folder Path:");
                        let mut path_buf = self.input_path.clone().unwrap_or_default();
                        let mut path_str = path_buf.display().to_string();
                        ui.text_edit_singleline(&mut path_str);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_folder() {
                                self.input_path = Some(path);
                                path_buf = self.input_path.clone().unwrap_or_default();
                                path_str = path_buf.display().to_string();
                            }
                        }
                        if !path_str.is_empty() {
                            ui.label(RichText::new(format!("Selected: {}", path_str)).color(STONE_BEIGE));
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Algorithms:").strong());
                        for algo in ["MD5", "SHA1", "SHA256"] {
                            let mut selected = self.selected_algorithms.contains(&algo.to_string());
                            if ui.checkbox(&mut selected, algo).changed() {
                                if selected {
                                    if !self.selected_algorithms.contains(&algo.to_string()) {
                                        self.selected_algorithms.push(algo.to_string());
                                    }
                                } else {
                                    self.selected_algorithms.retain(|a| a != algo);
                                }
                            }
                        }
                    });

                    let mut allow_overwrite = self.custom_args.contains("MZHASH_ALLOW_OVERWRITE=1");
                    if ui.checkbox(&mut allow_overwrite, "Allow Overwrite").changed() {
                        let mut args: Vec<String> = self.custom_args
                            .split_whitespace()
                            .map(str::to_string)
                            .filter(|arg| !arg.starts_with("MZHASH_ALLOW_OVERWRITE"))
                            .collect();
                        if allow_overwrite {
                            args.push("MZHASH_ALLOW_OVERWRITE=1".to_string());
                        }
                        self.custom_args = args.join(" ");
                    }

                    // --- End mzhash/xmzhash block ---
                }
                if tool.command.get(0).map(|s| s == "strings_to_yara").unwrap_or(false) {
                    ui.label(RichText::new("strings_to_yara Configuration").strong().color(LIGHT_CYAN));
                    ui.horizontal(|ui| {
                        ui.label("Rule Name*:");
                        ui.text_edit_singleline(&mut self.rule_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Description:");
                        if self.selected_format.ends_with(".txt") {
                            self.selected_format = self.selected_format.trim_end_matches(".txt").to_string();
                        }
                        ui.text_edit_singleline(&mut self.selected_format);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Author:");
                        ui.text_edit_singleline(&mut self.author_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Hash:");
                        ui.text_edit_singleline(&mut self.scratchpad_path);
                    });
                    ui.horizontal(|ui| {
                        ui.label("String Source:");
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.string_source_path = path.display().to_string(); 
                            }
                        }
                        if ui.button("Use Scratchpad").clicked() {
                            let filename = "scratchpad.txt";
                            let content = self.scratchpad_content.lock().unwrap();
                            if let Ok(mut file) = File::create(filename) {
                                let _ = writeln!(file, "{}", content);
                            }
                            self.string_source_path = filename.to_string(); 
                        }
                        ui.label(
                            if self.string_source_path == "scratchpad.txt" {
                                "Using: scratchpad.txt"
                            } else if !self.string_source_path.is_empty() {
                                &self.string_source_path
                            } else {
                                "No file selected"
                            }
                        );
                    });
                } else if tool.command.get(0).map(|s| s == "mzcount").unwrap_or(false) {
                    let mut table_display_mode = self.custom_args.contains("MZCOUNT_TABLE_DISPLAY=1");
                    ui.horizontal(|ui| {
                        ui.label("Display Mode:");
                        egui::ComboBox::from_id_source("mzcount_display_mode")
                            .selected_text(if table_display_mode { "Table View" } else { "Detailed View" })
                            .show_ui(ui, |ui| {
                                if ui.selectable_label(table_display_mode, "Table View").clicked() {
                                    table_display_mode = true;
                                }
                                if ui.selectable_label(!table_display_mode, "Detailed View").clicked() {
                                    table_display_mode = false;
                                }
                            });
                    });
                    self.custom_args = self
                        .custom_args
                        .split_whitespace()
                        .filter(|arg| !arg.starts_with("MZCOUNT_TABLE_DISPLAY"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    self.custom_args.push_str(&format!(
                        " MZCOUNT_TABLE_DISPLAY={}",
                        if table_display_mode { "1" } else { "0" }
                    ));
                    ui.horizontal(|ui| {
                        ui.label("Folder Path:");
                        let mut path_buf = self.input_path.clone().unwrap_or_default();
                        let mut path_str = path_buf.display().to_string();
                        ui.text_edit_singleline(&mut path_str);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_folder() {
                                self.input_path = Some(path);
                                path_buf = self.input_path.clone().unwrap_or_default();
                                path_str = path_buf.display().to_string();
                            }
                        }
                        if !path_str.is_empty() {
                            ui.label(RichText::new(format!("Selected: {}", path_str)).color(STONE_BEIGE));
                        }
                    });
                } else if tool.command.get(0).map(|s| s == "yr").unwrap_or(false) {
                    ui.label(RichText::new("YARA-X Configuration").strong().color(LIGHT_CYAN));

                    ui.horizontal(|ui| {
                        ui.label("Rule File:");
                        ui.text_edit_singleline(&mut self.scratchpad_path);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().add_filter("YARA Rules", &["yar", "yara"]).pick_file() {
                                self.scratchpad_path = path.display().to_string();
                            }
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Target File:");
                        let mut path_buf = self.input_path.clone().unwrap_or_default();
                        let mut path_str = path_buf.display().to_string();
                        ui.text_edit_singleline(&mut path_str);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.input_path = Some(path);
                                path_buf = self.input_path.clone().unwrap_or_default();
                                path_str = path_buf.display().to_string();
                            }
                        }
                        if !path_str.is_empty() {
                            ui.label(RichText::new(format!("Selected: {}", path_str)).color(STONE_BEIGE));
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Arguments:");
                        ui.text_edit_singleline(&mut self.custom_args);
                    });

                    // Override save report checkbox for YARA-X
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.save_report.0, "Save Report");
                        if self.save_report.0 {
                            ui.label("Format:");
                            egui::ComboBox::from_id_source("save_format")
                                .selected_text(&self.save_report.1)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.save_report.1, ".txt".to_string(), "txt");
                                    ui.selectable_value(&mut self.save_report.1, ".json".to_string(), "json");
                                    ui.selectable_value(&mut self.save_report.1, ".md".to_string(), "md");
                                });
                        }
                    });
                } else if tool.command.get(0).map(|s| s.ends_with("floss")).unwrap_or(false) {
                    // --- FLOSS tool configuration section ---
                    ui.horizontal(|ui| {
                        ui.label("Target File:");
                        let mut path_buf = self.input_path.clone().unwrap_or_default();
                        let mut path_str = path_buf.display().to_string();
                        ui.text_edit_singleline(&mut path_str);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.input_path = Some(path);
                                path_buf = self.input_path.clone().unwrap_or_default();
                                path_str = path_buf.display().to_string();
                            }
                        }
                        if !path_str.is_empty() {
                            ui.label(RichText::new(format!("Selected: {}", path_str)).color(STONE_BEIGE));
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Arguments:");
                        ui.text_edit_singleline(&mut self.custom_args);
                    });

                    // --- Begin FLOSS-specific argument controls ---
                    ui.horizontal(|ui| {
                        ui.label("Minimum Length (-n):");
                        let mut min_length = self.custom_args
                            .split_whitespace()
                            .enumerate()
                            .find_map(|(i, arg)| {
                                if arg == "-n" {
                                    self.custom_args.split_whitespace().nth(i + 1)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or("4")
                            .to_string();
                        if ui.text_edit_singleline(&mut min_length).changed() {
                            let mut args: Vec<String> = self.custom_args.split_whitespace().map(String::from).collect();
                            if let Some(i) = args.iter().position(|s| s == "-n") {
                                args.remove(i);
                                if i < args.len() {
                                    args.remove(i); // Remove the old value
                                }
                            }
                            args.push("-n".to_string());
                            args.push(min_length.clone());
                            self.custom_args = args.join(" ");
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Extract Only:");
                        for s_type in ["static", "stack", "tight", "decoded"] {
                            let flag = format!("--only {}", s_type);
                            let is_selected = self.custom_args.contains(&flag);
                            let mut selected = is_selected;
                            if ui.checkbox(&mut selected, s_type).changed() {
                                let mut args: Vec<String> = self.custom_args.split_whitespace().map(String::from).collect();
                                args.retain(|arg| !arg.starts_with("--only"));
                                if selected {
                                    args.push("--only".to_string());
                                    args.push(s_type.to_string());
                                }
                                self.custom_args = args.join(" ");
                            }
                        }
                    });
                    // --- Inserted: FLOSS sample format, progress, verbosity, debug, color ---
                    ui.horizontal(|ui| {
                        ui.label("Sample Format:");
                        egui::ComboBox::from_id_source("floss_sample_format")
                            .selected_text(self.selected_format.clone())
                            .show_ui(ui, |ui| {
                                for opt in ["auto", "pe", "sc32", "sc64"] {
                                    if ui.selectable_value(&mut self.selected_format, opt.to_string(), opt).clicked() {
                                        self.custom_args = self.custom_args
                                            .split_whitespace()
                                            .filter(|arg| arg != &"-f" && !["auto", "pe", "sc32", "sc64"].contains(arg))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        self.custom_args.push_str(&format!(" -f {}", opt));
                                    }
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        let mut disable_progress = self.custom_args.contains("--disable-progress");
                        if ui.checkbox(&mut disable_progress, "Disable Progress").changed() {
                            self.custom_args = self.custom_args
                                .split_whitespace()
                                .filter(|arg| *arg != "--disable-progress")
                                .collect::<Vec<_>>()
                                .join(" ");
                            if disable_progress {
                                self.custom_args.push_str(" --disable-progress");
                            }
                        }
                    });

                    // Inserted: Allow Large File (-L) toggle
                    ui.horizontal(|ui| {
                        let mut large_file = self.custom_args.contains("-L");
                        if ui.checkbox(&mut large_file, "Allow Large File (-L)").changed() {
                            self.custom_args = self.custom_args
                                .split_whitespace()
                                .filter(|arg| *arg != "-L")
                                .collect::<Vec<_>>()
                                .join(" ");
                            if large_file {
                                self.custom_args.push_str(" -L");
                            }
                        }
                    });


                    ui.horizontal(|ui| {
                        ui.label("Color Output:");
                        egui::ComboBox::from_id_source("floss_color_setting")
                            .selected_text(
                                if self.custom_args.contains("--color always") {
                                    "always"
                                } else if self.custom_args.contains("--color never") {
                                    "never"
                                } else {
                                    "auto"
                                }
                            )
                            .show_ui(ui, |ui| {
                                for mode in ["auto", "always", "never"] {
                                    if ui.selectable_label(
                                        self.custom_args.contains(&format!("--color {}", mode)),
                                        mode
                                    ).clicked() {
                                        self.custom_args = self.custom_args
                                            .split_whitespace()
                                            .filter(|arg| *arg != "--color" && *arg != "auto" && *arg != "always" && *arg != "never")
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        self.custom_args.push_str(&format!(" --color {}", mode));
                                    }
                                }
                            });
                    });
                    // --- Inserted: FLOSS Verbose (-v) toggle ---
                    ui.horizontal(|ui| {
                        let mut verbose = self.custom_args.contains("-v");
                        if ui.checkbox(&mut verbose, "Verbose (-v)").changed() {
                            self.custom_args = self
                                .custom_args
                                .split_whitespace()
                                .filter(|arg| *arg != "-v")
                                .collect::<Vec<_>>()
                                .join(" ");
                            if verbose {
                                self.custom_args.push_str(" -v");
                            }
                        }
                    });
                    // --- End FLOSS argument controls ---

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.save_report.0, "Save Report");
                        if self.save_report.0 {
                            ui.label("Format:");
                            egui::ComboBox::from_id_source("save_format")
                                .selected_text(&self.save_report.1)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.save_report.1, ".txt".to_string(), "txt");
                                    ui.selectable_value(&mut self.save_report.1, ".json".to_string(), "json");
                                    ui.selectable_value(&mut self.save_report.1, ".md".to_string(), "md");
                                });
                        }
                    });
                } else {

                    // --- Inserted: hashcheck tool-specific configuration ---
                    if tool.command.get(0).map(|s| s == "hashcheck").unwrap_or(false) {

                        ui.horizontal(|ui| {
                            ui.label("Hash File:");
                            let mut input_str = self.input_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                            ui.text_edit_singleline(&mut input_str);
                            if ui.button("Browse").clicked() {
                                if let Some(path) = FileDialog::new().add_filter("TSV or TXT", &["tsv", "txt"]).pick_file() {
                                    self.input_path = Some(path);
                                }
                            }
                            if let Some(ref path) = self.input_path {
                                if !path.as_os_str().is_empty() {
                                    ui.label(
                                        RichText::new(
                                            format!(
                                                "Selected: {}",
                                                self.input_path
                                                    .as_ref()
                                                    .map(|p| p.display().to_string())
                                                    .unwrap_or_default()
                                            )
                                        )
                                        .color(STONE_BEIGE)
                                    );
                                }
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Hash to Search:");
                            ui.text_edit_singleline(&mut self.custom_args);
                        });

                        ui.label(RichText::new("📌 Tip: TSV format is preferred for path lookup support.").color(LIGHT_GREEN));
                    } else {
                        // For mzhash/xmzhash, do not show duplicate input UI here.
                        if !(tool.command.get(0).map(|s| s == "mzhash" || s == "xmzhash").unwrap_or(false)) {
                            ui.horizontal(|ui| {
                                let label = match tool.input_type.as_str() {
                                    "hash" => "Hash:",
                                    "folder" => "Folder Path:",
                                    _ => "File Path:",
                                };
                                ui.label(label);

                                // Always allow editing the field
                                let mut path_str = self.input_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                                if ui.text_edit_singleline(&mut path_str).changed() {
                                    self.input_path = Some(std::path::PathBuf::from(path_str));
                                }

                                // Only allow browsing if not a hash
                                if tool.input_type != "hash" {
                                    if ui.button("Browse").clicked() {
                                        let picked = if tool.input_type == "folder" {
                                            FileDialog::new().pick_folder()
                                        } else {
                                            FileDialog::new().pick_file()
                                        };
                                        if let Some(path) = picked {
                                            self.input_path = Some(path);
                                        }
                                    }
                                }
                            });

                            // Move the fileminer mismatches checkbox here, directly after Folder Path row
                            if tool.command.get(0).map(|s| s == "fileminer").unwrap_or(false) {
                                let mut show_mismatches = self.custom_args.contains("-m");
                                if ui.checkbox(&mut show_mismatches, "Show mismatches only").changed() {
                                    let mut args: Vec<String> = self.custom_args
                                        .split_whitespace()
                                        .map(str::to_string)
                                        .filter(|arg| arg != "-m")
                                        .collect();
                                    if show_mismatches {
                                        args.push("-m".to_string());
                                    }
                                    self.custom_args = args.join(" ");
                                }
                            }
                            // --- PATCH: Restore FileMiner panel if FileMiner tool is selected ---
                            if let Some(selected) = &self.selected_tool {
                                if selected.name == tool.name {
                                    if tool.name.to_lowercase().contains("fileminer") {
                                        self.fileminer_panel.visible = true;
                                        self.fileminer_panel.is_minimized = false;
                                        // Minimize all other panels
                                        self.workspace.minimized = true;

                                    }
                                    // continue with other logic (if any)
                                }
                            }
                        }
                        if tool.exec_type.as_deref() == Some("script") || tool.exec_type.as_deref() == Some("binary") {
                            ui.horizontal(|ui| {
                                ui.label("Arguments:");
                                ui.text_edit_singleline(&mut self.custom_args);
                            });
                        }
                    }


                    if let Some(tool_name) = tool.command.get(0) {
                        let skip_report_tools = ["strings_to_yara", "combine_yara", "extract_samples", "mzcount", "mzhash", "xmzhash"];
                        if !skip_report_tools.contains(&tool_name.as_str()) {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.save_report.0, "Save Report");
                                if self.save_report.0 {
                                    ui.label("Format:");
                                    egui::ComboBox::from_id_source("save_format")
                                        .selected_text(&self.save_report.1)
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.save_report.1, ".txt".to_string(), "txt");
                                            ui.selectable_value(&mut self.save_report.1, ".json".to_string(), "json");
                                            ui.selectable_value(&mut self.save_report.1, ".md".to_string(), "md");
                                        });
                                }
                            });
                        }
                    }
                    if tool.command.get(0).map(|s| s == "extract_samples").unwrap_or(false) {
                        ui.horizontal(|ui| {
                            ui.label("ZIP Password:");
                            ui.text_edit_singleline(&mut self.zip_password);
                        });
                    }
                }

                if ui.button("Run").clicked() {
                    self.run_tool(ctx);
                }
            }

            ui.separator();
            ui.heading(RichText::new("Console Output").color(LIGHT_CYAN));
            let output_lines = self.output_lines.lock().unwrap().clone();
            ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                let mut latest_table_lines = vec![];
                let mut in_table_block = false;
                let mut standard_lines = vec![];

                for line in output_lines {
                    if line.contains("[TABLE_UPDATE]") {
                        in_table_block = true;
                        latest_table_lines.clear();
                        continue;
                    }

                    if in_table_block {
                        latest_table_lines.push(RichText::new(&line).monospace().color(STONE_BEIGE));
                    } else {
                        let clean_line = line.trim_start();
                        let styled = if clean_line.starts_with("Scan completed.") {
                            RichText::new(&line).monospace().color(GREEN)
                        } else if clean_line.starts_with("Total number of hashes written:") {
                            RichText::new(&line).monospace().color(RUST_ORANGE)
                        } else if clean_line.starts_with("Output file location:") {
                            RichText::new(&line).monospace().color(STONE_BEIGE)
                        } else if clean_line.to_lowercase().contains("potential filesystem ioc") {
                            RichText::new(&line).monospace().color(RUST_ORANGE)
                        } else if clean_line.to_lowercase().contains("potential network ioc") {
                            RichText::new(&line).monospace().color(RUST_ORANGE)
                        } else if clean_line.ends_with("unique detections matched.") {
                            RichText::new(&line).monospace().color(RUST_ORANGE)
                        } else if line.starts_with("[CRAB]") {
                            RichText::new(line.trim_start_matches("[CRAB]")).monospace().color(RED)
                        } else if line.starts_with("[URL]") {
                            RichText::new(line.trim_start_matches("[URL]")).monospace().color(STONE_BEIGE)
                        } else if line.starts_with("[STATUS]") {
                            RichText::new(line.trim_start_matches("[STATUS]")).monospace().color(RUST_ORANGE)
                        } else if line.starts_with("[OK]") {
                            RichText::new(line.trim_start_matches("[OK]")).monospace().color(GREEN)
                        } else if line.starts_with("[KOAN_COLOR]") {
                            RichText::new(line.trim_start_matches("[KOAN_COLOR]")).monospace().color(RUST_ORANGE)
                        } else if line.starts_with("[ABOUT]") {
                            RichText::new(line.trim_start_matches("[ABOUT]")).monospace().color(GREEN)
                        } else if line.starts_with("[FEATURES]") {
                            RichText::new(line.trim_start_matches("[FEATURES]")).monospace().color(GREEN)
                        } else if line.starts_with("[NOTE]") {
                            RichText::new(line.trim_start_matches("[NOTE]")).monospace().color(RUST_ORANGE)
                        } else if line.starts_with("[bold]") {
                            RichText::new(line.trim_start_matches("[bold]").replace("[reset]", "")).monospace().color(LIGHT_GREEN)
                        } else if line.contains("[reset]") {
                            RichText::new(line.replace("[reset]", "")).monospace().color(STONE_BEIGE)
                        } else if line.starts_with("[yellow]") {
                            RichText::new(line.trim_start_matches("[yellow]")).monospace().color(YELLOW)
                        } else if line.starts_with("[cyan]") {
                            RichText::new(line.trim_start_matches("[cyan]")).monospace().color(LIGHT_CYAN)
                        } else if line.starts_with("[stone]") {
                            RichText::new(line.trim_start_matches("[stone]")).monospace().color(STONE_BEIGE)
                        } else if line.starts_with("[highlight]") {
                            RichText::new(line.trim_start_matches("[highlight]")).monospace().color(LIGHT_GREEN)
                        } else if line.starts_with("[NOTE]") {
                            RichText::new(line.trim_start_matches("[NOTE]")).monospace().color(RUST_ORANGE)
                        } else if line.starts_with("[rust]") {
                            RichText::new(line.trim_start_matches("[rust]")).monospace().color(RUST_ORANGE)
                        } else if line.starts_with("[green]") {
                            RichText::new(line.trim_start_matches("[green]")).monospace().color(GREEN)
                        } else if line.starts_with("[white]") {
                            RichText::new(line.trim_start_matches("[white]")).monospace().color(Color32::WHITE)
                        } else if line.starts_with("[gray]") {
                            RichText::new(line.trim_start_matches("[gray]")).monospace().color(STONE_BEIGE)
                        } else if line.starts_with("[red]") {
                            RichText::new(line.trim_start_matches("[red]")).monospace().color(RED)
                        } else if line.contains("[highlight]") {
                            RichText::new(line.replacen("[highlight]", "", 1)).monospace().color(LIGHT_GREEN)
                        } else if line.contains("[stone]") {
                            RichText::new(line.replacen("[stone]", "", 1)).monospace().color(STONE_BEIGE)
                        } else {
                            RichText::new(&line).monospace().color(STONE_BEIGE)
                        };
                        standard_lines.push(styled);
                    }
                }

                for styled_line in standard_lines {
                    ui.label(styled_line);
                }

                if !latest_table_lines.is_empty() {
                    for styled_line in &latest_table_lines {
                        ui.label(styled_line.clone());
                    }
                }
            });

            if self.show_scratchpad {
                egui::Window::new("Scratchpad")
                    .default_width(400.0)
                    .open(&mut self.show_scratchpad)
                    .show(ctx, |ui| {
                        let mut content = self.scratchpad_content.lock().unwrap();
                        ui.add_sized(
                            [ui.available_width(), 300.0],
                            TextEdit::multiline(&mut *content),
                        );
                        ui.horizontal(|ui| {
                            ui.label("Save as:");
                            if ui.button(".txt").clicked() {
                                self.selected_format = ".txt".into();
                            }
                            if ui.button(".md").clicked() {
                                self.selected_format = ".md".into();
                            }
                            if ui.button(".yaml").clicked() {
                                self.selected_format = ".yaml".into();
                            }
                            if ui.button("Save").clicked() {
                                let filename = format!("scratchpad{}", self.selected_format);
                                if let Ok(mut file) = File::create(filename) {
                                    let _ = writeln!(file, "{}", content);
                                }
                            }
                            if ui.button("Open in VSCode").clicked() {
                                let _ = Command::new("code")
                                    .arg(format!("scratchpad{}", self.selected_format))
                                    .spawn();
                            }
                        });
                    });
            }

            if self.show_config {
                egui::Window::new("Configuration")
                    .default_width(400.0)
                    .open(&mut self.show_config)
                    .show(ctx, |ui| {
                        ui.label("VirusTotal API Key:");
                        let mut vt = self.vt_api_key.clone();
                        let mut changed_vt = false;
                        if self.hide_vt {
                            changed_vt |= ui.add(TextEdit::singleline(&mut vt).password(true)).changed();
                        } else {
                            changed_vt |= ui.text_edit_singleline(&mut vt).changed();
                        }
                        ui.checkbox(&mut self.hide_vt, "Hide VT Key");

                        if changed_vt && !vt.trim().is_empty() {
                            self.vt_api_key = vt.trim().to_string();
                            let _ = std::fs::write("vt-api.txt", &self.vt_api_key);
                        }

                        ui.separator();

                        ui.label("MalwareBazaar API Key:");
                        let mut mb = self.mb_api_key.clone();
                        let mut changed_mb = false;
                        if self.hide_mb {
                            changed_mb |= ui.add(TextEdit::singleline(&mut mb).password(true)).changed();
                        } else {
                            changed_mb |= ui.text_edit_singleline(&mut mb).changed();
                        }
                        ui.checkbox(&mut self.hide_mb, "Hide MB Key");

                        if changed_mb && !mb.trim().is_empty() {
                            self.mb_api_key = mb.trim().to_string();
                            let _ = std::fs::write("mb-api.txt", &self.mb_api_key);
                        }
                    });
            }
        });

        // Modal for Backup / Restore tools.yaml
        if self.show_tools_modal {
            use egui::Align2;
            use std::fs;
            use std::io::Read;
            use chrono::Utc;
            let mut modal_open = self.show_tools_modal;
            let mut should_close = false;
            egui::Window::new("Backup / Restore tools.yaml")
                .default_width(410.0)
                .collapsible(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut modal_open)
                .show(ctx, |ui| {
                    ui.label(RichText::new("Backup or restore your tools.yaml configuration.").color(LIGHT_CYAN));
                    ui.separator();
                    // Ensure saved_output/configuration exists
                    let config_dir = self.workspace_root.join("saved_output").join("configuration");
                    let _ = fs::create_dir_all(&config_dir);

                    // --- Vertically centered justified layout for tools.yaml modal ---
                    ui.vertical_centered_justified(|ui| {
                        let button_width = 200.0;
                        // Row 1: Back Up & Restore
                        ui.horizontal(|ui| {
                            if ui.add_sized([button_width, 30.0], egui::Button::new("Back Up"))
                                .on_hover_text("Save a backup copy of tools.yaml")
                                .clicked() {
                                let mut config_path = self.workspace_root.clone();
                                config_path = config_path.join("tools.yaml");
                                let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
                                let backup_path = config_dir.join(format!("tools_backup_{}.yaml", timestamp));
                                if let Ok(contents) = fs::read(&config_path) {
                                    let _ = fs::write(&backup_path, contents);
                                    self.restore_status_message = format!("✅ Backup saved as: {}", backup_path.display());
                                    self.tools_restore_success = true;
                                }
                            }
                            if ui.add_sized([button_width, 30.0], egui::Button::new("Restore"))
                                .on_hover_text("Restore tools.yaml from a backup file")
                                .clicked() {
                                if let Some(path) = FileDialog::new()
                                    .set_directory(&config_dir)
                                    .add_filter("YAML", &["yaml", "yml"])
                                    .pick_file() {
                                    if let Ok(mut file) = fs::File::open(&path) {
                                        let mut contents = String::new();
                                        if file.read_to_string(&mut contents).is_ok() {
                                            if serde_yaml::from_str::<serde_yaml::Value>(&contents).is_ok() {
                                                let mut config_path = self.workspace_root.clone();
                                                config_path = config_path.join("tools.yaml");
                                                if fs::write(&config_path, contents).is_ok() {
                                                    self.tools_restore_success = true;
                                                    self.restore_status_message = format!("✅ Loaded configuration from: {}", path.display());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });

                        ui.add_space(6.0);

                        // Row 2: REMnux & Default
                        ui.horizontal(|ui| {
                            if ui.add_sized([button_width, 30.0], egui::Button::new("Load REMnux Tools"))
                                .on_hover_text("Load remnux_tools.yaml as your tools.yaml")
                                .clicked() {
                                let remnux_path = self.workspace_root.join("MalChelaGUI").join("remnux").join("remnux_tools.yaml");
                                if remnux_path.exists() {
                                    if let Ok(mut file) = fs::File::open(&remnux_path) {
                                        let mut contents = String::new();
                                        if file.read_to_string(&mut contents).is_ok() {
                                            if serde_yaml::from_str::<serde_yaml::Value>(&contents).is_ok() {
                                                let mut config_path = self.workspace_root.clone();
                                                config_path = config_path.join("tools.yaml");
                                                if fs::write(&config_path, contents).is_ok() {
                                                    self.tools_restore_success = true;
                                                    self.restore_status_message = format!("✅ Loaded configuration from: {}", remnux_path.display());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if ui.add_sized([button_width, 30.0], egui::Button::new("Load Default Tools"))
                                .on_hover_text("Load the default tools.yaml shipped with MalChela")
                                .clicked() {
                                let default_path = self.workspace_root.join("MalChelaGUI").join("remnux").join("default_tools.yaml");
                                if default_path.exists() {
                                    if let Ok(mut file) = fs::File::open(&default_path) {
                                        let mut contents = String::new();
                                        if file.read_to_string(&mut contents).is_ok() {
                                            if serde_yaml::from_str::<serde_yaml::Value>(&contents).is_ok() {
                                                let mut config_path = self.workspace_root.clone();
                                                config_path = config_path.join("tools.yaml");
                                                if fs::write(&config_path, contents).is_ok() {
                                                    self.tools_restore_success = true;
                                                    self.restore_status_message = format!("✅ Loaded configuration from: {}", default_path.display());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });

                        ui.add_space(6.0);

                        // Row 3: Edit in VS Code
                        if ui.add_sized([200.0, 30.0], egui::Button::new("Edit in VS Code")).clicked() {
                            let mut config_path = std::env::current_exe().unwrap();
                            while let Some(parent) = config_path.parent() {
                                if parent.join("Cargo.toml").exists() {
                                    config_path = parent.join("tools.yaml");
                                    break;
                                }
                                config_path = parent.to_path_buf();
                            }
                            #[cfg(target_os = "macos")]
                            let _ = std::process::Command::new("open").arg(&config_path).spawn();
                            #[cfg(target_os = "linux")]
                            let _ = std::process::Command::new("xdg-open").arg(&config_path).spawn();
                            #[cfg(target_os = "windows")]
                            let _ = std::process::Command::new("explorer").arg(&config_path).spawn();
                        }
                    });

                    // Simplified status message
                    if self.tools_restore_success && !self.restore_status_message.is_empty() {
                        ui.separator();
                        ui.colored_label(GREEN, format!("{} Please restart MalChela GUI for changes to take effect.", self.restore_status_message));
                    }
                    ui.separator();
                    // --- Close button (own row) ---
                    if ui.button("Close").clicked() {
                        should_close = true;
                    }
                });
            self.show_tools_modal = modal_open && !should_close;
        }

        use egui::widgets::Hyperlink;
        TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Developed by Baker Street Forensics")
                        .color(STONE_BEIGE)
                        .monospace(),
                );
                ui.add(Hyperlink::from_label_and_url(RichText::new("Blog").color(LIGHT_CYAN), "https://bakerstreetforensics.com")
                );
                ui.add(Hyperlink::from_label_and_url(RichText::new("Github").color(LIGHT_CYAN), "https://github.com/dwmetz")
                );
                ui.add(Hyperlink::from_label_and_url(RichText::new("Store").color(LIGHT_CYAN), "https://www.teepublic.com/user/baker-street-forensics")
            );
            });
        });

    }
}

fn load_tools_from_yaml() -> (Vec<ToolConfig>, String) {
    AppState::load_tools_from_yaml()
}

fn main() {
    let workspace_root = std::env::current_dir()
        .ok()
        .and_then(|mut path| {
            while path.parent().is_some() {
                if path.join("Cargo.toml").exists() {
                    return Some(path);
                }
                path.pop();
            }
            None
        })
        .expect("Could not locate workspace root");

    let icon = load_icon().map(std::sync::Arc::new);

    let (tools, edition) = load_tools_from_yaml();
    let categorized_tools = AppState::categorize_tools(&tools);
    // Initialize all categories as expanded (collapsed = false)
    let mut collapsed_categories = BTreeMap::new();
    for k in categorized_tools.keys() {
        collapsed_categories.insert(k.clone(), false);
    }
    let vol3_plugins_path = workspace_root.join("config/vol3_plugins.yaml");
    let vol3_plugins: BTreeMap<String, Vec<Vol3Plugin>> = std::fs::read_to_string(&vol3_plugins_path)
    .ok()
    .and_then(|contents| serde_yaml::from_str(&contents).ok())
    .unwrap_or_default();

    let app = AppState {
        update_status: None,
        fileminer_minimized: false,
        input_type: InputType::None,  
        current_panel: ActivePanel::None,
        fileminer_panel: FileMinerPanel::default(),
        malchela_logo: None,
        categorized_tools,
        selected_tool: None,
        input_path: None,
        case_name: None,   
        command_output: Arc::new(Mutex::new(String::new())),
        output_lines: Arc::new(Mutex::new(Vec::new())),
        show_scratchpad: false,
        scratchpad_content: Arc::new(Mutex::new(String::new())),
        scratchpad_path: String::new(),
        string_source_path: String::new(),
        selected_format: ".txt".to_string(),
        banner_displayed: false,
        show_home: true,
        rule_name: String::new(),
        author_name: String::new(),
        zip_password: String::new(),
        show_config: false,
        vt_api_key: std::fs::read_to_string("vt-api.txt").unwrap_or_default().trim().to_string(),
        mb_api_key: std::fs::read_to_string("mb-api.txt").unwrap_or_default().trim().to_string(),
        hide_vt: true,
        hide_mb: true,
        save_report: (false, ".txt".to_string()),
        custom_args: String::new(),
        workspace_root,
        is_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        tshark_panel: TsharkPanel::default(),
        collapsed_categories,
        edition,
        show_tools_modal: false,
        tools_restore_success: false,
        restore_status_message: String::new(),
        vol3_panel: Vol3Panel::default(),
        vol3_plugins,
        current_progress: Arc::new(Mutex::new(0)),
        total_progress: Arc::new(Mutex::new(0)),
        selected_algorithms: Vec::new(),
        show_new_case_modal: false,
        workspace: WorkspacePanel::new(),
        case_sha256: None,
        case_modal: CaseModal::default(),
    };

    AppState::check_for_updates_in_thread(Arc::clone(&app.command_output), Arc::clone(&app.output_lines));
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1550.0, 900.0])
            .with_icon(icon.unwrap_or_else(|| std::sync::Arc::new(IconData { rgba: vec![0; 4], width: 1, height: 1 }))),
        ..Default::default()
    };

    // --- Set up FiraCode font definitions ---
    use egui::{FontDefinitions, FontData, FontFamily};
    let mut font_defs = FontDefinitions::default();
    font_defs.font_data.insert(
        "fira_code".to_owned(),
        FontData::from_static(include_bytes!("../assets/fonts/FiraCode-Regular.ttf")),
    );
    font_defs.families.entry(FontFamily::Proportional).or_default().insert(0, "fira_code".to_owned());
    font_defs.families.entry(FontFamily::Monospace).or_default().insert(0, "fira_code".to_owned());

    eframe::run_native(
        "MalChela",
        native_options,
        Box::new(|cc| {
            cc.egui_ctx.set_fonts(font_defs);
            Box::new(app)
        }),
    ).unwrap();
}


// Helper function to compute SHA256 of a file
fn compute_sha256<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Some(format!("{:x}", result))
}

// Helper to write the launch script for Vol3
fn write_launch_script(filename: &str, command: &str) {
    let script_body = format!(
        r#"#!/bin/bash
{}
echo
read -p "Press Enter to close...""#,
        command
    );
    let _ = std::fs::write(filename, script_body);
}