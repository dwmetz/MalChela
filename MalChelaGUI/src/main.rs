mod tshark_panel;
use tshark_panel::TsharkPanel;
mod vol3_panel;
use vol3_panel::{Vol3Panel, Vol3Plugin};
use eframe::{
    egui::{self, CentralPanel, Color32, Context, FontId, RichText, ScrollArea, SidePanel, TextEdit, TopBottomPanel, Visuals},
    App,
};
use egui::viewport::IconData;
fn load_icon(path: &std::path::Path) -> Option<IconData> {
    let image = image::open(path).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    let pixels = image.into_raw();
    Some(IconData { rgba: pixels, width, height })
}
use rfd::FileDialog;
use serde::Deserialize;
use rand::prelude::*;

#[derive(Debug, Deserialize)]
struct Koans {
    koans: Vec<String>,
}
 
use std::{
    collections::BTreeMap,
    fs::File,
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

struct AppState {
    categorized_tools: BTreeMap<String, Vec<ToolConfig>>,
    selected_tool: Option<ToolConfig>,
    input_path: String,
    command_output: Arc<Mutex<String>>,
    output_lines: Arc<Mutex<Vec<String>>>,
    show_scratchpad: bool,
    scratchpad_content: Arc<Mutex<String>>,
    scratchpad_path: String,
    string_source_path: String,
    selected_format: String,
    banner_displayed: bool,
    show_home: bool,
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
}

impl AppState {
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
            ctx.request_repaint();

            // Reset output state when running a new tool
            self.command_output.lock().unwrap().clear();
            self.output_lines.lock().unwrap().clear();
            self.is_running.store(false, std::sync::atomic::Ordering::Relaxed);

            // Reset arguments when running a new tool
            // self.custom_args.clear();  // <-- Removed per instructions
            // self.save_report = (false, ".txt".to_string()); // <-- Removed to preserve Save Report setting
            self.zip_password.clear();
            // self.scratchpad_path.clear(); // <-- Removed to allow rule file persistence across runs
            self.string_source_path.clear();
            self.selected_format = ".txt".to_string();

            // Special case for YARA-X (yr)
            if tool.command.get(0).map(|s| s == "yr").unwrap_or(false) {
                if self.scratchpad_path.is_empty() || self.input_path.is_empty() {
                    let mut out = self.command_output.lock().unwrap();
                    out.clear();
                    out.push_str("❌ Missing rule or target file.\n");
                    return;
                }
            }

            // Set environment variables for the tool (if needed)
            if tool.input_type == "folder" {
                std::env::set_var("MALCHELA_INPUT", &self.input_path);
            }

            std::env::remove_var("MZHASH_ALLOW_OVERWRITE");
            if self.custom_args.contains("MZHASH_ALLOW_OVERWRITE=1") {
                std::env::set_var("MZHASH_ALLOW_OVERWRITE", "1");
            }
            std::env::set_var("MALCHELA_GUI_MODE", "1");

            // Special case: Launch Vol3 in external terminal (outside of thread)
            let is_external = tool.exec_type.as_deref() != Some("cargo");
            let command = tool.command.clone();
            let input_path = self.input_path.clone();
            let custom_args = self.custom_args.clone();
            println!("Matched command path: {:?}", command.get(0));
            #[cfg(target_os = "macos")]
            if is_external && command.get(0).map(|s| s.contains("vol3")).unwrap_or(false) && !cfg!(windows) {
                let mut args = vec!["-f".to_string(), input_path.clone()];
                if !custom_args.trim().is_empty() {
                    args.push(custom_args.trim().to_string());
                }
                let joined_args = args.join(" ");
                // Use which::which to find the full path to vol3
                let vol3_path = which::which("vol3").unwrap_or_else(|_| std::path::PathBuf::from("vol3"));
                let full_cmd = format!("{} {}", vol3_path.display(), joined_args);

                {
                    let script_path = self.workspace_root.join("launch_vol3.command");
                    println!("📁 Writing Vol3 launch script to: {}", script_path.display());

                    match std::fs::write(
                        &script_path,
                        format!(
                            "#!/bin/bash\n{}\necho\necho Press Enter to close; read",
                            full_cmd
                        ),
                    ) {
                        Ok(_) => println!("✅ Script written successfully."),
                        Err(e) => println!("❌ Failed to write script: {}", e),
                    }

                    match std::process::Command::new("chmod").arg("+x").arg(&script_path).status() {
                        Ok(status) => println!("🔐 chmod status: {}", status),
                        Err(e) => println!("❌ chmod error: {}", e),
                    }

                    match std::process::Command::new("open").arg("-a").arg("Terminal").arg(&script_path).spawn() {
                        Ok(_) => println!("🚀 Terminal launch attempted."),
                        Err(e) => println!("❌ Failed to open Terminal: {}", e),
                    }
                }

                {
                    let mut out = self.command_output.lock().unwrap();
                    out.clear();
                    out.push_str("[green]🛠 Vol3 command launched in external terminal.\n");
                    let mut lines = self.output_lines.lock().unwrap();
                    lines.clear();
                    lines.push("🛠 Vol3 command launched in external terminal.".to_string());
                }
                self.is_running.store(false, std::sync::atomic::Ordering::Relaxed);
                return;
            }

            self.show_running_command(ctx);

            let command = tool.command.clone();
            let input_path = self.input_path.clone();
            let selected_format = self.selected_format.clone();
            let scratchpad_path = self.scratchpad_path.clone();
            let string_source_path = self.string_source_path.clone();
            let output = Arc::clone(&self.command_output);
            let gui_mode_args = tool.gui_mode_args.clone();
            let author_name = self.author_name.clone();
            let zip_password = self.zip_password.clone();
            let save_report = self.save_report.clone();
            let custom_args = self.custom_args.clone();
            let tool_optional_args = tool.optional_args.clone();
            let output_lines = Arc::clone(&self.output_lines);
            let is_external = tool.exec_type.as_deref() != Some("cargo");

            let workspace_root = self.workspace_root.clone();
            let is_running = Arc::clone(&self.is_running);
            let output = Arc::clone(&output);
            let output_lines = Arc::clone(&output_lines);
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
                        .and_then(|p| p.file_stem())
                        .and_then(|s| s.to_str())
                        .unwrap_or("python_tool");

                    let output_dir = workspace_root.join("saved_output").join(tool_output_name);
                    let _ = std::fs::create_dir_all(&output_dir);

                    // Build args for python: script first, then input_path, then others
                    let mut args: Vec<String> = Vec::new();
                    // Always treat optional_args[0] as the script, and input_path follows
                    if let Some(script) = tool_optional_args.get(0) {
                        args.push(script.clone());
                    }
                    args.push(input_path.clone());
                    // Add any additional gui_mode_args and custom_args after
                    args.extend(gui_mode_args);
                    if !custom_args.trim().is_empty() {
                        let parsed_custom_args = shell_words::split(&custom_args).unwrap_or_default();
                        args.extend(parsed_custom_args);
                    }
                    // Add any remaining optional_args (after [0])
                    if tool_optional_args.len() > 1 {
                        args.extend(tool_optional_args.iter().skip(1).cloned());
                    }

                    let mut command_builder = Command::new(&command[0]);
                    command_builder.args(&args);
                    command_builder.current_dir(&output_dir);

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
                            out.push_str(&format!("\nThe results have been saved to: {}\n", report_path.display()));
                        }
                        println!("Saved report to: {}", report_path.display());
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

                // Debug: Log binary check
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("vol3_command_debug.txt")
                {
                    let _ = writeln!(f, "Checking for binary: {:?}", &command[0]);
                }

                let binary_path = if is_external {
                    match which::which(&command[0]) {
                        Ok(path) => path,
                        Err(_) => {
                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("vol3_command_debug.txt")
                            {
                                let _ = writeln!(f, "Binary '{}' not found in PATH", command[0]);
                            }
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
                    args.push(input_path.clone());
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
                    base_args.insert(insert_idx, input_path.clone());
                } else if command[0] == "strings_to_yara" {
                    base_args.extend(vec![
                        input_path.clone(),
                        author_name.clone(),
                        selected_format.clone(),
                        scratchpad_path.clone(),
                        string_source_path.clone(),
                    ]);
                } else if !command.get(0).map(|s| s == "yr").unwrap_or(false) {
                    base_args.insert(0, input_path.clone());
                    if command.get(0).map(|s| s == "combine_yara").unwrap_or(false) {
                        // Only path
                    }
                    if command.get(0).map(|s| s == "extract_samples").unwrap_or(false) {
                        base_args.push(zip_password.clone());
                    }
                }
                args.extend(base_args);
                // End "first"/"last" logic

                args.extend(gui_mode_args);
                // Consistent Save Report CLI argument logic for all tools:
                if save_report.0 {
                    args.push("-o".to_string());
                    match save_report.1.as_str() {
                        ".txt" => args.push("-t".to_string()),
                        ".json" => args.push("-j".to_string()),
                        ".md" => args.push("-m".to_string()),
                        _ => {}
                    }
                }
                args.extend(tool_optional_args);
                if command.get(0).map(|s| s == "mzcount").unwrap_or(false) {
                    for (key, value) in &env_vars {
                        if key == "MZCOUNT_TABLE_DISPLAY" {
                            args.push(format!("{}={}", key, value));
                        }
                    }
                }
                if command.get(0).map(|s| s != "yr").unwrap_or(true) {
                    args.extend(parsed_custom_args);
                }

                // Write vol3_command_debug.txt after args are finalized
                let _ = std::fs::write(
                    "vol3_command_debug.txt",
                    format!(
                        "Binary path: {}\nArgs: {:?}\n",
                        binary_path.display(),
                        args
                    ),
                );

                if save_report.0 {
                    std::env::set_var("MALCHELA_SAVE_OUTPUT", "1");
                } else {
                    std::env::remove_var("MALCHELA_SAVE_OUTPUT");
                }

                println!("Attempting to run binary at path: {}", binary_path.display());
                println!("With arguments: {:?}", args);

                let mut command_builder = {
                    let mut cmd = Command::new(&binary_path);
                    cmd.args(&args);
                    cmd
                };
                command_builder.current_dir(&workspace_root);
                command_builder.stdout(Stdio::piped());
                command_builder.stderr(Stdio::piped());

                match command_builder.spawn() {
                    Ok(mut child) => {
                        // For terminal-driven Vol3, log after spawn as well
                        if is_external && command.get(0).map(|s| s == "vol3").unwrap_or(false) && !cfg!(windows) {
                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("vol3_command_debug.txt")
                            {
                                let _ = writeln!(f, "Terminal-launched Vol3 command initiated successfully.");
                            }
                        } else {
                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("vol3_command_debug.txt")
                            {
                                let _ = writeln!(f, "Command spawned successfully: {:?}", child.id());
                            }
                        }

                        if let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) {
                            let stderr_reader = BufReader::new(stderr);

                            let out_clone_stdout = Arc::clone(&output);
                            let output_lines_clone_stdout = Arc::clone(&output_lines);
                            let save_report = save_report.clone();
                            let workspace_root = workspace_root.clone();
                            let command = command.clone();
                            let is_running_clone = Arc::clone(&is_running);
                            // 🖼️ No ctx_clone here
                            thread::spawn(move || {
                                use std::io::{BufRead, BufReader};
                                let stdout = stdout; // take ownership here for the thread
                                let mut reader = BufReader::new(stdout);
                                let mut buffer = String::new();
                                loop {
                                    match reader.read_line(&mut buffer) {
                                        Ok(0) => break, // EOF
                                        Ok(_) => {
                                            {
                                                let mut lines = output_lines_clone_stdout.lock().unwrap();
                                                lines.push(buffer.trim_end().to_string());
                                            }
                                            {
                                                let mut out = out_clone_stdout.lock().unwrap();
                                                out.push_str(&buffer);
                                            }
                                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                                .create(true)
                                                .append(true)
                                                .open("vol3_command_debug.txt")
                                            {
                                                let _ = writeln!(f, "stdout: {}", buffer.trim_end());
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
                                        out.push_str(&format!("\nThe results have been saved to: {}\n", report_path.display()));
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
                                        lines.push(format!("[red]{}", line));
                                    }
                                    {
                                        let mut out = out_clone_stderr.lock().unwrap();
                                        out.push_str("[red]");
                                        out.push_str(&line);
                                        out.push('\n');
                                    }
                                }
                            });
                        }

                        let _ = child.wait();
                    }
                    Err(e) => {
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("vol3_command_debug.txt")
                        {
                            let _ = writeln!(f, "Command spawn failed: {}", e);
                        }

                        let mut out = output.lock().unwrap();
                        out.push_str(&format!("[red]Command spawn failed: {}\n", e));
                        return;
                    }
                }

                if command.get(0).map(|s| s == "fileanalyzer").unwrap_or(false) {
                    let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
                    if let Ok(contents) = std::fs::read_to_string(temp_path) {
                        let mut out = output.lock().unwrap();
                        let mut lines = output_lines.lock().unwrap();
                        out.clear();
                        lines.clear();
                        fn parse_and_push_line(line: &str, out: &mut String) {
                            let line = line.replace("[reset]", "")
                                           .replace("[bold]", "")
                                           .replace("[green]", "")
                                           .replace("[yellow]", "")
                                           .replace("[cyan]", "")
                                           .replace("[gray]", "");
                            if line.starts_with("[CRAB]") {
                                out.push_str("[CRAB]");
                                out.push_str(line.trim_start_matches("[CRAB]"));
                                out.push('\n');
                            } else if line.starts_with("[URL]") {
                                out.push_str("[URL]");
                                out.push_str(line.trim_start_matches("[URL]"));
                                out.push('\n');
                            } else if line.starts_with("[STATUS]") {
                                out.push_str("[STATUS]");
                                out.push_str(line.trim_start_matches("[STATUS]"));
                                out.push('\n');
                            } else if line.starts_with("[KOAN_COLOR]") {
                                out.push_str("[KOAN_COLOR]");
                                out.push_str(line.trim_start_matches("[KOAN_COLOR]"));
                                out.push('\n');
                            } else if line.starts_with("[ABOUT]") {
                                out.push_str("[ABOUT]");
                                out.push_str(line.trim_start_matches("[ABOUT]"));
                                out.push('\n');
                            } else if line.starts_with("[FEATURES]") {
                                out.push_str("[FEATURES]");
                                out.push_str(line.trim_start_matches("[FEATURES]"));
                                out.push('\n');
                            } else if line.starts_with("[NOTE]") {
                                out.push_str("[NOTE]");
                                out.push_str(line.trim_start_matches("[NOTE]"));
                                out.push('\n');
                            } else if line.starts_with("[rust]") {
                                out.push_str("[rust]");
                                out.push_str(line.trim_start_matches("[rust]"));
                                out.push('\n');
                            } else if line.starts_with("[green]") {
                                out.push_str("[green]");
                                out.push_str(line.trim_start_matches("[green]"));
                                out.push('\n');
                            } else if line.starts_with("[yellow]") {
                                out.push_str("[yellow]");
                                out.push_str(line.trim_start_matches("[yellow]"));
                                out.push('\n');
                            } else if line.starts_with("[white]") {
                                out.push_str("[white]");
                                out.push_str(line.trim_start_matches("[white]"));
                                out.push('\n');
                            } else if line.starts_with("[gray]") {
                                out.push_str("[gray]");
                                out.push_str(line.trim_start_matches("[gray]"));
                                out.push('\n');
                            } else if line.starts_with("[stone]") {
                                out.push_str("[stone]");
                                out.push_str(line.trim_start_matches("[stone]"));
                                out.push('\n');
                            } else {
                                out.push_str(&line);
                                out.push('\n');
                            }
                        }
                        for line in contents.lines() {
                            parse_and_push_line(line, &mut out);
                            lines.push(line.to_string());
                        }
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
            let selected_koan = std::fs::read_to_string("MalChelaGUI/koans/crabby_koans.yaml")
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

        TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let mut title = "MalChela v2.1.2 — YARA & Malware Analysis Toolkit".to_string();
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

        SidePanel::left("tool_panel")
            .resizable(false)
            .show(ctx, |ui| {
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
                                        self.selected_tool = Some(tool.clone());
                                        self.input_path.clear();
                                        self.custom_args.clear();
                                        self.show_home = false;
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
                        self.input_path.clear();
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

                    if ui.button(RichText::new("📖 User Guide").color(STONE_BEIGE)).on_hover_text("Open MalChela_User_Guide_v2.1.2.md").clicked() {
                        let mut guide_path = std::env::current_exe().unwrap();
                        while let Some(parent) = guide_path.parent() {
                            if parent.join("Cargo.toml").exists() {
                                guide_path = parent.join("docs/MalChela_User_Guide_v2.1.2.md");
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
                    }

                    if ui.button(RichText::new("📁 View Reports").color(STONE_BEIGE)).on_hover_text("Open saved_output folder").clicked() {
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

        CentralPanel::default().show(ctx, |ui| {
            if self.is_running.load(std::sync::atomic::Ordering::Relaxed) {
                ui.label(egui::RichText::new("🏃  Running...").color(YELLOW).strong());
            }
            if let Some(tool) = &self.selected_tool {
                if tool.command.get(0).map(|s| s == "tshark").unwrap_or(false) {
                    self.tshark_panel.ui(ui);
                    return;
                } else if tool.command.get(0).map(|s| s.contains("vol3")).unwrap_or(false) {
                    // Clear console output when selecting Vol3
                    self.command_output.lock().unwrap().clear();
                    self.output_lines.lock().unwrap().clear();

                    self.vol3_panel.ui(ui, &self.vol3_plugins, &mut self.input_path, &mut self.custom_args, &mut self.save_report);
                    // Removed: Save Report checkbox and format selection for Vol3.

                    if ui.button("Run").clicked() {
                        // Debug log for Vol3 Run button click
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("vol3_run_debug.log")
                        {
                            let _ = writeln!(f, "Run button clicked at: {}", chrono::Utc::now());
                        }
                        self.run_tool(ctx);
                    }
                    ui.label(RichText::new("(Vol3 command will launch in a separate terminal)").color(Color32::GRAY));

                    ui.separator();
                    ui.heading(RichText::new("Console Output").color(LIGHT_CYAN));
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            let output_lines = self.output_lines.lock().unwrap();
                            for line in output_lines.iter() {
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
                if !self.input_path.trim().is_empty() {
                    let mut status_line = String::from("🛠  Command line: ");
                    if let Some(exec_type) = tool.exec_type.as_deref() {
                        match exec_type {
                            "cargo" => {
                                status_line.push_str(&format!("cargo run -p {}", tool.command[0]));
                                if tool.input_type != "hash" {
                                    status_line.push_str(" -- ");
                                } else {
                                    status_line.push_str(" ");
                                }
                                status_line.push_str(&self.input_path);
                            }
                            "binary" | "script" => {
                                let script_display = tool.optional_args.get(0)
                                    .and_then(|s| std::path::Path::new(s).file_name())
                                    .and_then(|s| s.to_str());

                                if let Some(script_name) = script_display {
                                    status_line.push_str(&format!("{} {}", tool.command[0], script_name));
                                } else {
                                    status_line.push_str(&tool.command[0]);
                                }
                                status_line.push_str(" ");
                                status_line.push_str(&self.input_path);
                            }
                            _ => {}
                        }
                    }
                    if self.save_report.0 {
                        status_line.push_str(" -o");
                    }
                    ui.label(RichText::new(status_line).color(GREEN).strong());
                }
                if tool.command.get(0).map(|s| s == "strings_to_yara").unwrap_or(false) {
                    ui.label(RichText::new("strings_to_yara Configuration").strong().color(LIGHT_CYAN));
                    ui.horizontal(|ui| {
                        ui.label("Rule Name*:");
                        ui.text_edit_singleline(&mut self.input_path);
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
                        ui.text_edit_singleline(&mut self.input_path);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_folder() {
                                self.input_path = path.display().to_string();
                            }
                        }
                        if !self.input_path.trim().is_empty() {
                            ui.label(RichText::new(format!("Selected: {}", self.input_path)).color(STONE_BEIGE));
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
                        ui.text_edit_singleline(&mut self.input_path);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.input_path = path.display().to_string();
                            }
                        }
                        if !self.input_path.trim().is_empty() {
                            ui.label(RichText::new(format!("Selected: {}", self.input_path)).color(STONE_BEIGE));
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
                } else {
                    if tool.command.get(0).map(|s| s == "combine_yara").unwrap_or(false) {
                        ui.label("Combines all .yar/.yara files in the given folder (recursively) into a single YARA file.");
                    }
                    if tool.command.get(0).map(|s| s == "hashit").unwrap_or(false) {
                        ui.label(RichText::new("Select a file to hash").strong().color(LIGHT_CYAN));
                    }
                    if tool.command.get(0).map(|s| s == "nsrlquery").unwrap_or(false) {
                        ui.label(RichText::new("Enter a hash to check against NSRL").strong().color(LIGHT_CYAN));
                    }

                    ui.horizontal(|ui| {
                        let label = match tool.input_type.as_str() {
                            "hash" => "Hash:",
                            "folder" => "Folder Path:",
                            _ => "File Path:",
                        };
                        ui.label(label);
                        ui.text_edit_singleline(&mut self.input_path);
                        if tool.input_type != "hash" {
                            if ui.button("Browse").clicked() {
                                let picked = if tool.input_type == "folder" {
                                    FileDialog::new().pick_folder()
                                } else {
                                    FileDialog::new().pick_file()
                                };
                                if let Some(path) = picked {
                                    self.input_path = path.display().to_string();
                                }
                            }
                            if !self.input_path.trim().is_empty() {
                                ui.label(RichText::new(format!("Selected: {}", self.input_path)).color(STONE_BEIGE));
                            }
                        }
                    });
                    if tool.exec_type.as_deref() == Some("script") || tool.exec_type.as_deref() == Some("binary") {
                        ui.horizontal(|ui| {
                            ui.label("Arguments:");
                            ui.text_edit_singleline(&mut self.custom_args);
                        });
                    }

                    if let Some(tool_name) = tool.command.get(0) {
                        if tool_name == "mzmd5" || tool_name == "xmzmd5" {
                            let overwrite_var = "MZHASH_ALLOW_OVERWRITE=1";

                            ui.horizontal(|ui| {
                                ui.label("Note:");
                                ui.label("Output file already exists? Check 'Allow Overwrite' to replace it.");
                            });

                            let mut allow_overwrite = self.custom_args.contains(overwrite_var);
                            if ui.checkbox(&mut allow_overwrite, "Allow Overwrite")
                                .on_hover_text("Set environment variable to permit overwriting existing report.")
                                .changed()
                            {
                                self.custom_args = self
                                    .custom_args
                                    .split_whitespace()
                                    .filter(|arg| !arg.starts_with("MZHASH_ALLOW_OVERWRITE"))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                if allow_overwrite {
                                    if self.custom_args.trim().is_empty() {
                                        self.custom_args = overwrite_var.to_string();
                                    } else {
                                        self.custom_args.push_str(&format!(" {}", overwrite_var));
                                    }
                                }
                            }
                        }
                    }

                    if let Some(tool_name) = tool.command.get(0) {
                        let skip_report_tools = ["strings_to_yara", "combine_yara", "extract_samples", "mzcount", "mzmd5", "xmzmd5"];
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
                ui.add(Hyperlink::from_label_and_url("Website", "https://bakerstreetforensics.com"));
                ui.add(Hyperlink::from_label_and_url("Github", "https://github.com/dwmetz"));
                ui.add(Hyperlink::from_label_and_url("Store", "https://www.teepublic.com/user/baker-street-forensics"));
            });
        });

    }
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

    let icon_path = std::path::Path::new("images/icon.png");
    let icon = load_icon(&icon_path).map(std::sync::Arc::new);

    let (tools, edition) = AppState::load_tools_from_yaml();
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
        categorized_tools,
        selected_tool: None,
        input_path: String::new(),
        command_output: Arc::new(Mutex::new(String::new())),
        output_lines: Arc::new(Mutex::new(Vec::new())),
        show_scratchpad: false,
        scratchpad_content: Arc::new(Mutex::new(String::new())),
        scratchpad_path: String::new(),
        string_source_path: String::new(),
        selected_format: ".txt".to_string(),
        banner_displayed: false,
        show_home: true,
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
    };

    AppState::check_for_updates_in_thread(Arc::clone(&app.command_output), Arc::clone(&app.output_lines));
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1250.0, 850.0])
            .with_icon(icon.unwrap_or_else(|| std::sync::Arc::new(IconData { rgba: vec![0; 4], width: 1, height: 1 }))),
        ..Default::default()
    };
    eframe::run_native("MalChela", native_options, Box::new(|_cc| Box::new(app))).unwrap();
}
