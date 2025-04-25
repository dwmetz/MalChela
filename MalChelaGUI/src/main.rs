use eframe::{
    egui::{self, CentralPanel, Color32, Context, FontId, RichText, ScrollArea, SidePanel, TextEdit, TopBottomPanel, Visuals},
    App,
};
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
    io::{BufRead, BufReader, Write},
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
}

impl AppState {
    fn load_tools_from_yaml() -> Vec<ToolConfig> {
        let yaml = include_str!("../../tools.yaml");
        serde_yaml::from_str(yaml).expect("Failed to parse tools.yaml")
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
        categorized
    }

    fn run_tool(&mut self) {
        if let Some(tool) = &self.selected_tool {
            // Set MALCHELA_INPUT environment variable if needed (for folder input tools)
            if tool.input_type == "folder" {
                std::env::set_var("MALCHELA_INPUT", &self.input_path);
            }
            // Always remove the overwrite env var first, then set if requested
            std::env::remove_var("MZHASH_ALLOW_OVERWRITE");
            if self.custom_args.contains("MZHASH_ALLOW_OVERWRITE=1") {
                std::env::set_var("MZHASH_ALLOW_OVERWRITE", "1");
            }
            std::env::set_var("MALCHELA_GUI_MODE", "1");
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

            let is_external = tool.category == "External";
            thread::spawn(move || {
                // Ensure output directory is available and create it if needed
                if command.get(0).map(|s| s == "mstrings").unwrap_or(false) && save_report.0 {
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
                    let _ = std::fs::create_dir_all(workspace_root.join("saved_output").join("mstrings"));
                }
                // Find workspace root by searching for Cargo.toml upwards
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
                    command[0].clone()
                } else {
                    workspace_root
                        .join("target")
                        .join("debug")
                        .join(&binary_name)
                        .to_string_lossy()
                        .to_string()
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

                let mut args = Vec::new();
                if command[0] == "strings_to_yara" {
                    args.extend(vec![
                        input_path.clone(),
                        author_name.clone(),
                        selected_format.clone(),
                        scratchpad_path.clone(),
                        string_source_path.clone(),
                    ]);
                } else {
                    args.push(input_path.clone());
                    if command.get(0).map(|s| s == "combine_yara").unwrap_or(false) {
                        // Only path
                    }
                    if command.get(0).map(|s| s == "extract_samples").unwrap_or(false) {
                        args.push(zip_password.clone());
                    }
                }

                // Insert gui_mode_args and, for mstrings, --output if needed, then tool_optional_args
                args.extend(gui_mode_args);
                if command.get(0).map(|s| s == "mstrings").unwrap_or(false) && save_report.0 {
                    args.push("--output".to_string());
                }
                args.extend(tool_optional_args);

                // Only pass certain env var as CLI arg for mzcount, not for others
                if command.get(0).map(|s| s == "mzcount").unwrap_or(false) {
                    // Only pass MZCOUNT_TABLE_DISPLAY=... as CLI arg for mzcount
                    for (key, value) in &env_vars {
                        if key == "MZCOUNT_TABLE_DISPLAY" {
                            args.push(format!("{}={}", key, value));
                        }
                    }
                }
                // For all tools, pass non-env (non key=val) custom args as CLI args
                args.extend(parsed_custom_args);

                // Set MALCHELA_SAVE_OUTPUT only if requested
                if save_report.0 {
                    std::env::set_var("MALCHELA_SAVE_OUTPUT", "1");
                } else {
                    std::env::remove_var("MALCHELA_SAVE_OUTPUT");
                }

                let mut command_builder = Command::new(&binary_path);
                command_builder.args(&args);

                // Extract and apply custom env vars from custom_args string
                for env_var in custom_args.split_whitespace() {
                    if let Some((key, value)) = env_var.split_once('=') {
                        if key.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                            command_builder.env(key, value);
                        }
                    }
                }

                let mut child = command_builder
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("Failed to run built binary");

                if let Some(stdout) = child.stdout.take() {
                    let out_clone = Arc::clone(&output);
                    let output_lines_clone = Arc::clone(&output_lines);
                    thread::spawn(move || {
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

                if command.get(0).map(|s| s == "fileanalyzer").unwrap_or(false) {
                    let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
                    if let Ok(contents) = std::fs::read_to_string(temp_path) {
                        let mut out = output.lock().unwrap();
                        let mut lines = output_lines.lock().unwrap();
                        out.clear();
                        lines.clear();
                        fn parse_and_push_line(line: &str, out: &mut String) {
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
                                if line.starts_with("--- PE Header Details ---") {
                                    out.push_str("[rust]--- PE Header Details ---\n");
                                    return;
                                } else if line.starts_with("--- Heuristic Warnings ---") {
                                    out.push_str("[rust]--- Heuristic Warnings ---\n");
                                    return;
                                } else if line.starts_with("--- Heuristic Indicators ---") {
                                    out.push_str("[rust]--- Heuristic Indicators ---\n");
                                    return;
                                } else if line.trim_start().starts_with("PE Header parsed: ") {
                                    out.push_str("[white]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.starts_with("  Summary: ") {
                                    out.push_str("[stone]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Compile Time: ") {
                                    out.push_str("[highlight]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Sections:") || line.trim_start().starts_with("Sections:") {
                                    out.push_str("[stone]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.trim_start().starts_with("- ") && line.contains("(") && line.contains("bytes") && !line.contains("Imports") {
                                    // e.g. - .text (203740 bytes)
                                    out.push_str("[white]  ");
                                    out.push_str(line.trim_start_matches("- "));
                                    out.push('\n');
                                } else if line.trim_start().starts_with("Imports (") {
                                    out.push_str("[stone]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.trim_start().starts_with("- ") && !line.contains("(") && !line.contains("bytes") && !line.contains("Exports") {
                                    // e.g. - GetLastError
                                    out.push_str("[white]    ");
                                    out.push_str(line.trim_start_matches("- "));
                                    out.push('\n');
                                } else if line.trim_start().starts_with("Exports (") {
                                    out.push_str("[stone]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.starts_with("  Signed: ") || line.trim_start().starts_with("Signed: ") {
                                    out.push_str("[white]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.starts_with("File Type: ") ||
                                    line.starts_with("SHA-256 Hash: ") ||
                                    line.starts_with("File Size: ") ||
                                    line.starts_with("Last Modified: ") {
                                    out.push_str("[white]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.contains("YARA: ") && line.contains("match") {
                                    out.push_str("[yellow]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("- VirusTotal: ") {
                                    out.push_str("[rust]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("- Entropy: ") {
                                    out.push_str("[rust]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("- Packed: ") {
                                    out.push_str("[rust]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Section: ") {
                                    out.push_str("[stone]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("    Name: ") || line.starts_with("    Size: ") || line.starts_with("    Entropy: ") {
                                    out.push_str("[white]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Import: ") {
                                    out.push_str("[stone]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("    DLL: ") || line.starts_with("    Function: ") {
                                    out.push_str("[white]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else {
                                    out.push_str(line);
                                    out.push('\n');
                                }
                            }
                        }
                        for line in contents.lines() {
                            parse_and_push_line(line, &mut out);
                            lines.push(line.to_string());
                        }
                    }
                }

                // Save report if requested
                if save_report.0 {
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
                    let output_dir = workspace_root.join("saved_output").join(&command[0]);
                    let _ = std::fs::create_dir_all(&output_dir);
                    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
                    let report_path = output_dir.join(format!("report_{}{}", timestamp, save_report.1));
                    if let Ok(mut file) = File::create(&report_path) {
                        let final_output = output.lock().unwrap();
                        let _ = write!(file, "{}", final_output);
                    }
                    {
                        let mut out = output.lock().unwrap();
                        out.push_str(&format!("\nThe results have been saved to: {}\n", report_path.display()));
                    }
                }
            });

            let mut out = self.command_output.lock().unwrap();
            out.clear();
            let mut lines = self.output_lines.lock().unwrap();
            lines.clear();
        }
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
                ui.label(
                    RichText::new("MalChela v2.0 — YARA & Malware Analysis Toolkit")
                        .font(FontId::proportional(22.0))
                        .color(RUST_ORANGE),
                );
            });
        });

        SidePanel::left("tool_panel")
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading(RichText::new("Tools").color(RUST_ORANGE));
                for (category, tools) in &self.categorized_tools {
                    ui.vertical(|ui| {
                        let clean_category = category.trim_start_matches('~');
ui.label(RichText::new(clean_category).color(RUST_ORANGE));
                for tool in tools {
                    let tool_color = STONE_BEIGE;
                    if ui.button(RichText::new(&tool.name).color(tool_color)).clicked() {
                        self.selected_tool = Some(tool.clone());
                        self.input_path.clear(); 
                    }
                }
                    });
                }
                ui.separator();
                if ui.button(RichText::new("View Reports").color(STONE_BEIGE)).on_hover_text("Open saved_output folder").clicked() {
                    if let Ok(mut exe_path) = std::env::current_exe() {
                        while let Some(parent) = exe_path.parent() {
                            if parent.ends_with("MalChela") {
                                exe_path = parent.to_path_buf();
                                break;
                            }
                            exe_path = parent.to_path_buf();
                        }
                        let reports_path = exe_path.join("saved_output");
                        let _ = Command::new("open").arg(reports_path).spawn();
                    }
                }
                if ui.button(RichText::new("Scratchpad").color(STONE_BEIGE)).on_hover_text("Open in-app notepad").clicked() {
                    self.show_scratchpad = !self.show_scratchpad;
                }
                if ui.button(RichText::new("Configuration").color(STONE_BEIGE)).on_hover_text("Set API keys and options").clicked() {
                    self.show_config = true;
                }
                if ui.button(RichText::new("About").color(STONE_BEIGE)).on_hover_text("About MalChela and included tools").clicked() {
   
                    {
                        let mut out = self.command_output.lock().unwrap();
                        out.clear(); 
                    }
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


                        fn parse_and_push_line(line: &str, out: &mut String) {
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
                                if line.starts_with("--- PE Header Details ---") {
                                    out.push_str("[rust]--- PE Header Details ---\n");
                                    return;
                                } else if line.starts_with("--- Heuristic Warnings ---") {
                                    out.push_str("[rust]--- Heuristic Warnings ---\n");
                                    return;
                                } else if line.starts_with("--- Heuristic Indicators ---") {
                                    out.push_str("[rust]--- Heuristic Indicators ---\n");
                                    return;
                                } else if line.trim_start().starts_with("PE Header parsed: ") {
                                    out.push_str("[white]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.starts_with("  Summary: ") {
                                    out.push_str("[stone]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Compile Time: ") {
                                    out.push_str("[highlight]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Sections:") || line.trim_start().starts_with("Sections:") {
                                    out.push_str("[stone]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.trim_start().starts_with("- ") && line.contains("(") && line.contains("bytes") && !line.contains("Imports") {
                                    // e.g. - .text (203740 bytes)
                                    out.push_str("[white]  ");
                                    out.push_str(line.trim_start_matches("- "));
                                    out.push('\n');
                                } else if line.trim_start().starts_with("Imports (") {
                                    out.push_str("[stone]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.trim_start().starts_with("- ") && !line.contains("(") && !line.contains("bytes") && !line.contains("Exports") {
                                    // e.g. - GetLastError
                                    out.push_str("[white]    ");
                                    out.push_str(line.trim_start_matches("- "));
                                    out.push('\n');
                                } else if line.trim_start().starts_with("Exports (") {
                                    out.push_str("[stone]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.starts_with("  Signed: ") || line.trim_start().starts_with("Signed: ") {
                                    out.push_str("[white]");
                                    out.push_str(line.trim_start());
                                    out.push('\n');
                                } else if line.starts_with("File Type: ") ||
                                    line.starts_with("SHA-256 Hash: ") ||
                                    line.starts_with("File Size: ") ||
                                    line.starts_with("Last Modified: ") {
                                    out.push_str("[white]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.contains("YARA: ") && line.contains("match") {
                                    out.push_str("[yellow]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("- VirusTotal: ") {
                                    out.push_str("[rust]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("- Entropy: ") {
                                    out.push_str("[rust]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("- Packed: ") {
                                    out.push_str("[rust]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Section: ") {
                                    out.push_str("[stone]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("    Name: ") || line.starts_with("    Size: ") || line.starts_with("    Entropy: ") {
                                    out.push_str("[white]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("  Import: ") {
                                    out.push_str("[stone]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else if line.starts_with("    DLL: ") || line.starts_with("    Function: ") {
                                    out.push_str("[white]");
                                    out.push_str(line);
                                    out.push('\n');
                                } else {
                                    out.push_str(line);
                                    out.push('\n');
                                }
                            }
                        }

                        use std::io::Read;
                        if let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) {
                            let out_clone = Arc::clone(&output);
                            let output_lines = Arc::clone(&output_lines);
                            thread::spawn(move || {
                                let mut combined = String::new();
                                let mut buf = [0; 1024];

                                loop {
                                    let mut read_any = false;

                                    if let Ok(n) = stdout.read(&mut buf) {
                                        if n > 0 {
                                            combined.push_str(&String::from_utf8_lossy(&buf[..n]));
                                            read_any = true;
                                        }
                                    }

                                    if let Ok(n) = stderr.read(&mut buf) {
                                        if n > 0 {
                                            combined.push_str(&String::from_utf8_lossy(&buf[..n]));
                                            read_any = true;
                                        }
                                    }

                                    if !read_any {
                                        break;
                                    }
                                }

                                let mut out = out_clone.lock().unwrap();
                                for line in combined.lines() {
                                    parse_and_push_line(line, &mut out);
                                }
                                let mut lines = output_lines.lock().unwrap();
                                lines.clear();
                                for line in out.lines() {
                                    lines.push(line.to_string());
                                }
                            });
                        }

                        let _ = child.wait();
                    });
                }
                if ui.button(RichText::new("Home").color(STONE_BEIGE)).clicked() {
                    self.show_home = true;
                    self.banner_displayed = false;
                    self.selected_tool = None;
                    self.input_path.clear();
                }
            });

        CentralPanel::default().show(ctx, |ui| {
            if let Some(tool) = &self.selected_tool {
                ui.label(
                    RichText::new(format!(
                        "Selected Tool: {} (Input: {})",
                        tool.name, tool.input_type
                    ))
                    .color(LIGHT_CYAN)
                    .strong(),
                );
                if !self.input_path.trim().is_empty() {
                    let mut status_line = String::from("🛠️  Running: ");
                    if tool.category == "External" {
                        status_line.push_str(&tool.command.join(" "));
                    } else {
                        status_line.push_str(&format!("cargo run -p {}", tool.command[0]));
                    }
                    if tool.input_type != "hash" {
                        status_line.push_str(" -- ");
                        status_line.push_str(&self.input_path);
                    } else {
                        status_line.push_str(" ");
                        status_line.push_str(&self.input_path);
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
                    if tool.category == "External" {
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
                    self.run_tool();
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
                        } else if clean_line == "POTENTIAL FILESYSTEM IOC's" {
                            RichText::new(&line).monospace().color(RUST_ORANGE)
                        } else if clean_line == "POTENTIAL NETWORK IOC's" {
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
    let tools = AppState::load_tools_from_yaml();
    let categorized_tools = AppState::categorize_tools(&tools);
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
    };

    AppState::check_for_updates_in_thread(Arc::clone(&app.command_output), Arc::clone(&app.output_lines));
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native("MalChela", native_options, Box::new(|_cc| Box::new(app))).unwrap();
}
