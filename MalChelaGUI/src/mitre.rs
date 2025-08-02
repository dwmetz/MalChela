use eframe::egui::{self, Color32, RichText, TextEdit, Ui};
use rfd::FileDialog;
use std::fs::write;
use std::process::Command;

#[derive(Default, Clone)]
pub struct MitreLookupModal {
    pub visible: bool,
    pub search_input: String,
    pub latest_result: Option<(String, String)>, // (query, result)
    pub full_mode: bool,
    pub save_to_case: bool,
    pub case_name: String,
    pub selected_ext: String,
    pub last_saved_path: Option<String>,
    pub save_display_timer: Option<std::time::Instant>,
}

impl MitreLookupModal {
    pub fn new() -> Self {
        Self {
            visible: false,
            search_input: String::new(),
            latest_result: None,
            full_mode: false,
            save_to_case: false,
            case_name: String::new(),
            selected_ext: ".txt".to_string(),
            last_saved_path: None,
            save_display_timer: None,
        }
    }

    fn convert_to_markdown(input: &str) -> String {
        let mut output = String::new();
        for line in input.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("T") && trimmed.contains(" - ") && !trimmed.starts_with("🔹 T") {
                // Title blue line (Color32::from_rgb(120, 180, 255))
                output.push_str("# ");
                output.push_str(line);
                output.push('\n');
            } else if let Some((head, rest)) = if trimmed.contains(": ") {
                trimmed.split_once(": ")
            } else if trimmed.ends_with(':') {
                Some((&trimmed[..trimmed.len() - 1], ""))
            } else {
                None
            } {
                if ["Tactic(s)", "Platforms", "Detection", "Description", "Mitigations", "Malware", "Intrusion Sets", "Tools"]
                    .iter().any(|h| head.trim() == *h) {
                    output.push_str("## ");
                    output.push_str(head.trim());
                    output.push_str(":\n");
                    output.push_str(rest.trim());
                    output.push('\n');
                } else if trimmed.starts_with("- ") && trimmed.contains(':') {
                    // Cyan labels (Color32::from_rgb(100, 255, 255))
                    if let Some((subhead, subrest)) = trimmed[2..].split_once(':') {
                        output.push_str("### - ");
                        output.push_str(subhead.trim());
                        output.push_str(":\n");
                        output.push_str(subrest.trim());
                        output.push('\n');
                    } else {
                        output.push_str("### ");
                        output.push_str(line);
                        output.push('\n');
                    }
                } else {
                    output.push_str(line);
                    output.push('\n');
                }
            } else if trimmed.starts_with("- ") && trimmed.contains(':') {
                if let Some((head, rest)) = trimmed[2..].split_once(':') {
                    output.push_str("### ");
                    output.push_str(head.trim());
                    output.push_str(":\n");
                    output.push_str(rest.trim());
                    output.push('\n');
                } else {
                    output.push_str("### ");
                    output.push_str(&trimmed[2..]);
                    output.push('\n');
                }
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }
        output
    }

    pub fn render_modal(&mut self, ui: &mut Ui) {
        ui.label(RichText::new("Enter Technique ID or Keyword:").strong().color(Color32::from_rgb(150, 255, 255)));
        ui.add(TextEdit::singleline(&mut self.search_input).hint_text("e.g., T1027.004"));

        ui.checkbox(&mut self.full_mode, "Full");

        let do_search = ui.button("Search").clicked()
            || ui.input(|i| i.key_pressed(egui::Key::Enter));

        if do_search {

            let mut args = Vec::new();
            if self.full_mode {
                args.push("--full");
            }
            args.push(&self.search_input);

            let (stdout, stderr) = match Command::new("target/release/MITRE_lookup")
                .args(&args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .and_then(|child| {
                    let output = child.wait_with_output()?;
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                    if !stderr.is_empty() {
                        eprintln!("⚠️ MITRE_lookup stderr:\n{}", stderr);
                    }

                    Ok((stdout, stderr))
                }) {
                Ok((out, err)) if !out.is_empty() || !err.is_empty() => (out, err),
                Ok(_) => (String::new(), format!("No output from MITRE_lookup for '{}'", self.search_input)),
                Err(e) => (String::new(), format!("⚠️ Error running MITRE_lookup: {}", e)),
            };

            let combined_result = if !stderr.is_empty() {
                format!("{}\n\n⚠️ stderr:\n{}", stdout, stderr)
            } else {
                stdout
            };

            self.latest_result = Some((self.search_input.clone(), combined_result));
        }

        ui.horizontal(|ui| {
            if ui.button("Clear Results").clicked() {
                self.latest_result = None;
                self.search_input.clear();
            }
        });

        ui.horizontal(|ui| {
            // Shared format toggle for both Save As and Save to Case
            let extensions = [".txt", ".md"];
            ui.horizontal(|ui| {
                ui.label(RichText::new("Format:").strong());
                for ext in &extensions {
                    ui.add_space(4.0);
                    let selected = self.selected_ext == *ext;
                    let label = RichText::new(*ext);
                    if ui.selectable_label(selected, label).clicked() {
                        self.selected_ext = ext.to_string();
                    }
                }
            });
            if ui.button("Save As...").clicked() {
                if let Some((query, result)) = &self.latest_result {
                    let default_filename = format!("mitre_lookup_{}{}", query.replace(|c: char| !c.is_alphanumeric(), "_"), self.selected_ext);
                    let path = FileDialog::new().set_file_name(&default_filename).save_file().map(|p| p.display().to_string());
                    if let Some(path) = path {
                        let content = if self.selected_ext == ".md" {
                            Self::convert_to_markdown(result)
                        } else {
                            result.clone()
                        };
                        if let Err(e) = write(&path, content) {
                            eprintln!("⚠️ Failed to save MITRE result: {}", e);
                        }
                    }
                }
            }
            ui.add_space(16.0);
            ui.checkbox(&mut self.save_to_case, "Save to Case");
            if self.save_to_case {
                ui.add_space(8.0);
                ui.add(TextEdit::singleline(&mut self.case_name).hint_text("Enter case name...").desired_width(140.0));
                if ui.button("Save").clicked() {
                    if let Some((query, result)) = &self.latest_result {
                        if !self.case_name.trim().is_empty() {
                            let path = format!(
                                "saved_output/cases/{}/mitre_lookup/mitre_lookup_{}{}",
                                self.case_name.trim(),
                                query.replace(|c: char| !c.is_alphanumeric(), "_"),
                                self.selected_ext.as_str()
                            );
                            if let Some(parent) = std::path::Path::new(&path).parent() {
                                if let Err(e) = std::fs::create_dir_all(parent) {
                                    eprintln!("⚠️ Failed to create directory {}: {}", parent.display(), e);
                                }
                            }
                            let content = if self.selected_ext == ".md" {
                                Self::convert_to_markdown(result)
                            } else {
                                result.clone()
                            };
                            if let Err(e) = write(&path, content) {
                                eprintln!("⚠️ Failed to save MITRE result: {}", e);
                            } else {
                                self.last_saved_path = Some(path.clone());
                                self.save_display_timer = Some(std::time::Instant::now());
                                std::thread::spawn({
                                    let last_saved_path = self.last_saved_path.clone();
                                    move || {
                                        std::thread::sleep(std::time::Duration::from_secs(4));
                                        if last_saved_path.is_some() {
                                            // Notify the main thread to clear the saved path
                                            // Note: egui doesn't allow direct thread-to-UI communication,
                                            // so this requires a workaround; instead, we'll add an expiry flag
                                            // managed inside the struct using a timer.
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
                if let Some(path) = &self.last_saved_path {
                    if let Some(start_time) = self.save_display_timer {
                        if start_time.elapsed().as_secs() < 4 {
                            ui.label(RichText::new(format!("✅ Saved to: {}", path)).color(Color32::LIGHT_GREEN));
                        } else {
                            self.last_saved_path = None;
                            self.save_display_timer = None;
                        }
                    }
                }
            }
        });

        if let Some((query, result)) = &self.latest_result {
            Self::render_entry(ui, query, result);
        }
    }

    fn render_entry(ui: &mut Ui, query: &str, result: &str) {
        ui.group(|ui| {
            let query_lower = query.to_lowercase();
            let highlight = |ui: &mut Ui, text: &str| {
                if !query_lower.is_empty() {
                    let mut job = egui::text::LayoutJob::default();
                    let mut last = 0;
                    let text_lower = text.to_lowercase();
                    while let Some(pos) = text_lower[last..].find(&query_lower) {
                        let start = last + pos;
                        let end = start + query_lower.len();
                        job.append(&text[last..start], 0.0, egui::TextFormat::default());
                        job.append(&text[start..end], 0.0, egui::TextFormat {
                            color: Color32::YELLOW,
                            ..Default::default()
                        });
                        last = end;
                    }
                    job.append(&text[last..], 0.0, egui::TextFormat::default());
                    ui.add(egui::Label::new(job));
                } else {
                    ui.label(egui::RichText::new(text).monospace());
                }
            };
            for line in result.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("Search") {
                    ui.label(RichText::new(trimmed).color(Color32::YELLOW));
                } else if trimmed.starts_with("T") && trimmed.contains(" - ") && !trimmed.starts_with("🔹 T") {
                    ui.label(RichText::new(trimmed).color(Color32::from_rgb(120, 180, 255)).strong());
                } else if trimmed.starts_with("- ") && trimmed.contains(':') {
                    if let Some((name, rest)) = trimmed[2..].split_once(':') {
                        ui.label(RichText::new(format!("- {}:", name.trim())).color(Color32::from_rgb(100, 255, 255)).strong());
                        if !rest.trim().is_empty() {
                            highlight(ui, rest.trim());
                        }
                    } else {
                        highlight(ui, trimmed);
                    }
                } else if trimmed.starts_with("🔹 T") {
                    ui.label(RichText::new(trimmed).color(Color32::from_rgb(120, 180, 255)).strong());
                } else if let Some((head, rest)) = if trimmed.contains(": ") {
                    trimmed.split_once(": ")
                } else if trimmed.ends_with(':') {
                    Some((&trimmed[..trimmed.len() - 1], ""))
                } else {
                    None
                } {
                    if ["Tactic(s)", "Platforms", "Detection", "Description", "Mitigations", "Malware", "Intrusion Sets", "Tools"]
                        .iter().any(|h| head.trim() == *h) {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(format!("{}:", head)).color(Color32::from_rgb(255, 180, 100)).strong());
                            highlight(ui, rest);
                        });
                    } else if trimmed.ends_with(':') && trimmed.len() < 50 {
                        ui.label(RichText::new(trimmed).color(Color32::from_rgb(100, 255, 255)).strong());
                    } else {
                        highlight(ui, trimmed);
                    }
                } else {
                    highlight(ui, trimmed);
                }
            }
        });
        ui.separator();
    }

    pub fn show_ui(&mut self, ctx: &egui::Context, is_open: &mut bool) {
        egui::Window::new("MITRE Technique Lookup")
            .open(is_open)
            .resizable(true)
            .vscroll(true)
            .collapsible(false)
            .default_width(600.0)
            .show(ctx, |ui| {
                self.render_modal(ui);
            });

        if !*is_open {
            self.visible = false;
        }
    }
}
