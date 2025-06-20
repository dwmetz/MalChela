use which::which;
use serde::Deserialize;
use eframe::egui::{Ui, RichText, ComboBox, Color32};
use std::collections::{BTreeMap, HashMap};
use rfd::FileDialog;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Vol3Arg {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Vol3Plugin {
    pub name: String,
    pub label: String,
    pub args: Vec<Vol3Arg>,
    pub description: Option<String>,
}
#[derive(Clone)]
pub struct Vol3Panel {
    pub selected_plugin: Option<String>,
    pub custom_plugin_name: String,
    pub use_custom: bool,
    pub show_plugin_help: bool,
    pub plugin_search: String,
    pub arg_values: HashMap<String, String>,
    pub save_to_case: bool,
    pub case_subfolder: String,
    pub memory_image_path: Option<String>,


    pub launch_command: Option<String>,
}

impl Default for Vol3Panel {
    fn default() -> Self {
        Self {
            selected_plugin: None,
            custom_plugin_name: String::new(),
            use_custom: false,
            show_plugin_help: false,
            plugin_search: String::new(),
            arg_values: HashMap::new(),
            save_to_case: false,
            case_subfolder: String::new(),
            memory_image_path: None,
            launch_command: None,
        }
    }
}

impl Vol3Panel {
    fn plugin_supports_output(plugin_name: &str) -> bool {
        matches!(
            plugin_name,
            "windows.dumpfiles"
                | "windows.memdump"
                | "windows.memmap"
                | "windows.ssdt"
                | "windows.dlldump"
                | "windows.moddump"
                | "windows.driverscan"
                | "linux.memdump"
                | "linux.dmesg"
        )
    }

    pub fn ui(
        &mut self,
        ui: &mut Ui,
        plugins: &BTreeMap<String, Vec<Vol3Plugin>>,
        input_path: &mut Option<std::path::PathBuf>,
        custom_args: &mut String,
        _save_report: &mut (bool, String),
    ) {
        ui.label(RichText::new("Selected Tool: Volatility 3 (Input: file)").color(Color32::from_rgb(0, 255, 255)).strong());
        // Build the Vol3 command preview in the correct order using helper:
        let dump_path = input_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        let plugin_name = if self.use_custom {
            self.custom_plugin_name.as_str()
        } else {
            self.selected_plugin.as_deref().unwrap_or("<plugin>")
        };
        let output_path = self.arg_values.iter()
            .find(|(k, _)| k.contains("output") || k.contains("dump") || k.contains("path"))
            .map(|(_, v)| v.as_str());
        let preview_cmd = self.build_command_string(&dump_path, plugin_name, custom_args, output_path);
        ui.label(RichText::new(format!("🛠 Command line: {}", preview_cmd)).color(Color32::from_rgb(0, 255, 0)));

        use std::path::PathBuf;
        ui.horizontal(|ui| {
            ui.label("Memory Image (-f):");
            let mut input_display = input_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            if ui.text_edit_singleline(&mut input_display).changed() {
                *input_path = Some(PathBuf::from(input_display.clone()));
            }
            if ui.button("Browse").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    *input_path = Some(path);
                    ui.ctx().request_repaint();
                }
            }
        });

        let mut all_plugins = Vec::new();
        for (_category, items) in plugins {
            for plugin in items {
                all_plugins.push((plugin.label.clone(), plugin.name.clone()));
            }
        }
        all_plugins.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        if all_plugins.is_empty() {
            ui.label(RichText::new("⚠️ No plugins found in vol3_plugins.yaml").color(Color32::YELLOW));
        }

        ui.horizontal(|ui| {
            ui.label("Plugin:");
            ComboBox::from_id_source("vol3_plugin_dropdown")
                .selected_text(
                    if self.use_custom {
                        "(other)".to_string()
                    } else {
                        self.selected_plugin.clone().unwrap_or_else(|| "Select plugin".to_string())
                    }
                )
                .show_ui(ui, |ui| {
                    for (label, name) in &all_plugins {
                        if ui.selectable_label(!self.use_custom && self.selected_plugin.as_deref() == Some(name), label).clicked() {
                            self.selected_plugin = Some(name.clone());
                            self.use_custom = false;
                            ui.ctx().request_repaint();
                        }
                    }
                    if ui.selectable_label(self.use_custom, "(other)").clicked() {
                        self.use_custom = true;
                        ui.ctx().request_repaint();
                    }
                });
            if ui.button("?").clicked() {
                self.show_plugin_help = true;
            }
        });

        if !self.use_custom {
            if let Some(selected_name) = &self.selected_plugin {
                for (_category, items) in plugins {
                    for plugin in items {
                        if &plugin.name == selected_name {
                            if let Some(desc) = &plugin.description {
                                ui.label(RichText::new(desc).color(Color32::GRAY));
                            }
                        }
                    }
                }
            }
        }

        if self.show_plugin_help {
            use eframe::egui::Window;
            Window::new(
                RichText::new("Volatility Plugin Reference")
                    .color(Color32::from_rgb(250, 109, 28))
                    .strong()
            )
            .title_bar(true)
            .collapsible(false)
            .resizable(true)
            .scroll2([true, true])
            .open(&mut self.show_plugin_help)
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.label("Search:");
                    ui.text_edit_singleline(&mut self.plugin_search);
                });
                ui.separator();
                for (_category, items) in plugins {
                    for plugin in items {
                        if !self.plugin_search.is_empty()
                            && !plugin.name.contains(&self.plugin_search)
                            && !plugin.label.contains(&self.plugin_search)
                        {
                            continue;
                        }
                        ui.label(RichText::new(plugin.name.clone()).strong());
                        ui.label(RichText::new(format!("  {}", plugin.label)).color(Color32::from_rgb(180, 180, 180)));
                        ui.add_space(4.0);
                        if !plugin.args.is_empty() {
                            for arg in &plugin.args {
                                ui.horizontal(|ui| {
                                    ui.label(&arg.name);
                                    ui.label(RichText::new(format!("({})", arg.arg_type)).color(Color32::GRAY));
                                });
                            }
                        }
                        ui.add_space(8.0);
                        ui.separator();
                    }
                }
            });
        }


        if self.use_custom {
            ui.horizontal(|ui| {
                ui.label("Custom Plugin:");
                ui.text_edit_singleline(&mut self.custom_plugin_name);
            });
        }

        if !self.use_custom {
            if let Some(plugin_name) = &self.selected_plugin {
                for (_category, items) in plugins {
                    for plugin in items {
                        if &plugin.name == plugin_name {
                            for arg in &plugin.args {
                                ui.horizontal(|ui| {
                                    ui.label(format!("{}:", arg.name));
                                    let val = self.arg_values.entry(arg.name.clone()).or_default();
                                    if arg.arg_type == "path" {
                                        ui.text_edit_singleline(val);
                                        if ui.button("Browse").clicked() {
                                            if let Some(path) = FileDialog::new().pick_file() {
                                                *val = path.display().to_string();
                                                ui.ctx().request_repaint();
                                            }
                                        }
                                    } else if arg.arg_type == "folder" {
                                        ui.text_edit_singleline(val);
                                        if ui.button("Browse").clicked() {
                                            if let Some(path) = FileDialog::new().pick_folder() {
                                                *val = path.display().to_string();
                                                ui.ctx().request_repaint();
                                            }
                                        }
                                    } else if arg.arg_type == "path_out" {
                                        if self.save_to_case {
                                            let fixed_path = format!("saved_output/cases/{}/vol3/{}", self.case_subfolder, plugin.name);
                                            *val = fixed_path.clone();
                                            let label = if plugin.name == "windows.memmap" {
                                                format!("--output-dir=\"{}\"", fixed_path)
                                            } else {
                                                format!("--dump-dir \"{}\"", fixed_path)
                                            };
                                            ui.label(RichText::new(label).color(Color32::GRAY));
                                        } else {
                                            ui.text_edit_singleline(val);
                                            if ui.button("Browse").clicked() {
                                                if let Some(path) = FileDialog::new().pick_folder() {
                                                    *val = path.display().to_string();
                                                    ui.ctx().request_repaint();
                                                }
                                            }
                                        }
                                    } else if arg.arg_type == "flag" {
                                        let checked = self.arg_values.entry(arg.name.clone()).or_insert("true".to_string());
                                        let mut is_checked = checked == "true";
                                        if ui.checkbox(&mut is_checked, "").changed() {
                                            *checked = is_checked.to_string();
                                        }
                                    } else {
                                        ui.text_edit_singleline(val);
                                    }
                                });
                            }
                            break; 
                        }
                    }
                }
            }
        }

        if !self.use_custom {
            if let Some(plugin_name) = &self.selected_plugin {
                for (_category, items) in plugins {
                    for plugin in items {
                        if &plugin.name == plugin_name {
                            let mut args = Vec::new();
                            // (no longer auto-enable save_report if plugin uses a path_out arg)
                            for arg in &plugin.args {
                                if let Some(val) = self.arg_values.get(&arg.name) {
                                    if arg.arg_type == "flag" {
                                        if val.trim() == "true" {
                                            // Ensure flag starts with exactly one "--"
                                            args.push(format!("--{}", arg.name.trim_start_matches('-')));
                                        }
                                    } else if !val.trim().is_empty() {
                                        if arg.arg_type == "path_out" {
                                            // Skip adding --output-dir/--dump-dir here to avoid duplication
                                            continue;
                                        } else {
                                            // Sanitize argument: ensure -- prefix, trim extra dashes, quote value
                                            args.push(format!("--{} \"{}\"", arg.name.trim_start_matches('-'), val.trim()));
                                        }
                                    }
                                }
                            }
                            *custom_args = args.join(" ");
                            break;
                        }
                    }
                }
            }
        }

        if let Some(selected_name) = &self.selected_plugin {
            if Vol3Panel::plugin_supports_output(selected_name) {
                ui.add_space(8.0);
                ui.separator();
                if ui.checkbox(&mut self.save_to_case, "📁 Save to Case").clicked() {
                    // optional callback logic
                }
                if self.save_to_case {
                    ui.horizontal(|ui| {
                        ui.label("Subfolder:");
                        ui.text_edit_singleline(&mut self.case_subfolder);
                    });
                }
            }
        }




    }
    pub fn get_selected_plugin(&self) -> String {
        self.selected_plugin.clone().unwrap_or_default()
    }

    pub fn get_memory_image_path(&self) -> Option<String> {
        self.memory_image_path.clone()
    }

    /// Build the command string for invoking a Volatility 3 plugin with given arguments.
    /// This logic ensures the output path is only injected if plugin_supports_output returns true.
    pub fn build_command_string(
        &self,
        mem_path: &str,
        plugin_name: &str,
        custom_args: &str,
        output_path: Option<&str>,
    ) -> String {
        let vol3_path = which("vol3").unwrap_or_else(|_| std::path::PathBuf::from("/Users/dmetz/.local/bin/vol3"));
        let mut full_command_str = format!("{} -f \"{}\"", vol3_path.display(), mem_path);

        let output_dir = if let Some(path) = output_path {
            Some(path.to_string())
        } else if self.save_to_case && !self.case_subfolder.is_empty() {
            Some(format!("saved_output/cases/{}/vol3/{}", self.case_subfolder, plugin_name))
        } else {
            None
        };

        use std::env;

        if let Some(output_dir) = output_dir {
            let output_flag = if plugin_name == "windows.memmap" {
                "--output-dir"
            } else if plugin_name.starts_with("windows.") || plugin_name.starts_with("linux.") {
                "--dump-dir"
            } else {
                "--output-file"
            };

            let abs_output_path = env::current_dir().unwrap().join(&output_dir);
            let abs_output_str = abs_output_path.to_string_lossy();
            full_command_str.push_str(&format!(" {} \"{}\"", output_flag, abs_output_str));
        }

        full_command_str.push_str(&format!(" {}", plugin_name));

        // Inject --dump for windows.memmap if not already present in custom_args
        if plugin_name == "windows.memmap" && !custom_args.contains("--dump") {
            full_command_str.push_str(" --dump");
        }

        if !custom_args.trim().is_empty() {
            full_command_str.push(' ');
            full_command_str.push_str(custom_args.trim());
        }
        full_command_str
    }

    /// Public wrapper for building Vol3 command string.
    pub fn build_vol3_command(
        &self,
        dump_path: &str,
        plugin_name: &str,
        custom_args: &str,
        output_path: Option<&str>,
    ) -> String {
        self.build_command_string(dump_path, plugin_name, custom_args, output_path)
    }

    /// Ensure the case output directory exists for Vol3, if applicable.
    pub fn ensure_vol3_case_output_dir(&self) {
        if let Some(plugin_name) = self.selected_plugin.as_ref() {
            if let Some(subfolder) = (!self.case_subfolder.is_empty()).then(|| self.case_subfolder.clone()) {
                let output_dir = format!("saved_output/cases/{}/vol3/{}", subfolder, plugin_name);
                let output_path = std::path::Path::new(&output_dir);
                if let Err(e) = std::fs::create_dir_all(output_path) {
                    eprintln!("⚠️ Failed to create Vol3 output directory: {}", e);
                }
            }
        }
    }
}