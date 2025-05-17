use serde::Deserialize;
use eframe::egui::{Ui, RichText, ComboBox, Color32};
use std::collections::{BTreeMap, HashMap};
use rfd::FileDialog;

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Vol3Arg {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Vol3Plugin {
    pub name: String,
    pub label: String,
    pub args: Vec<Vol3Arg>,
}

#[derive(Default)]
pub struct Vol3Panel {
    pub selected_plugin: Option<String>,
    pub custom_plugin_name: String,
    pub use_custom: bool,
    pub show_plugin_help: bool,
    pub plugin_search: String,
    pub arg_values: HashMap<String, String>,
}

impl Vol3Panel {
    pub fn ui(
        &mut self,
        ui: &mut Ui,
        plugins: &BTreeMap<String, Vec<Vol3Plugin>>,
        input_path: &mut String,
        custom_args: &mut String,
        save_report: &mut (bool, String),
    ) {
        ui.label(RichText::new("Selected Tool: Volatility 3 (Input: file)").color(Color32::from_rgb(0, 255, 255)).strong());
        let preview_cmd = format!(
            "vol3 -f {} {}",
            input_path.trim(),
            if self.use_custom {
                self.custom_plugin_name.as_str()
            } else {
                self.selected_plugin.as_deref().unwrap_or("<plugin>")
            }
        );
        ui.label(RichText::new(format!("🛠 Command line: {}", preview_cmd)).color(Color32::from_rgb(0, 255, 0)));
        ui.label(RichText::new("(Command will launch in a new terminal)").color(Color32::GRAY));


        let mut all_plugins = Vec::new();
        for (_category, items) in plugins {
            for plugin in items {
                all_plugins.push((plugin.label.clone(), plugin.name.clone()));
            }
        }

        if all_plugins.is_empty() {
            ui.label(RichText::new("⚠️ No plugins found in vol3_plugins.yaml").color(Color32::YELLOW));
        }

        // Plugin selector and help button in a horizontal layout
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
                        }
                    }
                    if ui.selectable_label(self.use_custom, "(other)").clicked() {
                        self.use_custom = true;
                    }
                });
            if ui.button("?").on_hover_text("View plugin reference").clicked() {
                self.show_plugin_help = true;
            }
        });

        // Plugin help modal using egui::Window for interactive modal behavior
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
                        ui.label(format!("• {} — {}", plugin.name, plugin.label));
                        if !plugin.args.is_empty() {
                            for arg in &plugin.args {
                                ui.label(format!("      {} ({})", arg.name, arg.arg_type));
                            }
                        }
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

        // Dynamically render input fields for plugin args if a plugin is selected and not using custom
        if !self.use_custom {
            if let Some(plugin_name) = &self.selected_plugin {
                for (_category, items) in plugins {
                    for plugin in items {
                        if &plugin.name == plugin_name {
                            for arg in &plugin.args {
                                match arg.arg_type.as_str() {
                                    "text" => {
                                        ui.horizontal(|ui| {
                                            ui.label(format!("{}:", arg.name));
                                            let val = self.arg_values.entry(arg.name.clone()).or_default();
                                            ui.text_edit_singleline(val);
                                            if !val.trim().is_empty() {
                                                custom_args.push(' ');
                                                custom_args.push_str(&format!("--{} {}", arg.name, val));
                                            }
                                        });
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        ui.horizontal(|ui| {
            ui.label("Memory Image (-f):");
            ui.text_edit_singleline(input_path);
            if ui.button("Browse").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    *input_path = path.display().to_string();
                }
            }
        });

        ui.horizontal(|ui| {
            ui.checkbox(&mut save_report.0, "Save Report");
            if save_report.0 {
                ui.label("Format:");
                ComboBox::from_id_source("vol3_save_format")
                    .selected_text(&save_report.1)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut save_report.1, ".txt".to_string(), "txt");
                        ui.selectable_value(&mut save_report.1, ".json".to_string(), "json");
                        ui.selectable_value(&mut save_report.1, ".md".to_string(), "md");
                    });
            }
        });

        *custom_args = if self.use_custom {
            self.custom_plugin_name.clone()
        } else {
            self.selected_plugin.clone().unwrap_or_default()
        };


        // Removed scroll area and output rendering; handled in main.rs.
    }
}