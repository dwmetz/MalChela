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
        _save_report: &mut (bool, String),
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
                        }
                    }
                    if ui.selectable_label(self.use_custom, "(other)").clicked() {
                        self.use_custom = true;
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
                                            }
                                        }
                                    } else if arg.arg_type == "folder" {
                                        ui.text_edit_singleline(val);
                                        if ui.button("Browse").clicked() {
                                            if let Some(path) = FileDialog::new().pick_folder() {
                                                *val = path.display().to_string();
                                            }
                                        }
                                    } else if arg.arg_type == "path_out" {
                                        ui.text_edit_singleline(val);
                                        if ui.button("Browse").clicked() {
                                            if let Some(path) = FileDialog::new().pick_folder() {
                                                *val = path.display().to_string();
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
                                            args.push(arg.name.clone());
                                        }
                                    } else if !val.trim().is_empty() {
                                        args.push(format!("{} \"{}\"", arg.name, val.trim()));
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

        ui.horizontal(|ui| {
            ui.label("Memory Image (-f):");
            ui.text_edit_singleline(input_path);
            if ui.button("Browse").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    *input_path = path.display().to_string();
                }
            }
        });




    }
}