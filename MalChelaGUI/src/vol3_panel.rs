use serde::Deserialize;
use eframe::egui::{Ui, RichText, ComboBox, Color32};
use std::collections::BTreeMap;
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


        let mut all_plugins = Vec::new();
        for (_category, items) in plugins {
            for plugin in items {
                all_plugins.push((plugin.label.clone(), plugin.name.clone()));
            }
        }

        if all_plugins.is_empty() {
            ui.label(RichText::new("⚠️ No plugins found in vol3_plugins.yaml").color(Color32::YELLOW));
        }

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


        if self.use_custom {
            ui.horizontal(|ui| {
                ui.label("Custom Plugin:");
                ui.text_edit_singleline(&mut self.custom_plugin_name);
            });
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