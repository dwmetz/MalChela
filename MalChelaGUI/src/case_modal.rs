
use eframe::egui::{Context, Ui, Window, Grid, RichText, Align2, ScrollArea, Button, Color32, Vec2, TextEdit};
use std::sync::{Arc, Mutex};


pub struct CaseModal {
    pub visible: bool,
    pub search_query: String,
    pub search_results: Vec<std::path::PathBuf>,
    pub preview_path: Option<std::path::PathBuf>,
    pub new_case_visible: bool,
    pub new_case_name: String,
    pub new_case_input_type: String,
    pub new_case_input_path: Option<std::path::PathBuf>,
    pub selected_case_name: Arc<Mutex<Option<String>>>,

}

impl Default for CaseModal {
    fn default() -> Self {
        Self {
            visible: false,
            search_query: String::new(),
            search_results: vec![],
            preview_path: None,
            new_case_visible: false,
            new_case_name: String::new(),
            new_case_input_type: "file".to_string(),
            new_case_input_path: None,
            selected_case_name: Arc::new(Mutex::new(None)),

        }
    }
}

impl CaseModal {
    pub fn show(&mut self, ctx: &Context, app_state: &mut crate::AppState) {
        if !self.visible {
            return;
        }

        let visible_clone = self.visible;
        let preview_path_clone = self.preview_path.clone();
        let mut temp_is_open = visible_clone;
        let this = self as *mut Self;

        Window::new(
            RichText::new("📁 Case Management")
                .color(crate::RUST_ORANGE)
                .strong()
        )
            .title_bar(true)
            .title_alignment(eframe::egui::Align::LEFT)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .default_width(620.0)
            .default_height(540.0)
            .open(&mut temp_is_open)
            .show(ctx, {
                let app_state_ptr = app_state as *mut crate::AppState;
                move |ui| {
                    // SAFETY: We are in the same single-threaded context and we know `self` and `app_state` outlive this closure
                    let this = unsafe { &mut *this };
                    let app_state = unsafe { &mut *app_state_ptr };
                    this.render_contents(ui, app_state, ctx, preview_path_clone.clone());
                }
            });
        self.visible = temp_is_open;
    }

    fn render_contents(&mut self, ui: &mut Ui, app_state: &mut crate::AppState, ctx: &Context, preview_path: Option<std::path::PathBuf>) {
        // Removed redundant header row and separator.

        ui.horizontal_top(|ui| {
            // Left: Logo
            if let Some(texture) = &app_state.malchela_logo {
                let desired_size = Vec2::new(160.0, 160.0);
                ui.image((texture.id(), desired_size));
            }

            ui.add_space(12.0); // spacing between image and buttons

            // Right: Button stack
            ui.vertical(|ui| {

                ui.horizontal(|ui| {
                    ui.label("🔍 Search Cases");
                    ui.text_edit_singleline(&mut self.search_query);
                    if ui.button("Search").clicked() {
                        use std::fs;

                        self.search_results.clear();
                        let query_lower = self.search_query.to_lowercase();
                        let case_root = std::path::Path::new("saved_output/cases");

                        for entry in walkdir::WalkDir::new(case_root)
                            .into_iter()
                            .filter_map(Result::ok)
                        {
                            if entry.file_type().is_file() {
                                if let Ok(content) = fs::read_to_string(entry.path()) {
                                    if content.to_lowercase().contains(&query_lower) {
                                        self.search_results.push(entry.path().to_path_buf());
                                    }
                                }
                            }
                        }
                    }
                });

                if !self.search_results.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label("👀 Results");
                        ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
                            if ui.button("❌ Clear").clicked() {
                                self.search_results.clear();
                                self.search_query.clear();
                            }
                        });
                    });
                    ui.vertical(|ui| {
                        for result in &self.search_results {
                            ui.horizontal(|ui| {
                                if ui.add(
                                    Button::new(RichText::new("Preview").color(Color32::BLACK)).fill(crate::LIGHT_CYAN)
                                ).clicked() {
                                    self.preview_path = Some(result.clone());
                                }
                                if result.file_name().map(|f| f == "case.json").unwrap_or(false) {
                                    if ui.add(
                                        Button::new(RichText::new("Load").color(Color32::BLACK)).fill(crate::LIGHT_GREEN)
                                    ).clicked() {
                                        app_state.workspace.reset();
                                        app_state.load_existing_case(result);
                                        app_state.workspace.load_case_metadata(result.clone());
                                        app_state.workspace.is_visible = true;
                                        app_state.workspace.minimized = false;
                                        self.visible = false;
                                    }
                                }
                                let relative_path = result.strip_prefix("saved_output/cases").unwrap_or(result);
                                let components: Vec<_> = relative_path.components().collect();
                                let case_name = components.get(0).map(|c| c.as_os_str().to_string_lossy()).unwrap_or_default();
                                let folder_path = components.get(1..components.len().saturating_sub(1))
                                    .map(|comps| comps.iter().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"))
                                    .unwrap_or_default();
                                let file_name = result.file_name().unwrap_or_default().to_string_lossy();

                                let label_text = if folder_path.is_empty() {
                                    format!("{case_name} › {file_name}")
                                } else {
                                    format!("{case_name} › {folder_path}/{file_name}")
                                };

                                ui.label(RichText::new(label_text).color(crate::STONE_BEIGE));
                            });
                        }
                    });
                }

                ui.separator();

                Grid::new("case_modal_buttons").show(ui, |ui| {
                    ui.label(RichText::new("📄 New Case").color(crate::LIGHT_CYAN));
                    if ui.add(Button::new(RichText::new("Create").color(Color32::BLACK)).fill(crate::RUST_ORANGE)).clicked() {
                        self.new_case_visible = true;
                    }
                    ui.end_row();

                    ui.label(RichText::new("📁 Load Case").color(crate::LIGHT_CYAN));
                    if ui.add(Button::new(RichText::new("Load").color(Color32::BLACK)).fill(crate::RUST_ORANGE)).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Case JSON", &["json"])
                            .set_directory("saved_output/cases")
                            .pick_file()
                        {
                            app_state.workspace.reset();
                            app_state.load_existing_case(&path);
                            app_state.workspace.load_case_metadata(path.clone());
                            app_state.workspace.is_visible = true;
                            app_state.workspace.minimized = false;
                            self.visible = false;
                        }
                    }
                    ui.end_row();

                    ui.label(RichText::new("📦 Archive Case").color(crate::LIGHT_CYAN));
                    static mut SHOW_ARCHIVE_MODAL: bool = false;
                    static mut ARCHIVE_IN_PROGRESS: bool = false;
                    // Use Arc<Mutex<String>> for status
                    // Declare it outside the unsafe so it's only created once per function call
                    let archive_status = Arc::new(Mutex::new(String::new()));

                    if ui.add(Button::new(RichText::new("Browse").color(Color32::BLACK)).fill(crate::RUST_ORANGE)).clicked() {
                        unsafe { SHOW_ARCHIVE_MODAL = true; }
                    }
                    ui.end_row();

                    unsafe {
                        if SHOW_ARCHIVE_MODAL {
                            // Use Arc<Mutex<String>> for status message
                            let archive_status_clone = archive_status.clone();
                            // SAFER: use addr_of_mut and cast to *mut bool, then use unsafe block to get mutable ref
                            let modal_open_ptr = std::ptr::addr_of_mut!(SHOW_ARCHIVE_MODAL) as *mut bool;
                            Window::new(RichText::new("📦 Archive a Case").color(crate::RUST_ORANGE))
                                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                                .collapsible(false)
                                .title_bar(true)
                                .resizable(false)
                                .default_width(420.0)
                                .open(&mut *modal_open_ptr)
                                .show(ctx, |ui| {
                                    // Title bar already has close button; remove redundant close button.
                                    ui.separator();

                                    let selected_case_name = self.selected_case_name.clone();
                                    if let Ok(entries) = std::fs::read_dir("saved_output/cases") {
                                        for entry in entries.flatten() {
                                            if entry.path().is_dir() {
                                                if let Some(name) = entry.file_name().to_str() {
                                                    let is_selected = selected_case_name.lock().unwrap().as_deref() == Some(name);
                                                    if ui.radio(is_selected, name).clicked() {
                                                        *selected_case_name.lock().unwrap() = Some(name.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    ui.separator();

                                    ui.horizontal(|ui| {
                                        if ui.button("Archive").clicked() {
                                            // Set archive-in-progress flag
                                            ARCHIVE_IN_PROGRESS = true;
                                            // Immediately update GUI status for feedback (on main thread)
                                            {
                                                let mut status = archive_status_clone.lock().unwrap();
                                                *status = "⏳ Preparing to archive...".to_string();
                                                ctx.request_repaint();
                                            }
                                            let ctx = ctx.clone();
                                            let archive_status_clone = archive_status_clone.clone();
                                            // Move archive logic into a background thread for responsiveness
                                            std::thread::spawn({
                                                let ctx = ctx.clone();
                                                let archive_status_clone = archive_status_clone.clone();
                                                let case_name = self.selected_case_name.lock().unwrap().clone();
                                                move || {
                                                    if let Some(case_name) = case_name.clone() {
                                                        use chrono::Local;
                                                        use std::path::Path;

                                                        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
                                                        let archive_name = format!("{}_{}.zip", case_name, timestamp);
                                                        let archive_path = Path::new("saved_output/archives").join(&archive_name);
                                                        let case_dir = Path::new("saved_output/cases").join(&case_name);

                                                        // Ensure the archive directory exists
                                                        if let Err(e) = std::fs::create_dir_all("saved_output/archives") {
                                                            println!("❌ Failed to create archive directory: {}", e);
                                                            {
                                                                let mut status = archive_status_clone.lock().unwrap();
                                                                *status = format!("❌ Failed to create archive directory: {}", e);
                                                                ctx.request_repaint();
                                                            }
                                                            ARCHIVE_IN_PROGRESS = false;
                                                            return;
                                                        }

                                                        {
                                                            let mut status = archive_status_clone.lock().unwrap();
                                                            *status = format!("📦 Archiving case: {}", case_name);
                                                            ctx.request_repaint();
                                                        }

                                                        match std::fs::File::create(&archive_path) {
                                                            Ok(file) => {
                                                                let mut zip = zip::ZipWriter::new(file);
                                                                let options: zip::write::FileOptions<'_, ()> =
                                                                    zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

                                                                for entry in walkdir::WalkDir::new(&case_dir).into_iter().filter_map(Result::ok) {
                                                                    let path = entry.path();
                                                                    if path.is_file() {
                                                                        // Update status for each file being archived
                                                                        {
                                                                            let mut status = archive_status_clone.lock().unwrap();
                                                                            *status = format!("📦 Archiving: {}", path.display());
                                                                            ctx.request_repaint();
                                                                        }
                                                                        if let Ok(mut f) = std::fs::File::open(path) {
                                                                            if let Ok(rel_path) = path.strip_prefix(&case_dir) {
                                                                                zip.start_file(rel_path.to_string_lossy(), options).expect("Failed to add file to zip");
                                                                                std::io::copy(&mut f, &mut zip).expect("Failed to write file contents");
                                                                            }
                                                                        }
                                                                    }
                                                                }

                                                                match zip.finish() {
                                                                    Ok(_) => {
                                                                        {
                                                                            let mut status = archive_status_clone.lock().unwrap();
                                                                            *status = format!("✅ Archived to {}", archive_path.display());
                                                                            ctx.request_repaint();
                                                                        }
                                                                        // Do not auto-close the archive modal; let user close manually
                                                                    }
                                                                    Err(e) => {
                                                                        println!("❌ Failed to finalize archive: {}", e);
                                                                        {
                                                                            let mut status = archive_status_clone.lock().unwrap();
                                                                            *status = format!("❌ Failed to finalize archive: {}", e);
                                                                            ctx.request_repaint();
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                println!("❌ Failed to create archive file: {}", e);
                                                                {
                                                                    let mut status = archive_status_clone.lock().unwrap();
                                                                    *status = format!("❌ Failed to create archive file: {}", e);
                                                                    ctx.request_repaint();
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        println!("⚠️ No case selected for archiving.");
                                                        {
                                                            let mut status = archive_status_clone.lock().unwrap();
                                                            *status = "⚠️ No case selected for archiving.".to_string();
                                                            ctx.request_repaint();
                                                        }
                                                    }
                                                    // Reset archive-in-progress flag when done (in all arms)
                                                    ARCHIVE_IN_PROGRESS = false;
                                                }
                                            });
                                        }
                                        // Remove/cancel button below, as close "X" is now at the top
                                        // if ui.button("Cancel").clicked() {
                                        //     SHOW_ARCHIVE_MODAL = false;
                                        // }
                                    });
                                    // Show status message only after Archive is clicked or while in progress,
                                    // and always show the latest archive_status
                                    {
                                        let working = ARCHIVE_IN_PROGRESS;
                                        if let Ok(status) = archive_status.lock() {
                                            if working || !status.is_empty() {
                                                ui.add_space(8.0);
                                                ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                                                    ui.label(RichText::new(status.clone()).color(crate::LIGHT_CYAN));
                                                });
                                            }
                                        }
                                    }
                                });
                        }
                    }

                    ui.label(RichText::new("🔄 Restore Case").color(crate::LIGHT_CYAN));
                    if ui.add(Button::new(RichText::new("Browse").color(Color32::BLACK)).fill(crate::RUST_ORANGE)).clicked() {
                        // restore logic
                    }
                    ui.end_row();
                });
            });
        });

        ui.separator();

        // My Cases
        use std::fs;

        ui.label(RichText::new("📂 My Cases").color(crate::RUST_ORANGE).size(16.0));

        let case_count = fs::read_dir("saved_output/cases")
            .map(|entries| entries.filter_map(Result::ok).filter(|e| e.path().is_dir()).count())
            .unwrap_or(0);

        let needs_scroll = case_count > 5;

        if needs_scroll {
            ScrollArea::vertical()
                .auto_shrink([false; 2])
                .max_height(160.0)
                .show(ui, |ui| {
                    self.render_case_list(ui, app_state);
                });
        } else {
            self.render_case_list(ui, app_state);
        }

        if let Some(path) = &preview_path {
            if let Ok(raw) = std::fs::read(path) {
                let contents = String::from_utf8_lossy(&raw)
                    .replace('\0', "␀"); // Replace null bytes with a visible placeholder or use "" to strip
                Window::new(format!("Preview: {}", path.display()))
                    .default_width(600.0)
                    .default_height(400.0)
                    .collapsible(false)
                    .resizable(true)
                    .show(ctx, |ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("📄 File Preview").color(crate::RUST_ORANGE));
                                ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
                                    if ui.button("❌").clicked() {
                                        self.preview_path = None;
                                    }
                                });
                            });
                            ui.separator();
                            ScrollArea::vertical()
                                .auto_shrink([false; 2])
                                .stick_to_bottom(true)
                                .show(ui, |ui| {
                                    ui.add(
                                        TextEdit::multiline(&mut contents.clone())
                                            .font(eframe::egui::TextStyle::Monospace)
                                            .desired_rows(20)
                                            .code_editor()
                                            .desired_width(f32::INFINITY),
                                    );
                                });
                        });
                    });
            }
        }

        // New Case Modal
        if self.new_case_visible {
            Window::new(RichText::new("Start New Case").color(crate::RUST_ORANGE))
                .default_width(500.0)
                .default_height(220.0)
                .resizable(false)
                .collapsible(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Case Name:");
                        ui.add_sized([250.0, 20.0], TextEdit::singleline(&mut self.new_case_name));

                        ui.label("Input Type:");
                        if ui.radio_value(&mut self.new_case_input_type, "file".to_string(), "File").clicked() {
                            self.new_case_input_path = None;
                        }
                        if ui.radio_value(&mut self.new_case_input_type, "folder".to_string(), "Folder").clicked() {
                            self.new_case_input_path = None;
                        }
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Browse File").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.new_case_input_path = Some(path);
                            }
                        }
                        if let Some(p) = &self.new_case_input_path {
                            let full_path = p.display().to_string();
                            let max_chars = 60;
                            let truncated = if full_path.len() > max_chars {
                                format!("...{}", &full_path[full_path.len() - max_chars..])
                            } else {
                                full_path
                            };
                            ui.label(format!("Selected: {}", truncated));
                        }
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Start Case").clicked() {
                            if let Some(path) = &self.new_case_input_path {
                                app_state.workspace.new_case(path.clone(), self.new_case_name.clone(), self.new_case_input_type.clone());
                                self.visible = false;
                                self.new_case_visible = false;
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.new_case_visible = false;
                        }
                    });
                });
        }
    }
}

use crate::AppState;

pub fn show_case_modal(ctx: &Context, app_state: &mut AppState) {
    let (case_modal_ptr, app_state_ptr): (*mut CaseModal, *mut AppState) = (
        &mut app_state.case_modal,
        app_state,
    );
    unsafe {
        (*case_modal_ptr).show(ctx, &mut *app_state_ptr);
    }
}


impl CaseModal {
    fn render_case_list(&mut self, ui: &mut Ui, app_state: &mut crate::AppState) {
        if let Ok(entries) = std::fs::read_dir("saved_output/cases") {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        ui.horizontal(|ui| {
                            ui.add_space(24.0);
                            if ui.link(RichText::new(name).color(crate::LIGHT_CYAN)).clicked() {
                                let case_path = std::path::Path::new("saved_output/cases").join(name);
                                let case_json = case_path.join("case.json");
                                app_state.load_existing_case(&case_json);
                                app_state.workspace.load_case_metadata(case_json);
                                app_state.workspace.is_visible = true;
                                app_state.workspace.minimized = false;
                                self.visible = false;
                            }
                        });
                    }
                }
            }
        }
    }
}