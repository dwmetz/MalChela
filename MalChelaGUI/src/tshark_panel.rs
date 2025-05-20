use eframe::egui::{self, RichText};
use chrono::Local;

pub struct TsharkPanel {
    input_path: String,
    output: String,
    running: bool,
    show_file_dialog: bool,
    fields: Vec<String>,
    current_field: String,
    include_headers: bool,
    command_preview: String,
    display_filter: String,
    save_output: bool,
    display_output_type: String,
    compress_output: bool,
    show_reference_modal: bool,
    field_search: String,
}

impl Default for TsharkPanel {
    fn default() -> Self {
        Self {
            input_path: String::new(),
            output: String::new(),
            running: false,
            show_file_dialog: false,
            fields: vec![],
            current_field: String::new(),
            include_headers: false,
            command_preview: String::new(),
            display_filter: String::new(),
            save_output: false,
            display_output_type: "text".to_string(),
            compress_output: false,
            show_reference_modal: false,
            field_search: String::new(),
        }
    }
}

impl TsharkPanel {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Selected Tool: TShark (Input: file)").color(egui::Color32::from_rgb(0, 255, 255)).strong());

        if self.running {
            ui.label(RichText::new("🏃 Running...").color(egui::Color32::YELLOW));
        }

        ui.label(RichText::new(format!("🛠 Command line: tshark {}", self.command_preview)).color(egui::Color32::GREEN));

        ui.horizontal(|ui| {
            ui.label("PCAP Path:");
            ui.text_edit_singleline(&mut self.input_path);
            if ui.button("Browse").clicked() {
                self.show_file_dialog = true;
            }
        });

        if self.show_file_dialog {
            if let Some(path) = rfd::FileDialog::new().add_filter("PCAP/PCAPNG", &["pcap", "pcapng"]).pick_file() {
                self.input_path = path.display().to_string();
            }
            self.show_file_dialog = false;
        }

        ui.horizontal(|ui| {
            ui.label("Display Filter (-Y):");
            ui.text_edit_singleline(&mut self.display_filter);
            if ui.button("?").clicked() {
                self.show_reference_modal = true;
            }
        });

        ui.horizontal(|ui| {
            ui.label("Display Output Format (-T):");
            ui.radio_value(&mut self.display_output_type, "text".to_string(), "Text");
            ui.radio_value(&mut self.display_output_type, "json".to_string(), "JSON");
            ui.radio_value(&mut self.display_output_type, "pdml".to_string(), "PDML");
            ui.radio_value(&mut self.display_output_type, "fields".to_string(), "Fields (with -e)");
        });

        ui.horizontal(|ui| {
            ui.label("Field:");
            ui.text_edit_singleline(&mut self.current_field);
            if ui.button("Add Field").clicked() && !self.current_field.is_empty() {
                if !self.fields.contains(&self.current_field) {
                    self.fields.push(self.current_field.clone());
                }
                self.current_field.clear();
                self.display_output_type = "fields".to_string();
            }
        });

        ui.horizontal(|ui| {
        ui.label("Fields:");
        for (i, field) in self.fields.iter().enumerate() {
            ui.label(field);
            if ui.button("❌").clicked() {
                self.fields.remove(i);
                break;
            }
        }
    });

    ui.horizontal(|ui| {
        ui.checkbox(&mut self.include_headers, "Include Headers (-E header=y)");
        ui.checkbox(&mut self.save_output, "Save Decoded Output to File (-w)");
    });

        if self.save_output {
            ui.checkbox(&mut self.compress_output, "Compress Output as .gz");
        }

        if ui.button("Run").clicked() {
            use std::process::Command;
            use std::fs::{write, self};

            let save_path = format!(
                "saved_output/tshark/report_{}.{}",
                Local::now().format("%Y%m%d%H%M%S"),
                if self.compress_output { "gz" } else { "pcap" }
            );

            self.running = true;

            let mut args = vec!["-r", &self.input_path];

            if self.display_output_type == "fields" && !self.fields.is_empty() {
                args.push("-T");
                args.push("fields");
            } else if self.display_output_type != "text" {
                args.push("-T");
                args.push(&self.display_output_type);
            }

            for field in &self.fields {
                args.push("-e");
                args.push(field);
            }

            if self.include_headers {
                args.push("-E");
                args.push("header=y");
            }

            if !self.display_filter.is_empty() {
                args.push("-Y");
                args.push(&self.display_filter);
            }

            if self.save_output {
                args.push("-w");
                args.push(&save_path);
                args.push("-P");
            }

            self.command_preview = format!(
                "{}{}{}{}{}",
                if !self.display_filter.is_empty() {
                    format!("-r {} -Y {}", self.input_path, self.display_filter)
                } else {
                    format!("-r {}", self.input_path)
                },
                if self.display_output_type == "fields" && !self.fields.is_empty() {
                    format!(" -T fields{}", self.fields.iter().map(|f| format!(" -e {}", f)).collect::<String>())
                } else if self.display_output_type != "text" {
                    format!(" -T {}", self.display_output_type)
                } else {
                    "".to_string()
                },
                if self.include_headers { " -E header=y" } else { "" },
                if self.save_output { format!(" -w {} -P", save_path) } else { "".to_string() },
                "".to_string(),
            );

            // dbg!(&args);
            // println!("Command: tshark {}", self.command_preview);
            let debug_info = format!("Command: tshark {}\n", self.command_preview);
            let _ = write("/tmp/tshark_debug.txt", debug_info);

            let _ = fs::create_dir_all("saved_output/tshark");

            let output = Command::new("tshark")
                .args(&args)
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        self.output = String::from_utf8_lossy(&output.stdout).to_string();
                    } else {
                        self.output = String::from_utf8_lossy(&output.stderr).to_string();
                    }
                }
                Err(e) => {
                    self.output = format!("Failed to run tshark: {}", e);
                }
            }

            self.running = false;
        }

        if self.show_reference_modal {
            egui::Window::new(
                RichText::new("TShark Field Reference")
                    .color(egui::Color32::from_rgb(250, 109, 28)) // Rust orange
                    .strong(),
            )
            .collapsible(false)
            .resizable(true)
            .open(&mut self.show_reference_modal)
            .show(ui.ctx(), |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(RichText::new("Common Fields:").strong());
                    ui.separator();

                    ui.label("Search Fields:");
                    ui.text_edit_singleline(&mut self.field_search);
                    ui.separator();

                    let fields = vec![
                        ("ip.addr", "Any IP address (source or destination)"),
                        ("ip.src", "Source IP address"),
                        ("ip.dst", "Destination IP address"),
                        ("tcp.port", "Any TCP port"),
                        ("tcp.srcport", "TCP source port"),
                        ("tcp.dstport", "TCP destination port"),
                        ("udp.port", "Any UDP port"),
                        ("udp.srcport", "UDP source port"),
                        ("udp.dstport", "UDP destination port"),
                        ("tcp.flags", "TCP flags"),
                        ("tcp.flags.syn", "SYN flag"),
                        ("tcp.flags.ack", "ACK flag"),
                        ("tcp.flags == 0x2", "TCP SYN only (connection attempts)"),
                        ("http.request", "HTTP request"),
                        ("http.host", "HTTP host header"),
                        ("http.request.full_uri", "Full HTTP request URI"),
                        ("http.request.method", "HTTP request method"),
                        ("http.user_agent", "HTTP user agent string"),
                        ("http.file_data", "HTTP transferred file data"),
                        ("http contains", "HTTP traffic containing ASCII or hex"),
                        ("frame.contains", "Any frame that contains ASCII or hex pattern"),
                        ("ssl.handshake.type", "SSL handshake type"),
                        ("tls.handshake.type", "TLS handshake type"),
                        ("frame.number", "Frame (packet) number"),
                        ("eth.addr", "Ethernet address"),
                        ("eth.src", "Source MAC address"),
                        ("eth.dst", "Destination MAC address"),
                        ("dns.qry.name", "DNS query name"),
                        ("dns", "Any DNS traffic"),
                        ("!(ssdp or udp)", "Exclude noisy SSDP/UDP protocols"),
                    ];

                    for (field, desc) in fields.iter().filter(|(f, d)| {
                        self.field_search.is_empty()
                            || f.to_lowercase().contains(&self.field_search.to_lowercase())
                            || d.to_lowercase().contains(&self.field_search.to_lowercase())
                    }) {
                        ui.horizontal(|ui| {
                            if ui.add(egui::Label::new(RichText::new(*field).monospace())).on_hover_text(*desc).clicked() {
                                ui.output_mut(|o| o.copied_text = field.to_string());
                            }
                            if ui.button("📋").on_hover_text("Copy to clipboard").clicked() {
                                ui.output_mut(|o| o.copied_text = field.to_string());
                            }
                        });
                    }

                    ui.separator();
                    ui.label(RichText::new("💡 Tips for Writing Display Filters:").color(egui::Color32::from_rgb(250, 109, 28)).strong());

                    let tips = vec![
                        ("ip.addr == 192.168.1.1", "Any traffic to or from 192.168.1.1"),
                        ("http.request.method == \"GET\"", "Filters HTTP GET requests"),
                        ("ip.src == 10.0.0.1 && tcp.dstport == 443", "Source IP 10.0.0.1 to TCP port 443 (HTTPS)"),
                        ("(http.request or tls.handshake.type == 1) and !(ssdp)", "Show HTTP or TLS client hellos, excluding SSDP"),
                        ("http.request or dns.qry.name matches \"(hopto|ddns)\" or ssl.handshake.type == 1", "Find traffic related to dynamic DNS or encrypted C2"),
                        ("tcp.flags.syn == 1 and tcp.flags.ack == 0", "Initial TCP connection attempts (SYN without ACK)"),
                    ];

                    for (expr, tooltip) in tips {
                        ui.horizontal(|ui| {
                            if ui.add(egui::Label::new(RichText::new(expr).monospace())).on_hover_text(tooltip).clicked() {
                                ui.output_mut(|o| o.copied_text = expr.to_string());
                            }
                            if ui.button("📋").on_hover_text("Copy to clipboard").clicked() {
                                ui.output_mut(|o| o.copied_text = expr.to_string());
                            }
                        });
                    }
                });
            });
        }

        ui.separator();
        ui.label(RichText::new("Console Output").color(egui::Color32::from_rgb(0, 255, 255)).strong().size(20.0));
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.monospace(&self.output);
        });
    }
}