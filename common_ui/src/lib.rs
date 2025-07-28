use egui::Color32;

// Color constants for GUI mode use
pub const OXIDE_ORANGE: Color32 = Color32::from_rgb(200, 100, 50);
pub const STONE_BEIGE: Color32 = Color32::from_rgb(210, 200, 190);
pub const CYAN: Color32 = Color32::from_rgb(100, 255, 255);


use colored::Colorize;

pub fn styled_line(tag: &str, content: &str) -> String {
    let gui_mode = std::env::var("MALCHELA_GUI_MODE").is_ok();

    match (gui_mode, tag) {
        (true, "green") => format!("[green]{}", content),
        (true, "yellow") => format!("[yellow]{}", content),
        (true, "red") => format!("[red]{}", content),
        (true, "NOTE") => format!("[NOTE]{}", content),
        (true, "white") => format!("[white]{}", content),
        (true, "gray") => format!("[gray]{}", content),
        (true, "rust") => format!("[rust]{}", content),
        (true, "ABOUT") => format!("[ABOUT]{}", content),
        (true, "FEATURES") => format!("[FEATURES]{}", content),
        (true, "stone") => format!("[stone]{}", content),
        (true, "highlight") => format!("[highlight]{}", content),
        (false, "green") => content.green().bold().to_string(),
        (false, "yellow") => content.yellow().bold().to_string(),
        (false, "red") => content.red().bold().to_string(),
        (false, "NOTE") => content.truecolor(255, 120, 0).to_string(),
        (false, "white") => content.white().to_string(),
        (false, "gray") => content.truecolor(200, 200, 200).to_string(),
        (false, "rust") => content.truecolor(255, 140, 0).to_string(),
        (false, "ABOUT") => content.green().bold().to_string(),
        (false, "FEATURES") => content.green().bold().to_string(),
        (false, "stone") => content.truecolor(200, 200, 200).to_string(),
        (false, "highlight") => content.truecolor(180, 255, 180).to_string(),
        _ => content.to_string(),
    }
}

pub fn parse_colored_output(input: &str) -> Vec<(String, Color32)> {
    let mut styled_lines = Vec::new();

    for line in input.lines() {
        let (color, content) = if let Some(stripped) = line.strip_prefix("[green]") {
            (Color32::from_rgb(0, 255, 0), stripped)
        } else if let Some(stripped) = line.strip_prefix("[yellow]") {
            (Color32::from_rgb(255, 255, 0), stripped)
        } else if let Some(stripped) = line.strip_prefix("[red]") {
            (Color32::from_rgb(255, 0, 0), stripped)
        } else if let Some(stripped) = line.strip_prefix("[stone]") {
            (STONE_BEIGE, stripped)
        } else if let Some(stripped) = line.strip_prefix("[gray]") {
            (Color32::GRAY, stripped)
        } else {
            (Color32::WHITE, line)
        };

        styled_lines.push((content.to_string(), color));
    }

    styled_lines
}