use dialoguer::theme::Theme;
use console::Style;
use std::fmt::{self, Write};

#[allow(dead_code)]
pub struct NoPrefixTheme;

impl Theme for NoPrefixTheme {
    fn format_prompt(&self, f: &mut dyn Write, prompt: &str) -> fmt::Result {
        write!(f, "{} ", prompt)
    }

    fn format_select_prompt(&self, f: &mut dyn Write, prompt: &str) -> fmt::Result {
        // Apply the indentation to the category and submenu headings
        write!(f, "    {}", prompt)
    }

    fn format_select_prompt_item(
        &self,
        f: &mut dyn Write,
        text: &str,
        active: bool,
    ) -> fmt::Result {
        let yellow = Style::new().yellow();
        let cyan = Style::new().cyan();
        let gray = Style::new().color256(245);
        let trimmed = text.trim();
    
        let styled_text = if trimmed == "← Back" {
            if active {
                yellow.apply_to(trimmed)
            } else {
                gray.apply_to(trimmed)
            }
        } else {
            if active {
                cyan.apply_to(trimmed) // leave group titles green from source
            } else {
                cyan.apply_to(trimmed)
            }
        };
    
        if active {
            write!(f, "          {} {}", yellow.apply_to("›"), styled_text)
        } else {
            write!(f, "            {}", styled_text)
        }
    }}