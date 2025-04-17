// src/theme.rs
use dialoguer::theme::Theme;
use console::{Style, Term};
use std::io;

pub struct NoPrefixTheme;

impl Theme for NoPrefixTheme {
    fn format_prompt(&self, f: &mut dyn io::Write, prompt: &str) -> io::Result<()> {
        write!(f, "{} ", prompt)
    }

    fn format_select_prompt(&self, f: &mut dyn io::Write, prompt: &str, _selection: Option<&str>) -> io::Result<()> {
        write!(f, "{} ", prompt)
    }

    fn format_select_prompt_selection(
        &self,
        f: &mut dyn io::Write,
        prompt: &str,
        sel: &str,
    ) -> io::Result<()> {
        write!(f, "{} {}", prompt, Style::new().yellow().apply_to(sel))
    }

    fn format_select_item(&self, f: &mut dyn io::Write, text: &str, active: bool) -> io::Result<()> {
        if active {
            write!(f, "  {} {}", Style::new().yellow().apply_to("›"), Style::new().yellow().apply_to(text))
        } else {
            write!(f, "    {}", text)
        }
    }

    fn format_select_item_checked(&self, f: &mut dyn io::Write, text: &str, active: bool) -> io::Result<()> {
        self.format_select_item(f, text, active)
    }

    fn format_select_item_unchecked(&self, f: &mut dyn io::Write, text: &str, active: bool) -> io::Result<()> {
        self.format_select_item(f, text, active)
    }
}