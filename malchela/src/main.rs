use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::env;
use std::path::PathBuf;
use std::fs;

use colored::*;
use rand::seq::SliceRandom;
use serde::Deserialize;

use crate::menu::{generate_tool_menu};

#[derive(Debug, Deserialize)]
struct Koans {
    koans: Vec<String>,
}

fn load_random_koan() -> String {
    std::fs::read_to_string("MalChelaGUI/koans/crabby_koans.yaml")
        .ok()
        .and_then(|content| serde_yaml::from_str::<Koans>(&content).ok())
        .and_then(|k| k.koans.choose(&mut rand::thread_rng()).cloned())
        .unwrap_or_else(|| "🦀 No koan today.".to_string())
}

mod theme;
mod menu;

fn find_workspace_root() -> io::Result<PathBuf> {
    let exe_path = env::current_exe()?;
    let resolved_exe_path = fs::canonicalize(exe_path)?;

    if let Some(parent1) = resolved_exe_path.parent() {
        if let Some(parent2) = parent1.parent() {
            let workspace_root = parent2.to_path_buf();
            if workspace_root.exists() && workspace_root.is_dir() {
                return Ok(workspace_root);
            }
        }
    }
    eprintln!("{}", "Error: Workspace root not found.".red());
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Workspace root not found",
    ))
}

fn check_for_updates() -> io::Result<()> {
    let workspace_root = find_workspace_root()?;

    let update_output = Command::new("git")
        .arg("remote")
        .arg("update")
        .current_dir(&workspace_root)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()?;

    if !update_output.status.success() {
        io::stderr().write_all(&update_output.stderr)?;
        eprintln!("{}", "Error: Git remote update failed.".red());
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Git remote update failed",
        ));
    }

    let status_output = Command::new("git")
        .arg("status")
        .arg("-uno")
        .current_dir(&workspace_root)
        .output()?;

    let status_str = String::from_utf8_lossy(&status_output.stdout);

    if status_str.contains("branch is behind") {
        println!(
            "{}",
            "Update available. Please run `git pull` from the workspace root.".yellow()
        );
    } else {
        println!("{}", "MalChela is up to date!".green());
    }

    let koan = load_random_koan();
    println!();
    println!("{}", koan.truecolor(255, 121, 63));

    Ok(())
}

fn clear_screen() {
    if cfg!(target_os = "windows") {
        let _ = Command::new("cmd").arg("/C").arg("cls").status();
    } else {
        let _ = Command::new("clear").status();
    }
}

fn pause() {
    println!("\nPress Enter to continue...");
    let mut buffer = String::new();
    let _ = io::stdin().read_line(&mut buffer);
}

fn print_banner() {
    let crab_art = r#"
                ▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒                                
              ▒▒▒▒▒▒                ▒▒▒▒▒▒                              
              ▒▒▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒▒▒▒▒▒▒            ▒▒▒▒▒▒▒▒▒▒                            
            ▒▒▒▒      ██        ██      ▒▒▒▒                            
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
            ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                            
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
                ▒▒▒▒    ▒▒▒▒▒▒▒▒    ▒▒▒▒                                
    "#;
    println!("{}", crab_art.red());
    println!("        {}", "    https://bakerstreetforensics.com".truecolor(110, 130, 140));
    println!();
    println!("        {}", "     MalChela Analysis Toolkit v3.0".yellow());
    println!();
}

fn main() {
    print_banner();

    if let Err(err) = check_for_updates() {
        eprintln!("{}", format!("Error checking for updates: {}", err).red());
    }

    pause();

    let tool_menu = generate_tool_menu();

    loop {
        clear_screen();
        print_banner();

        println!("Available Tools:");
        let formatted_tools: Vec<String> = tool_menu
            .iter()
            .enumerate()
            .map(|(i, entry)| format!("[{}] {} ({})", i + 1, entry.display_name, entry.shortcode))
            .collect();

        let max_width = formatted_tools
            .iter()
            .take((formatted_tools.len() + 1) / 2)
            .map(|s| s.len())
            .max()
            .unwrap_or(0) + 4;

        let half = (formatted_tools.len() + 1) / 2;
        for i in 0..half {
            let left = &formatted_tools[i];
            let right = formatted_tools.get(i + half);
            match right {
                Some(r) => println!("{:<width$}{}", left, r, width = max_width),
                None => println!("{}", left),
            }
        }
        println!("\n[0] Exit");

        print!("\nSelect a tool by number or shortcode: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("{}", "Failed to read input.".red());
            continue;
        }

        let input = input.trim();

        if input == "0" || input.eq_ignore_ascii_case("exit") {
            println!("{}", "Exiting...".yellow());
            break;
        }

        let selected = if let Ok(num) = input.parse::<usize>() {
            if num == 0 || num > tool_menu.len() {
                None
            } else {
                Some(&tool_menu[num - 1])
            }
        } else {
            tool_menu.iter().find(|entry| entry.shortcode.eq_ignore_ascii_case(input))
        };

        if let Some(entry) = selected {
            println!("{}", format!("Launching: {}", entry.display_name).cyan());
            let child = Command::new("cargo")
                .args(&entry.command_args)
                .spawn();

            match child {
                Ok(mut child_proc) => {
                    let _ = child_proc.wait();
                }
                Err(e) => {
                    eprintln!("{}", format!("Failed to launch command: {}", e).red());
                }
            }
            pause();
        } else {
            println!("{}", "Invalid selection, please try again.".red());
            pause();
        }
    }
}