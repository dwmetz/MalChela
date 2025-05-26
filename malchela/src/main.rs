use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::env;
use std::path::PathBuf;
use std::fs;

use colored::*;
use dialoguer::Select;
use rand::seq::SliceRandom;
use serde::Deserialize;

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
use theme::NoPrefixTheme;
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
    println!("        {}", "MalChela - YARA & Malware Analysis Toolkit".yellow());
    println!();
}

enum MenuAction {
    Launch(Vec<String>),
    Exit,
    None,
}

fn main() {
    print_banner();

    if let Err(err) = check_for_updates() {
        eprintln!("{}", format!("Error checking for updates: {}", err).red());
    }

    pause();

    let groups: Vec<(String, Vec<(String, Vec<String>)>)> = menu::grouped_menu()
        .into_iter()
        .map(|(group, items)| {
            (
                group.to_string(),
                items
                    .into_iter()
                    .map(|(label, args)| {
                        (label.to_string(), args.into_iter().map(|s| s.to_string()).collect())
                    })
                    .collect(),
            )
        })
        .collect();

    let mut menu_labels = vec![];
    let mut menu_actions = vec![];

    for (group, tools) in &groups {
        menu_labels.push(format!(
            "{}  {}",
            match group.as_str() {
                "File Analysis" => "⚠",
                "String Analysis" => "§",
                "Hashing Tools" => "⌗",
                "YARA Tools" => "☠",
                "Threat Intel" => "☢",
                "Utilities" => "⚙",
                _ => "•",
            },
            group
        ).green());
        menu_actions.push(MenuAction::None);

        for (label, command) in tools {
            menu_labels.push(format!("• {}", label).cyan());
            menu_actions.push(MenuAction::Launch(command.clone()));
        }
    }

    menu_labels.push("⏻  Exit".green());
    menu_actions.push(MenuAction::Exit);

    let theme = NoPrefixTheme;

    loop {
        clear_screen();
        print_banner();

        let selection = Select::with_theme(&theme)
            .with_prompt("    Choose a tool:")
            .items(&menu_labels)
            .default(0)
            .interact_opt()
            .unwrap();

        if let Some(index) = selection {
            match &menu_actions[index] {
                MenuAction::Launch(command) => {
                    println!("{}", format!("Launching: {}", command.join(" ")).cyan());
                    let _ = Command::new("cargo")
                        .args(command.iter())
                        .spawn()
                        .unwrap()
                        .wait();
                    pause();
                }
                MenuAction::Exit => {
                    println!("{}", "Exiting...".yellow());
                    break;
                }
                MenuAction::None => {}
            }
        } else {
            break;
        }
    }
}