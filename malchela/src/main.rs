use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::env;
use std::path::PathBuf;
use std::fs;

use colored::*;
use dialoguer::Select;
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
    println!("        {}", "    https://bakerstreetforensics.com".yellow());
    println!();
    println!("        {}", "MalChela - YARA & Malware Analysis Toolkit".white());
    println!();
}

fn main() {
    print_banner();

    if let Err(err) = check_for_updates() {
        eprintln!("{}", format!("Error checking for updates: {}", err).red());
    }

    pause();

    loop {
        clear_screen();
        print_banner();

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

            let mut group_names: Vec<String> = groups
            .iter()
            .map(|(name, _)| match name.as_str() {
                "File Analysis" => format!("\u{26A0}  {}", name),
                "Hashing Tools" => format!("\u{2317}  {}", name),
                "YARA Tools" => format!("\u{2620}  {}", name),
                "Threat Intel" => format!("\u{2622}  {}", name),
                "Utilities" => format!("\u{2699}  {}", name),
                _ => name.to_string(),
            })
            .map(|s| format!("            {}", s.green()))
            .collect();

        group_names.push("    ⏻  Exit".to_string());

        let theme = NoPrefixTheme;

        let group_selection = Select::with_theme(&theme)
            .with_prompt("    Choose a category:")
            .items(&group_names)
            .default(0)
            .interact_opt()
            .unwrap();

        if let Some(group_index) = group_selection {
            if group_index == group_names.len() - 1 {
                println!("{}", "Exiting...".yellow());
                break;
            }

            let (group_name, tools): &(String, Vec<(String, Vec<String>)>) = &groups[group_index];

            loop {
                clear_screen();
                print_banner();

                let mut items: Vec<String> = tools
                    .iter()
                    .map(|(name, _)| format!("        {}", name))
                    .collect();

                items.push("        ← Back".to_string());

                let tool_selection = Select::with_theme(&theme)
                    .with_prompt(format!("    {}", group_name))
                    .items(&items)
                    .default(0)
                    .interact_opt()
                    .unwrap();

                if let Some(tool_index) = tool_selection {
                    if tool_index == items.len() - 1 {
                        break;
                    }

                    let (_name, command): &(String, Vec<String>) = &tools[tool_index];
                    println!("{}", format!("Launching: {}", command.join(" ")).cyan());

                    let _ = Command::new("cargo")
                        .args(command)
                        .spawn()
                        .unwrap()
                        .wait();

                    pause();
                } else {
                    break;
                }
            }
        } else {
            break;
        }
    }
}