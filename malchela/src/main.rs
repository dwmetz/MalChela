use std::process::{Command, Stdio};
use std::io::{self, Write};
use colored::*;
use std::env;
use std::path::PathBuf;
use std::fs;

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
    eprintln!("{}", "Error: Workspace root not found.");
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Workspace root not found",
    ))
}


fn check_for_updates(crab_art: &str) -> io::Result<()> {
    let workspace_root = match find_workspace_root() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{}", format!("Error finding workspace root: {}", err).red());
            return Err(err);
        }
    };

    if let Err(err) = env::set_current_dir(&workspace_root) {
        eprintln!("{}", format!("Error changing directory: {}", err).red());
        return Err(err);
    }

    let update_output = Command::new("git")
        .arg("remote")
        .arg("update")
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
        .output()?;

    let status_str = String::from_utf8_lossy(&status_output.stdout);

    if status_str.contains("branch is behind") {
        println!("{}", crab_art);
        println!("{}", "Update available. Please run `git pull` from the workspace root.".yellow());
    } else {
        println!("{}", "Your branch is up to date.".green());
    }

    Ok(())
}

fn main() {
    let crab_art = format!(
        "{}",
        r#"
                                                                                    
                                                                                        
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

            https://bakerstreetforensics.com                                                                                                                                  
"#
        .red()
    );

    if let Err(err) = check_for_updates(&crab_art) {
        eprintln!("{}", format!("Error checking for updates: {}", err).red());
    }

    pause();

    clear_screen();

    let programs = vec![
        ("  Combine YARA".green(), "cargo run --bin combine_yara"),
        ("  Extract Samples".green(), "cargo run --bin extract_samples"),
        ("  Hash It".green(), "cargo run --bin hashit"),
        ("  MStrings".green(), "cargo run --bin mstrings"),
        ("  MZCount".green(), "cargo run --bin mzcount"),
        ("  MZMD5".green(), "cargo run --bin mzmd5"),
        ("  NSRL MD5 Lookup".green(), "cargo run --bin nsrlmd5"),
        ("  NSRL SHA1 Lookup".green(), "cargo run --bin nsrlsha1"),
        ("  Strings to YARA".green(), "cargo run --bin strings_to_yara"),
        (" Malware Hash Lookup".green(), "cargo run --bin vthash"),
        (" XMZMD5".green(), "cargo run --bin xmzmd5"),
        (" About".green(), "cargo run --bin about"),
    ];

    loop {
        println!("{}", crab_art);
        println!("{}", "MalChela - YARA & Malware Analysis Toolkit".yellow());

        println!("\nSelect a program to launch:");
        for (i, (name, _)) in programs.iter().enumerate() {
            println!("{}. {}", i + 1, name);
        }
        println!("{}. {}", programs.len() + 1, " Exit".bright_black());

        print!("\nEnter your choice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let choice: usize = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("{}", "Invalid input. Please enter a number.".red());
                continue;
            }
        };

        if choice == programs.len() + 1 {
            println!("{}", "Exiting...".yellow());
            break;
        }

        if let Some((_, command)) = programs.get(choice - 1) {
            println!("{}", format!("Launching {}...", command).cyan());
            match Command::new("sh")
                .arg("-c")
                .arg(command)
                .spawn()
            {
                Ok(mut child) => {
                    child.wait().unwrap();
                }
                Err(e) => {
                    println!("{}", format!("Failed to launch program: {}", e).red());
                }
            }
            pause();
        } else {
            println!("{}", "Invalid choice. Please try again.".red());
        }
        clear_screen();
    }
}

fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd").arg("/C").arg("cls").status().unwrap();
    } else {
        Command::new("clear").status().unwrap();
    }
}

fn pause() {
    println!("\nPress Enter to return to the menu...");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
}