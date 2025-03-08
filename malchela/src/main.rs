use std::process::Command;
use std::io::{self, Write};

// ANSI color codes
const RED: &str = "\x1B[31m";
const GREEN: &str = "\x1B[32m";
const YELLOW: &str = "\x1B[33m";
const BLUE: &str = "\x1B[34m";
const CYAN: &str = "\x1B[36m";
const RESET: &str = "\x1B[0m";
const GRAY: &str = "\x1B[37m"; 

fn main() {
    let crab_art = format!(
        "{}{}{}",
        RED,
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
"#,
        RESET
    );

    let programs = vec![
        (format!("{} Combine YARA{}", GREEN, RESET), "cargo run --bin combine_yara"),
        (format!("{} Extract Samples{}", GREEN, RESET), "cargo run --bin extract_samples"),
        (format!("{} Hash It{}", GREEN, RESET), "cargo run --bin hashit"),
        (format!("{} MStrings{}", GREEN, RESET), "cargo run --bin mstrings"),
        (format!("{} MZCount{}", GREEN, RESET), "cargo run --bin mzcount"),
        (format!("{} MZMD5{}", GREEN, RESET), "cargo run --bin mzmd5"),
        (format!("{} NSRL MD5 Lookup{}", GREEN, RESET), "cargo run --bin nsrlmd5"),
        (format!("{} NSRL SHA1 Lookup{}", GREEN, RESET), "cargo run --bin nsrlsha1"),
        (format!("{} Strings to YARA{}", GREEN, RESET), "cargo run --bin strings_to_yara"),
        (format!("{}Malware Hash Lookup{}", GREEN, RESET), "cargo run --bin vthash"),
        (format!("{}XMZMD5{}", GREEN, RESET), "cargo run --bin xmzmd5"),
        (format!("{}About{}", GREEN, RESET), "cargo run --bin about"),
    ];

    loop {
        clear_screen();
        println!("{}", crab_art);
        println!("{}MalChela - YARA & Malware Analysis Toolkit{}", BLUE, RESET);

        println!("\nSelect a program to launch:");
        for (i, (name, _)) in programs.iter().enumerate() {
            println!("{}. {}", i + 1, name);
        }
        println!("{}. {}Exit{}", programs.len() + 1, GRAY, RESET);

        print!("\nEnter your choice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let choice: usize = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("{}Invalid input. Please enter a number.{}", RED, RESET);
                continue;
            }
        };

        if choice == programs.len() + 1 {
            println!("{}Exiting...{}", YELLOW, RESET);
            break;
        }

        if let Some((_, command)) = programs.get(choice - 1) {
            println!("{}Launching {}...{}", CYAN, command, RESET);
            match Command::new("sh")
                .arg("-c")
                .arg(command)
                .spawn()
            {
                Ok(mut child) => {
                    child.wait().unwrap();
                }
                Err(e) => {
                    println!("{}Failed to launch program: {}{}", RED, e, RESET);
                }
            }
            pause();
        } else {
            println!("{}Invalid choice. Please try again.{}", RED, RESET);
        }
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