use std::process::Command;
use std::io::{self, Write};
fn main() {
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

            https://bakerstreetforensics.com                                                                                                                                  
"#;
    let programs = vec![
        ("Combine YARA", "cargo run --bin combine_yara"),
        ("Extract Samples", "cargo run --bin extract_samples"),
        ("Hash It", "cargo run --bin hashit"),
        ("MZCount", "cargo run --bin mzcount"),
        ("MZMD5", "cargo run --bin mzmd5"),
        ("NSRL MD5 Lookup", "cargo run --bin nsrlmd5"),
        ("NSRL SHA1 Lookup", "cargo run --bin nsrlsha1"),
        ("Strings to YARA", "cargo run --bin strings_to_yara"),
        ("Malware Hash Lookup", "cargo run --bin vthash"),
        ("XMZMD5", "cargo run --bin xmzmd5"),
        ("About", "cargo run --bin about"),
    ];

    loop {
        clear_screen(); // Clear the screen before showing the menu
        println!("{}", crab_art);
        println!("MalChela - YARA & Malware Analysis Toolkit");

        println!("\nSelect a program to launch:");
        for (i, (name, _)) in programs.iter().enumerate() {
            println!("{}. {}", i + 1, name);
        }
        println!("{}. Exit", programs.len() + 1);

        print!("\nEnter your choice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let choice: usize = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Invalid input. Please enter a number.");
                continue;
            }
        };

        if choice == programs.len() + 1 {
            println!("Exiting...");
            break;
        }

        if let Some((_, command)) = programs.get(choice - 1) {
            println!("Launching {}...", command);
            match Command::new("sh")
                .arg("-c")
                .arg(command)
                .spawn()
            {
                Ok(mut child) => {
                    child.wait().unwrap();
                }
                Err(e) => {
                    println!("Failed to launch program: {}", e);
                }
            }
            pause(); // Pause after program execution
        } else {
            println!("Invalid choice. Please try again.");
        }
    }
}

/// Clears the terminal screen
fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd").arg("/C").arg("cls").status().unwrap();
    } else {
        Command::new("clear").status().unwrap();
    }
}

/// Pauses the program until the user presses Enter
fn pause() {
    println!("\nPress Enter to return to the menu...");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
}
