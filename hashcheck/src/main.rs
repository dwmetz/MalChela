use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use chrono::Local;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (file_path, hash_value, save_output, output_format) = if args.len() >= 3 {
        let file = args[1].trim().to_string();
        let hash = args[2].trim().to_string();
        let save = args.contains(&"-o".to_string());
        let format = if args.contains(&"-t".to_string()) {
            "txt"
        } else if args.contains(&"-j".to_string()) {
            "json"
        } else if args.contains(&"-m".to_string()) {
            "md"
        } else if save {
            println!("\nOutput format required. Use -t, -j, or -m with -o.");
            println!();
            println!("Output was not saved.");
            return;
        } else {
            ""
        };
        let save_output = save && !format.is_empty();
        (file, hash, save_output, format.to_string())
    } else {
        // Prompt for file path
        print!("Enter the path to the hash file (.tsv recommended for file path lookup): ");
        io::stdout().flush().unwrap();
        let mut file_path = String::new();
        io::stdin().read_line(&mut file_path).unwrap();
        let file_path = file_path.trim().to_string();

        // Prompt for hash
        print!("Enter the hash value to search for: ");
        io::stdout().flush().unwrap();
        let mut hash_value = String::new();
        io::stdin().read_line(&mut hash_value).unwrap();
        let hash_value = hash_value.trim().to_string();

        (file_path, hash_value, false, String::new())
    };

    // Open and read file
    if !Path::new(&file_path).exists() {
        eprintln!("File not found: {}", file_path);
        return;
    }

    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let mut found = false;

    for line in reader.lines() {
        match line {
            Ok(content) => {
                if content.contains(&hash_value) {
                    found = true;
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error reading line: {}", e);
                return;
            }
        }
    }

    if found {
        println!("Hash: {}", hash_value);
        println!("Hash value FOUND in the file.");

        // Re-open to search for the path (for TSV lookup)
        if let Ok(file) = File::open(&file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if line.contains(&hash_value) {
                    if let Some((_, path)) = line.split_once('\t') {
                        println!("Associated file path: {}", path);
                    }
                    break;
                }
            }
        }
    } else {
        println!("Hash value NOT found in the file.");
    }

    if save_output {
        let mut path = std::env::current_dir().unwrap_or_else(|_| ".".into());
        path.push("saved_output/hashcheck");
        std::fs::create_dir_all(&path).ok();
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let output_file = path.join(format!("report_{}.{}", timestamp, output_format));
        let report = match output_format.as_str() {
            "json" => {
                format!(
                    "{{\n  \"file\": \"{}\",\n  \"hash\": \"{}\",\n  \"result\": \"{}\"\n}}",
                    file_path,
                    hash_value,
                    if found { "FOUND" } else { "NOT FOUND" }
                )
            }
            "md" => {
                format!(
                    "# Hash Check Report\n\n- **File:** `{}`\n- **Hash:** `{}`\n- **Result:** **{}**\n",
                    file_path,
                    hash_value,
                    if found { "FOUND" } else { "NOT FOUND" }
                )
            }
            _ => {
                format!(
                    "Hash Check Result\n=================\nFile: {}\nHash: {}\nResult: {}\n",
                    file_path,
                    hash_value,
                    if found { "FOUND" } else { "NOT FOUND" }
                )
            }
        };
        let _ = std::fs::write(&output_file, report);
        println!("\nThe results have been saved to: {}", output_file.display());
    }
}