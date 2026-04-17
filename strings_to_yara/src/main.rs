use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use common_config::get_output_dir;

/// Reads lines from a file and returns an iterator.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(BufReader::new(file).lines())
}

/// Reads strings from a file and generates a YARA rule as a string.
fn create_yara_rule(
    rule_name: &str,
    author: &str,
    description: &str,
    hash_value: String,
    strings_file: &str,
) -> io::Result<String> {
    let mut yara_rule = format!(
        "rule {} {{\n\
         \tmeta:\n\
         \t\tauthor = \"{}\"\n\
         \t\tdescription = \"{}\"\n\
         \t\thash = \"{}\"\n\n\
         \tstrings:\n",
        rule_name, author, description, hash_value
    );

    if let Ok(lines) = read_lines(strings_file) {
        let mut id = 1;
        for line in lines.flatten() {
            let line_owned = line.to_string();
            let trimmed = line_owned.trim();
            if trimmed.to_lowercase().starts_with("hash:") {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let new_hash = parts[1].trim();
                    yara_rule = yara_rule.replace(&format!("hash = \"{}\"", hash_value), &format!("hash = \"{}\"", new_hash));
                }
                continue;
            }
            if !trimmed.is_empty() {
                let escaped = line_owned.replace('\\', "\\\\").replace('"', "\\\"");
                yara_rule.push_str(&format!("\t\t$s{} = \"{}\"\n", id, escaped));
                id += 1;
            }
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Could not open file: {}", strings_file),
        ));
    }

    yara_rule.push_str("\n\tcondition:\n\t\tuint16be(0) == 0x4D5A and\n\t\tall of them\n}\n");

    Ok(yara_rule)
}


fn prompt(msg: &str) -> String {
    print!("{}", msg);
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut filtered_args = vec![];
    let mut skip_next = false;

for (_i, arg) in args.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--case" {
            skip_next = true;
            continue;
        }
        filtered_args.push(arg.clone());
    }

    let case_name = args.iter().position(|x| x == "--case").and_then(|i| args.get(i + 1));

    let rule_name = filtered_args.get(0).cloned().unwrap_or_else(|| prompt("Rule name: "));
    let mut author = filtered_args.get(1).cloned().unwrap_or_else(|| prompt("Author (or leave blank for Anonymous): "));
    if author.is_empty() {
        author = "Anonymous".to_string();
    }
    if author == "Anonymous" {
        if let Ok(env_author) = std::env::var("MALCHELA_AUTHOR") {
            author = env_author;
        }
    }

    let description = filtered_args.get(2).cloned().unwrap_or_else(|| prompt("Description (optional): "));
    let hash_value = filtered_args.get(3).cloned().unwrap_or_else(|| prompt("Hash value (optional): "));
    let strings_file = filtered_args.get(4).cloned().unwrap_or_else(|| prompt("Path to strings file: "));

    println!("Using input file: {}", strings_file);
    println!("Rule Name: {}", rule_name);
    println!("Author: {}", author);
    println!("Description: {}", description);
    println!("Hash: {}", hash_value);
    println!("Input file: {}", strings_file);

    match create_yara_rule(&rule_name, &author, &description, hash_value, &strings_file) {
        Ok(yara_rule) => {
            println!("\n--- YARA Rule Content ---\n{}", yara_rule);

            let output_dir = if let Some(case) = case_name {
                common_config::ensure_case_json(case);
                get_output_dir(&format!("cases/{}", case))
            } else {
                get_output_dir("strings_to_yara")
            };
            std::fs::create_dir_all(&output_dir)?;

            let filename = format!("{}.yar", rule_name);
            let output_path = output_dir.join(&filename);

            let mut file = File::create(&output_path)?;
            file.write_all(yara_rule.as_bytes())?;

            println!(
                "\nYARA rule saved to: {}\n",
                output_path.display()
            );

            // If MALCHELA_YARA_LIB is set, also copy to the workspace yara_rules directory
            if std::env::var("MALCHELA_YARA_LIB").is_ok() {
                if let Some(workspace) = common_config::find_workspace_root() {
                    let lib_dir = workspace.join("yara_rules");
                    if let Ok(()) = std::fs::create_dir_all(&lib_dir) {
                        let lib_path = lib_dir.join(&filename);
                        if let Ok(()) = std::fs::copy(&output_path, &lib_path).map(|_| ()) {
                            println!("Also saved to YARA Library: {}", lib_path.display());
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error generating YARA rule: {}", e);
        }
    }

    Ok(())
}