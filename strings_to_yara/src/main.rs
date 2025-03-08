use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// Prompts the user for input and returns the collected metadata.
fn get_user_input() -> (String, String, String, String, String) {
    let mut input = String::new();

    println!("Enter the rule name: ");
    io::stdin().read_line(&mut input).unwrap();
    let rule_name = input.trim().to_string();
    input.clear();

    println!("Enter the author: ");
    io::stdin().read_line(&mut input).unwrap();
    let author = input.trim().to_string();
    input.clear();

    println!("Enter the description: ");
    io::stdin().read_line(&mut input).unwrap();
    let description = input.trim().to_string();
    input.clear();

    println!("Enter the hash value: ");
    io::stdin().read_line(&mut input).unwrap();
    let hash_value = input.trim().to_string();
    input.clear();

    println!("Enter the path to the source text file (e.g., strings.txt): ");
    io::stdin().read_line(&mut input).unwrap();
    let strings_file = input.trim().to_string();

    (rule_name, author, description, hash_value, strings_file)
}

/// Reads strings from a file and generates a YARA rule as a string.
fn create_yara_rule(
    rule_name: &str,
    author: &str,
    description: &str,
    hash_value: &str,
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

    // Open the strings file and read its lines.
    if let Ok(lines) = read_lines(strings_file) {
        for (id, line) in lines.enumerate() {
            if let Ok(content) = line {
                yara_rule.push_str(&format!("\t\t$s{} = \"{}\"\n", id + 1, content.trim()));
            }
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Could not open file: {}", strings_file),
        ));
    }

    yara_rule.push_str("\n\tcondition:\n\t\tall of them\n}\n");

    Ok(yara_rule)
}

/// Reads lines from a file and returns an iterator.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() -> io::Result<()> {
    // Gather user input for metadata and file location.
    let (rule_name, author, description, hash_value, strings_file) = get_user_input();

    // Generate the YARA rule.
    match create_yara_rule(&rule_name, &author, &description, &hash_value, &strings_file) {
        Ok(yara_rule) => {
            // Print the generated YARA rule.
            println!("Generated YARA rule:\n{}", yara_rule);

            // Create the "Saved_Output" directory if it doesn't exist.
            let output_dir = Path::new("Saved_Output");
            fs::create_dir_all(output_dir)?;

            // Save the YARA rule to a file in the "Saved_Output" directory.
            let yar_filename = format!("{}.yar", rule_name);
            let mut yar_file_path = PathBuf::from(output_dir);
            yar_file_path.push(yar_filename);

            let mut yar_file = File::create(&yar_file_path)?;
            yar_file.write_all(yara_rule.as_bytes())?;

            println!("YARA rule saved to {}", yar_file_path.display());
        }
        Err(e) => {
            eprintln!("Error generating YARA rule: {}", e);
        }
    }

    Ok(())
}