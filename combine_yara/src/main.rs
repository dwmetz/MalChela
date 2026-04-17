use common_config::{get_output_dir, ensure_case_json};
use std::fs::File;
use std::io::{stdin, Write};
use walkdir::WalkDir;
use std::env;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse --case <name> from args
    let case_name = args.windows(2)
        .find(|w| w[0] == "--case")
        .map(|w| w[1].clone());

    // First non-flag, non-case-value argument is the search directory
    let mut skip_next = false;
    let search_dir_arg = args.iter().skip(1).find(|arg| {
        if skip_next {
            skip_next = false;
            return false;
        }
        if *arg == "--case" {
            skip_next = true;
            return false;
        }
        !arg.starts_with('-')
    }).cloned();

    let search_dir = search_dir_arg.unwrap_or_else(|| {
        println!("Enter the directory path to scan for YARA rules:");
        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read line");
        input.trim().to_string()
    });

    let mut combined_rules = String::new();

    for entry in WalkDir::new(search_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext_str| {
                    let ext = ext_str.to_ascii_lowercase();
                    ext == "yar" || ext == "yara"
                })
                .unwrap_or(false)
        })
    {
        let path = entry.path();
        let content = std::fs::read_to_string(path)?;
        combined_rules.push_str(&content);
        combined_rules.push('\n');
    }

    let output_dir = if let Some(ref case) = case_name {
        ensure_case_json(case);
        get_output_dir("cases").join(case).join("combine_yara")
    } else {
        get_output_dir("combine_yara")
    };
    std::fs::create_dir_all(&output_dir)?;
    let output_file_path = output_dir.join("combined_rules.yar");
    let mut output = File::create(&output_file_path)?;
    output.write_all(combined_rules.as_bytes())?;

    println!("Combined YARA rules written to: {}", output_file_path.display());

    Ok(())
}
