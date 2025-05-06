use std::fs;
use std::io::Write;
use chrono::Utc;
use common_config::get_output_dir;
use common_ui::styled_line;
use std::{fs::File, io::{self, Read}};
use md5;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::Sha256;
use clap::Parser;

#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliArgs {
    /// File to hash
    #[clap(value_name = "FILE")]
    file_path: Option<String>,

    /// Save output to report file
    #[clap(short = 'o', long = "output")]
    save_output: bool,

    /// Output as text
    #[clap(short = 't', long = "text", action)]
    text: bool,

    /// Output as JSON
    #[clap(short = 'j', long = "json", action)]
    json: bool,

    /// Output as Markdown
    #[clap(short = 'm', long = "markdown", action)]
    markdown: bool,
}

fn main() {
    let cli = CliArgs::parse();

    let file_path = match cli.file_path {
        Some(path) => path,
        None => {
            println!("Enter the file path:");
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("Failed to read input");
            input.trim().to_string()
        }
    };

    let save_output = cli.save_output || std::env::var("MALCHELA_SAVE_OUTPUT").is_ok();

    // Open the file
    let mut file = File::open(&file_path).expect("Failed to open the file");

    // Read the file content in chunks
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read the file");

    // Compute MD5 hash
    let md5_hash = md5::compute(&buffer);

    // Compute SHA1 hash
    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(&buffer);
    let sha1_hash = sha1_hasher.finalize();

    // Compute SHA256 hash
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&buffer);
    let sha256_hash = sha256_hasher.finalize();



    println!("{}", styled_line("stone", &format!("MD5: {:x}", md5_hash)));
    println!("{}", styled_line("stone", &format!("SHA1: {:x}", sha1_hash)));
    println!("{}", styled_line("stone", &format!("SHA256: {:x}", sha256_hash)));

    if save_output {
        let output_dir = get_output_dir("hashit");
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");

        let format = if cli.text {
            "txt"
        } else if cli.json {
            "json"
        } else if cli.markdown {
            "md"
        } else {
            println!("\n{}", styled_line("yellow", "Output format required. Use -t, -j, or -m with -o."));
            println!("{}", styled_line("stone", "Output was not saved."));
            return;
        };

        match format {
            "txt" => {
                let text_path = output_dir.join(format!("report_{}.txt", timestamp));
                fs::create_dir_all(output_dir.clone()).expect("Failed to create output directory");
                let mut file = File::create(&text_path).expect("Failed to create report file");

                writeln!(file, "MD5: {:x}", md5_hash).unwrap();
                writeln!(file, "SHA1: {:x}", sha1_hash).unwrap();
                writeln!(file, "SHA256: {:x}", sha256_hash).unwrap();

                println!("{}", styled_line("green", &format!("Text report saved to: {}", text_path.display())));
            }
            "md" => {
                let md_path = output_dir.join(format!("report_{}.md", timestamp));
                fs::create_dir_all(output_dir.clone()).expect("Failed to create output directory");
                let mut file = File::create(&md_path).expect("Failed to create markdown report file");

                writeln!(file, "# Hash Report").unwrap();
                writeln!(file, "- **MD5**: {:x}", md5_hash).unwrap();
                writeln!(file, "- **SHA1**: {:x}", sha1_hash).unwrap();
                writeln!(file, "- **SHA256**: {:x}", sha256_hash).unwrap();

                println!("{}", styled_line("green", &format!("Markdown report saved to: {}", md_path.display())));
            }
            _ => {
                let json_path = output_dir.join(format!("report_{}.json", timestamp));
                fs::create_dir_all(output_dir.clone()).expect("Failed to create output directory");
                let mut file = File::create(&json_path).expect("Failed to create JSON report file");

                let json = serde_json::json!({
                    "md5": format!("{:x}", md5_hash),
                    "sha1": format!("{:x}", sha1_hash),
                    "sha256": format!("{:x}", sha256_hash)
                });

                file.write_all(serde_json::to_string_pretty(&json).unwrap().as_bytes()).unwrap();
                println!("{}", styled_line("green", &format!("JSON report saved to: {}", json_path.display())));
            }
        }
    } else if std::env::var("MALCHELA_GUI_MODE").is_err() {
        println!("{}", styled_line("stone", "Output was not saved."));
    }
}
