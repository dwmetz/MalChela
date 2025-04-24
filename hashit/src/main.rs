use std::fs::{self, OpenOptions};
use std::path::PathBuf;
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

    let timestamp = Utc::now().format("%Y%m%d%H%M").to_string();
    let filename = format!("hashit-{}-report.txt", timestamp);
    let output_dir: PathBuf = get_output_dir("hashit");
    let report_path = output_dir.join(&filename);

    use std::io::Write;

    println!("{}", styled_line("stone", &format!("MD5: {:x}", md5_hash)));
    println!("{}", styled_line("stone", &format!("SHA1: {:x}", sha1_hash)));
    println!("{}", styled_line("stone", &format!("SHA256: {:x}", sha256_hash)));

    if save_output {
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).expect("Failed to create output directory");
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&report_path)
            .expect("Failed to create report file");

        writeln!(file, "{}", styled_line("stone", &format!("MD5: {:x}", md5_hash))).unwrap();
        writeln!(file, "{}", styled_line("stone", &format!("SHA1: {:x}", sha1_hash))).unwrap();
        writeln!(file, "{}", styled_line("stone", &format!("SHA256: {:x}", sha256_hash))).unwrap();

        println!("{}", styled_line("green", &format!("The results have been saved to: {}", report_path.display())));
    } else {
        println!("{}", styled_line("stone", "Output was not saved."));
    }
}
