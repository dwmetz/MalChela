use std::{fs::File, io::{self, Read}};
use md5;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::Sha256;

fn main() {
    // Prompt user for file path
    println!("Enter the file path:");
    let mut file_path = String::new();
    io::stdin().read_line(&mut file_path).expect("Failed to read input");
    let file_path = file_path.trim();

    // Open the file
    let mut file = File::open(file_path).expect("Failed to open the file");

    // Read the file content in chunks
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read the file");

    // Compute MD5 hash
    let md5_hash = md5::compute(&buffer);
    println!("MD5: {:x}", md5_hash);

    // Compute SHA1 hash
    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(&buffer);
    let sha1_hash = sha1_hasher.finalize();
    println!("SHA1: {:x}", sha1_hash);

    // Compute SHA256 hash
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&buffer);
    let sha256_hash = sha256_hasher.finalize();
    println!("SHA256: {:x}", sha256_hash);
}
