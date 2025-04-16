use std::fs;
use std::path::PathBuf;

/// Returns the path to the output directory for a given program.
/// Example: `<workspace_root>/saved_output/bin1/`
pub fn get_output_dir(program_name: &str) -> PathBuf {
    // Debug print to verify it's being called correctly
    // println!("common_config::get_output_dir called for {}", program_name);

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let crate_dir = manifest_dir.parent().expect("Failed to get crate folder");
    let workspace_root = crate_dir.parent().expect("Failed to get workspace root");

    let output_path = workspace_root.join("saved_output").join(program_name);
    fs::create_dir_all(&output_path).expect("Failed to create output directory");

    output_path
}