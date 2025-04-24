use std::process;

mod api_setup;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: config <subcommand>");
        eprintln!("Available subcommands:");
        eprintln!("  api_setup   - Configure API keys for VT and MalwareBazaar");
        process::exit(1);
    }

    match args[1].as_str() {
        "api_setup" => api_setup::run(),
        _ => {
            eprintln!("Unknown subcommand: {}", args[1]);
            process::exit(1);
        }
    }
}
