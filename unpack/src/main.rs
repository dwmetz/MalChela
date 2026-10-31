use clap::Parser;
use common_config::get_output_dir;
use common_ui::styled_line;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use unpack::{engine, external, report, util};

#[derive(Parser)]
#[command(
    name = "unpack",
    version,
    about = "Static packer detection and unpacking for PE, ELF, and Mach-O (UPX incl. tampered headers, fat Mach-O, PyInstaller, .NET/Costura resources, NSIS, Inno Setup, overlays and embedded executables). Never executes the sample."
)]
struct Args {
    #[arg(help = "Path to the file to unpack")]
    input: Option<String>,

    #[arg(long, value_name = "DIR", help = "Directory for recovered payloads (default: <input>_unpacked next to the input, or inside the case)")]
    out: Option<String>,

    #[arg(long, help = "Optional case name for routing output")]
    case: Option<String>,

    #[arg(long, help = "Print a machine-readable JSON summary to stdout instead of the console report")]
    json: bool,

    #[arg(short, long, help = "Save the report to file")]
    output: bool,

    #[arg(short = 't', long, help = "Save report as TXT")]
    text: bool,

    #[arg(short = 'j', long = "json-report", help = "Save report as JSON")]
    json_report: bool,

    #[arg(short = 'm', long, help = "Save report as Markdown")]
    markdown: bool,

    #[arg(long, default_value_t = 3, help = "Maximum unpacking depth (layers)")]
    max_depth: u32,

    #[arg(long, default_value_t = 512, value_name = "MB", help = "Cap on total bytes written across the run")]
    max_output_mb: u64,

    #[arg(long, help = "Do not call external helpers (upx, 7-Zip, innoextract); detection and native handlers only")]
    no_external: bool,

    #[arg(long, help = "With -o: only save a report when something was detected (used by Analyze to keep cases free of 'nothing found' reports)")]
    only_if_found: bool,

    #[arg(long, help = "Show which optional external helpers are available, then exit")]
    check: bool,
}

#[derive(Serialize)]
struct PayloadJson {
    path: String,
    sha256: String,
    size: u64,
    format: String,
    depth: u32,
    source: String,
}

#[derive(Serialize)]
struct Summary<'a> {
    success: bool,
    input: String,
    sha256: String,
    verdict: String,
    /// A non-informational detection or a recovered payload.
    significant: bool,
    packed: bool,
    out_dir: Option<String>,
    payloads: Vec<PayloadJson>,
    mitre: Vec<&'static str>,
    bytes_written: u64,
    tree: &'a engine::Node,
}

fn helpers() -> Vec<(String, Option<PathBuf>)> {
    external::ALL.iter().map(|s| (s.key.to_string(), external::find(s))).collect()
}

fn main() {
    let args = Args::parse();

    if args.check {
        println!("{}", styled_line("yellow", "unpack — optional external helpers"));
        for (spec, (_k, found)) in external::ALL.iter().zip(helpers()) {
            match found {
                Some(p) => println!("{}", styled_line("green", &format!("  {:<12} {}", spec.key, p.display()))),
                None => println!("{}", styled_line("stone", &format!("  {:<12} not found  ({}; or set {})", spec.key, spec.install_hint, spec.env))),
            }
        }
        println!("{}", styled_line("stone", "Native (no helper needed): fat Mach-O split, PyInstaller, .NET/Costura resources, overlay + embedded executable carving, detection."));
        return;
    }

    let input = match args.input.clone() {
        Some(p) => p,
        None => {
            println!("{}", styled_line("yellow", "Enter the path to the file to unpack:"));
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).expect("Failed to read input");
            s.trim().trim_matches('"').to_string()
        }
    };
    let input_path = PathBuf::from(&input);
    if !input_path.is_file() {
        fail(&args, &input, "Input path does not exist or is not a file");
    }

    let stem = util::file_stem(&input_path);
    let out_dir = match (&args.out, &args.case) {
        (Some(o), _) => PathBuf::from(o),
        (None, Some(case)) => {
            common_config::ensure_case_json(case);
            PathBuf::from(format!("saved_output/cases/{}/unpack", case)).join(format!("{}_unpacked", stem))
        }
        (None, None) => input_path.parent().unwrap_or_else(|| Path::new(".")).join(format!("{}_unpacked", stem)),
    };

    // Absolute, so payload paths in the report and JSON stay valid from any cwd.
    let out_dir = if out_dir.is_relative() {
        std::env::current_dir().map(|c| c.join(&out_dir)).unwrap_or(out_dir)
    } else {
        out_dir
    };

    let opts = engine::Options {
        out_dir: out_dir.clone(),
        max_depth: args.max_depth.clamp(1, 10),
        max_output: args.max_output_mb.max(1).saturating_mul(1024 * 1024),
        use_external: !args.no_external,
    };
    let result = match engine::run(&input_path, opts) {
        Ok(r) => r,
        Err(e) => fail(&args, &input, &e),
    };
    let root = &result.root;
    let payloads = engine::payloads(root);
    let out_dir_str = out_dir.display().to_string();

    if args.json {
        let mut mitre = Vec::new();
        if engine::packing_found(root) {
            mitre.push("T1027.002");
        }
        if engine::embedded_found(root) {
            mitre.push("T1027.009");
        }
        if engine::encoded_found(root) {
            mitre.push("T1027.013");
        }
        let summary = Summary {
            success: true,
            input: input.clone(),
            sha256: root.sha256.clone(),
            verdict: report::verdict_line(root),
            significant: engine::significant(root),
            packed: engine::packing_found(root),
            out_dir: if payloads.is_empty() { None } else { Some(out_dir_str.clone()) },
            payloads: payloads
                .iter()
                .map(|p| PayloadJson {
                    path: p.path.clone(),
                    sha256: p.sha256.clone(),
                    size: p.size,
                    format: p.format_label.clone(),
                    depth: p.depth,
                    source: p.source.clone().unwrap_or_default(),
                })
                .collect(),
            mitre,
            bytes_written: result.bytes_written,
            tree: root,
        };
        println!("{}", serde_json::to_string(&summary).unwrap());
    } else {
        print!("{}", report::console(root, &out_dir_str));
    }

    let skip_save = args.only_if_found && !engine::significant(root);
    if args.output && !skip_save {
        let dir = if let Some(ref case) = args.case {
            common_config::ensure_case_json(case);
            PathBuf::from(format!("saved_output/cases/{}/unpack", case))
        } else {
            get_output_dir("unpack")
        };
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("Failed to create output directory: {}", e);
            std::process::exit(1);
        }
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let (ext, body) = if args.text {
            ("txt", report::plain(root, &out_dir_str))
        } else if args.json_report {
            ("json", serde_json::to_string_pretty(root).unwrap())
        } else {
            ("md", report::markdown(root, &out_dir_str))
        };
        let path = dir.join(format!("report_{}.{}", ts, ext));
        match std::fs::File::create(&path).and_then(|mut f| f.write_all(body.as_bytes())) {
            Ok(_) => {
                if !args.json {
                    println!("\n{}", styled_line("green", &format!("Report saved to: {}", path.display())));
                }
                if let Some(ref case) = args.case {
                    common_config::register_case_output("unpack", case, &input, &path);
                }
            }
            Err(e) => eprintln!("Failed to save report: {}", e),
        }
    } else if !args.json && !skip_save && std::env::var("MALCHELA_GUI_MODE").is_err() {
        println!("\n{}", styled_line("stone", "Output was not saved. Use -o with -t, -j, or -m to export results."));
    }
}

fn fail(args: &Args, input: &str, msg: &str) -> ! {
    if args.json {
        println!("{}", serde_json::json!({ "success": false, "input": input, "error": msg }));
    } else {
        eprintln!("{}", styled_line("red", &format!("Error: {}", msg)));
    }
    std::process::exit(1);
}
