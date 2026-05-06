use clap::Parser;
use common_config::get_output_dir;
use common_ui::styled_line;
use goblin::mach::{self, Mach, SingleArch};
use goblin::Object;
use serde::Serialize;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

fn is_gui_mode() -> bool {
    std::env::var("MALCHELA_GUI_MODE").is_ok() && std::env::var("MALCHELA_WORKSPACE_MODE").is_err()
}

fn plain_text(s: &str) -> String {
    let stripped = strip_ansi_escapes::strip_str(s);
    stripped
        .lines()
        .map(|line| {
            if line.starts_with('[') {
                if let Some(end) = line.find(']') {
                    return line[end + 1..].to_string();
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Parser)]
#[command(name = "macho_info", about = "Parses Mach-O binaries for static analysis indicators.")]
struct Args {
    #[arg(help = "Path to Mach-O binary")]
    input: Option<String>,

    #[arg(short, long, help = "Save output to file")]
    output: bool,

    #[arg(short = 't', long, help = "Save as TXT format")]
    text: bool,

    #[arg(short = 'j', long, help = "Save as JSON format")]
    json: bool,

    #[arg(short = 'm', long, help = "Save as Markdown format")]
    markdown: bool,

    #[arg(long, help = "Optional case name for routing output")]
    case: Option<String>,
}

#[derive(Serialize, Clone)]
struct SectionInfo {
    name: String,
    segment: String,
    size: u64,
    entropy: f64,
    high_entropy: bool,
}

#[derive(Serialize, Clone)]
struct ArchInfo {
    cpu_type: String,
    file_type: String,
    dylibs: Vec<String>,
    rpath_entries: Vec<String>,
    sections: Vec<SectionInfo>,
    symbol_count: usize,
    symbols_stripped: bool,
    pagezero_present: bool,
    pagezero_zero_sized: bool,
    has_pie: bool,
}

#[derive(Serialize)]
struct MachoReport {
    file_path: String,
    is_fat: bool,
    architectures: Vec<ArchInfo>,
    flags: Vec<String>,
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0f64, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

fn cpu_type_name(cputype: u32, cpusubtype: u32) -> String {
    // CPU type values from macOS definitions
    let arch_abi64: u32 = 0x0100_0000;
    match cputype {
        7 => "x86".to_string(),
        v if v == 7 | arch_abi64 => "x86_64".to_string(),
        12 => "arm".to_string(),
        v if v == 12 | arch_abi64 => {
            // arm64e has cpusubtype 0x80000002
            if cpusubtype & 0x0000_00ff == 2 { "arm64e".to_string() } else { "arm64".to_string() }
        }
        v if v == 12 | 0x0200_0000 => "arm64_32".to_string(),
        18 => "powerpc".to_string(),
        v if v == 18 | arch_abi64 => "powerpc64".to_string(),
        other => format!("cpu_type_0x{:x}", other),
    }
}

fn filetype_name(ft: u32) -> &'static str {
    match ft {
        0x1 => "Object file",
        0x2 => "Executable",
        0x3 => "Fixed VM shared library",
        0x4 => "Core dump",
        0x5 => "Preloaded executable",
        0x6 => "Dynamic library",
        0x7 => "Dynamic linker",
        0x8 => "Bundle",
        0x9 => "Shared library stub",
        0xa => "dSYM companion file",
        0xb => "Kext bundle",
        _ => "Unknown",
    }
}

fn analyze_macho_single(bytes: &[u8], macho: &mach::MachO) -> ArchInfo {
    let cpu_str = cpu_type_name(macho.header.cputype, macho.header.cpusubtype);
    let file_type = filetype_name(macho.header.filetype).to_string();

    // Dylibs and rpaths are pre-computed by goblin
    let dylibs: Vec<String> = macho.libs.iter().map(|s| s.to_string()).collect();
    let rpath_entries: Vec<String> = macho.rpaths.iter().map(|s| s.to_string()).collect();

    // PIE flag: MH_PIE = 0x200000
    let has_pie = macho.header.flags & 0x20_0000 != 0;

    // __PAGEZERO check via load commands
    let mut pagezero_present = false;
    let mut pagezero_zero_sized = false;
    for lc in &macho.load_commands {
        match &lc.command {
            mach::load_command::CommandVariant::Segment64(seg) => {
                let name = std::str::from_utf8(&seg.segname).unwrap_or("").trim_matches('\0');
                if name == "__PAGEZERO" {
                    pagezero_present = true;
                    if seg.vmsize == 0 {
                        pagezero_zero_sized = true;
                    }
                }
            }
            mach::load_command::CommandVariant::Segment32(seg) => {
                let name = std::str::from_utf8(&seg.segname).unwrap_or("").trim_matches('\0');
                if name == "__PAGEZERO" {
                    pagezero_present = true;
                    if seg.vmsize == 0 {
                        pagezero_zero_sized = true;
                    }
                }
            }
            _ => {}
        }
    }

    // Sections with entropy
    let mut sections: Vec<SectionInfo> = Vec::new();
    for segment in &macho.segments {
        let seg_name = std::str::from_utf8(&segment.segname)
            .unwrap_or("?")
            .trim_matches('\0')
            .to_string();
        if let Ok(sects) = segment.sections() {
            for (sect, _) in sects {
                let sect_name = std::str::from_utf8(&sect.sectname)
                    .unwrap_or("?")
                    .trim_matches('\0')
                    .to_string();
                let offset = sect.offset as usize;
                let size = sect.size as usize;
                let sect_data = if offset > 0 && offset + size <= bytes.len() {
                    &bytes[offset..offset + size]
                } else {
                    &[]
                };
                let entropy = calculate_entropy(sect_data);
                sections.push(SectionInfo {
                    name: sect_name,
                    segment: seg_name.clone(),
                    size: sect.size,
                    entropy,
                    high_entropy: entropy > 7.0,
                });
            }
        }
    }

    // Symbol count
    let symbol_count = macho.symbols.as_ref().map(|s| s.iter().count()).unwrap_or(0);
    let symbols_stripped = symbol_count == 0;

    ArchInfo {
        cpu_type: cpu_str,
        file_type,
        dylibs,
        rpath_entries,
        sections,
        symbol_count,
        symbols_stripped,
        pagezero_present,
        pagezero_zero_sized,
        has_pie,
    }
}

fn print_arch_info(arch: &ArchInfo, temp_file: &mut File) {
    {
        let line = styled_line("stone", &format!("  CPU:       {}", arch.cpu_type));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }
    {
        let line = styled_line("stone", &format!("  File Type: {}", arch.file_type));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }
    {
        let line = styled_line("stone", &format!("  PIE/ASLR: {}", if arch.has_pie { "Yes" } else { "No" }));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    if arch.pagezero_present {
        let (color, note) = if arch.pagezero_zero_sized {
            ("yellow", " [SUSPICIOUS: zero-sized]")
        } else {
            ("stone", "")
        };
        let line = styled_line(color, &format!("  __PAGEZERO: present{}", note));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    {
        let (sym_str, color) = if arch.symbols_stripped {
            ("Stripped", "yellow")
        } else {
            ("Present", "stone")
        };
        let line = styled_line(color, &format!("  Symbols:  {} ({} symbols)", sym_str, arch.symbol_count));
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    if !arch.dylibs.is_empty() {
        println!();
        writeln!(temp_file).ok();
        let heading = styled_line("NOTE", "  --- Linked Libraries ---");
        println!("{}", heading);
        writeln!(temp_file, "{}", plain_text(&heading)).ok();
        for lib in &arch.dylibs {
            let line = styled_line("stone", &format!("    {}", lib));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    if !arch.rpath_entries.is_empty() {
        println!();
        writeln!(temp_file).ok();
        let heading = styled_line("NOTE", "  --- RPATH Entries ---");
        println!("{}", heading);
        writeln!(temp_file, "{}", plain_text(&heading)).ok();
        for rp in &arch.rpath_entries {
            let line = styled_line("yellow", &format!("    {}", rp));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }

    if !arch.sections.is_empty() {
        println!();
        writeln!(temp_file).ok();
        let heading = styled_line("NOTE", "  --- Sections ---");
        println!("{}", heading);
        writeln!(temp_file, "{}", plain_text(&heading)).ok();
        let hdr = styled_line("stone", &format!("  {:9}  {:20}  {:>10}  {:>8}", "Segment", "Section", "Size", "Entropy"));
        println!("{}", hdr);
        writeln!(temp_file, "{}", plain_text(&hdr)).ok();
        let sep = styled_line("stone", &format!("  {:->9}  {:->20}  {:->10}  {:->8}", "", "", "", ""));
        println!("{}", sep);
        writeln!(temp_file, "{}", plain_text(&sep)).ok();
        for s in &arch.sections {
            let flag = if s.high_entropy { " [HIGH]" } else { "" };
            let color = if s.high_entropy { "yellow" } else { "stone" };
            let line = styled_line(color, &format!(
                "  {:9}  {:20}  {:>10}  {:>7.4}{}",
                s.segment, s.name, s.size, s.entropy, flag
            ));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    }
}

fn build_flags(arch: &ArchInfo) -> Vec<String> {
    let mut flags = Vec::new();

    if arch.symbols_stripped {
        flags.push("Symbol table stripped — adversarial hardening indicator".to_string());
    }
    if arch.pagezero_zero_sized {
        flags.push("__PAGEZERO is zero-sized — classic privilege escalation trick in older macOS malware".to_string());
    }
    for s in &arch.sections {
        if s.high_entropy {
            flags.push(format!(
                "High entropy ({:.4}) in {}/{} — possible packed/encrypted content",
                s.entropy, s.segment, s.name
            ));
        }
    }
    // Suspicious dylib triad: CoreFoundation + SystemConfiguration + Security with few others
    let cf = arch.dylibs.iter().any(|d| d.contains("CoreFoundation"));
    let sc = arch.dylibs.iter().any(|d| d.contains("SystemConfiguration"));
    let sec = arch.dylibs.iter().any(|d| d.contains("/Security.framework"));
    if cf && sc && sec && arch.dylibs.len() < 8 {
        flags.push("Dylib triad (CoreFoundation + SystemConfiguration + Security) with minimal other imports — common C2 comms pattern".to_string());
    }
    if !arch.rpath_entries.is_empty() {
        flags.push(format!(
            "{} RPATH entr{} — check for dylib hijacking potential",
            arch.rpath_entries.len(),
            if arch.rpath_entries.len() == 1 { "y" } else { "ies" }
        ));
    }
    // Deprecated / EOL system crypto libraries
    let deprecated_patterns = [
        ("libcrypto.0.9.8", "OpenSSL 0.9.8 — deprecated, EOL, numerous known CVEs"),
        ("libssl.0.9.8",    "OpenSSL 0.9.8 — deprecated, EOL, numerous known CVEs"),
        ("libcrypto.0.0",   "OpenSSL 0.0 — very old deprecated crypto library"),
        ("libssl.0.0",      "OpenSSL 0.0 — very old deprecated crypto library"),
    ];
    for lib in &arch.dylibs {
        for (pat, note) in &deprecated_patterns {
            if lib.contains(pat) {
                flags.push(format!(
                    "Links deprecated crypto library `{}` — {} (suspicious in any modern binary)",
                    lib, note
                ));
            }
        }
    }
    flags
}

fn main() {
    let args = Args::parse();

    let file_path = match args.input {
        Some(p) => p,
        None => {
            let line = styled_line("yellow", "\nEnter the path to the Mach-O binary:");
            println!("{}", line);
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).expect("Failed to read input");
            s.trim_end_matches(&['\n', '\r'][..]).to_string()
        }
    };

    if !Path::new(&file_path).exists() {
        println!("{}", styled_line("yellow", "File not found!"));
        return;
    }

    let bytes = match fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => {
            println!("{}", styled_line("yellow", &format!("Failed to read file: {}", e)));
            return;
        }
    };

    println!();
    let temp_path = std::env::temp_dir().join("malchela_temp_output.txt");
    let mut temp_file = File::create(&temp_path).expect("Failed to create temp output file");

    let heading = styled_line("NOTE", "--- Mach-O Info ---");
    println!("{}", heading);
    writeln!(temp_file, "{}", plain_text(&heading)).ok();

    let line = styled_line("stone", &format!("File: {}", file_path));
    println!("{}", line);
    writeln!(temp_file, "{}", plain_text(&line)).ok();

    let mut all_arch_info: Vec<ArchInfo> = Vec::new();
    let mut all_flags: Vec<String> = Vec::new();
    let mut is_fat = false;

    match Object::parse(&bytes) {
        Ok(Object::Mach(Mach::Binary(ref macho))) => {
            println!();
            writeln!(temp_file).ok();
            let heading = styled_line("NOTE", "--- Architecture ---");
            println!("{}", heading);
            writeln!(temp_file, "{}", plain_text(&heading)).ok();

            let arch = analyze_macho_single(&bytes, macho);
            print_arch_info(&arch, &mut temp_file);
            let flags = build_flags(&arch);
            all_flags.extend(flags);
            all_arch_info.push(arch);
        }
        Ok(Object::Mach(Mach::Fat(ref fat))) => {
            is_fat = true;
            let line = styled_line("stone", &format!("Fat/Universal binary ({} architectures)", fat.narches));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();

            for i in 0..fat.narches {
                match fat.get(i) {
                    Ok(SingleArch::MachO(ref macho)) => {
                        println!();
                        writeln!(temp_file).ok();
                        let heading = styled_line("NOTE", &format!("--- Architecture {} ---", i + 1));
                        println!("{}", heading);
                        writeln!(temp_file, "{}", plain_text(&heading)).ok();

                        let arch = analyze_macho_single(&bytes, macho);
                        print_arch_info(&arch, &mut temp_file);
                        let flags = build_flags(&arch);
                        all_flags.extend(flags);
                        all_arch_info.push(arch);
                    }
                    Ok(SingleArch::Archive(_)) => {
                        let line = styled_line("stone", &format!("  Arch {}: Archive (skipped)", i + 1));
                        println!("{}", line);
                        writeln!(temp_file, "{}", plain_text(&line)).ok();
                    }
                    Err(e) => {
                        let line = styled_line("yellow", &format!("  Failed to parse arch {}: {}", i + 1, e));
                        println!("{}", line);
                        writeln!(temp_file, "{}", plain_text(&line)).ok();
                    }
                }
            }
        }
        Ok(_) => {
            let line = styled_line("yellow", "File is not a Mach-O binary.");
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            return;
        }
        Err(e) => {
            let line = styled_line("yellow", &format!("Failed to parse binary: {}", e));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
            return;
        }
    }

    if !all_flags.is_empty() {
        println!();
        writeln!(temp_file).ok();
        let heading = styled_line("NOTE", "--- Flags / Indicators ---");
        println!("{}", heading);
        writeln!(temp_file, "{}", plain_text(&heading)).ok();
        for flag in &all_flags {
            let line = styled_line("yellow", &format!("  [!] {}", flag));
            println!("{}", line);
            writeln!(temp_file, "{}", plain_text(&line)).ok();
        }
    } else {
        println!();
        writeln!(temp_file).ok();
        let line = styled_line("stone", "No suspicious Mach-O indicators found.");
        println!("{}", line);
        writeln!(temp_file, "{}", plain_text(&line)).ok();
    }

    temp_file.flush().expect("Failed to flush temp file");

    if args.output {
        let output_dir = if let Some(ref case) = args.case {
            common_config::ensure_case_json(case);
            let path = format!("saved_output/cases/{}/macho_info", case);
            std::fs::create_dir_all(&path).expect("Failed to create case output directory");
            std::path::PathBuf::from(path)
        } else {
            let path = get_output_dir("macho_info");
            std::fs::create_dir_all(&path).expect("Failed to create default output directory");
            path
        };

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let format = if args.text { "txt" } else if args.json { "json" } else { "md" };

        let report = MachoReport {
            file_path: file_path.clone(),
            is_fat,
            architectures: all_arch_info.clone(),
            flags: all_flags.clone(),
        };

        let out_path = match format {
            "txt" => output_dir.join(format!("report_{}.txt", timestamp)),
            "json" => output_dir.join(format!("report_{}.json", timestamp)),
            _ => output_dir.join(format!("report_{}.md", timestamp)),
        };

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create output directories");
        }

        match format {
            "txt" => {
                fs::copy(&temp_path, &out_path).expect("Failed to save text report");
                println!("\n{}\n", styled_line("green", &format!("Text report saved to: {}", out_path.display())));
            }
            "json" => {
                let json = serde_json::to_string_pretty(&report).expect("Failed to serialize");
                let mut f = File::create(&out_path).expect("Failed to create JSON report");
                f.write_all(json.as_bytes()).expect("Failed to write JSON report");
                println!("\n{}\n", styled_line("green", &format!("JSON report saved to: {}", out_path.display())));
            }
            _ => {
                let mut md = String::new();
                md.push_str("# Mach-O Info Report\n\n");
                md.push_str(&format!("**File:** `{}`  \n", file_path));
                md.push_str(&format!("**Fat/Universal:** {}  \n\n", is_fat));

                for (i, arch) in report.architectures.iter().enumerate() {
                    md.push_str(&format!("## Architecture {}\n\n", i + 1));
                    md.push_str("| Property | Value |\n|----------|-------|\n");
                    md.push_str(&format!("| CPU | {} |\n", arch.cpu_type));
                    md.push_str(&format!("| File Type | {} |\n", arch.file_type));
                    md.push_str(&format!("| PIE/ASLR | {} |\n", arch.has_pie));
                    md.push_str(&format!("| Symbols Stripped | {} |\n", arch.symbols_stripped));
                    md.push_str(&format!("| Symbol Count | {} |\n", arch.symbol_count));

                    if !arch.dylibs.is_empty() {
                        md.push_str("\n### Linked Libraries\n\n");
                        for lib in &arch.dylibs {
                            md.push_str(&format!("- `{}`\n", lib));
                        }
                    }
                    if !arch.rpath_entries.is_empty() {
                        md.push_str("\n### RPATH Entries\n\n");
                        for rp in &arch.rpath_entries {
                            md.push_str(&format!("- `{}`\n", rp));
                        }
                    }
                    if !arch.sections.is_empty() {
                        md.push_str("\n### Sections\n\n");
                        md.push_str("| Segment | Section | Size | Entropy | High Entropy |\n");
                        md.push_str("|---------|---------|------|---------|:------------:|\n");
                        for s in &arch.sections {
                            md.push_str(&format!(
                                "| {} | {} | {} | {:.4} | {} |\n",
                                s.segment, s.name, s.size, s.entropy,
                                if s.high_entropy { "**YES**" } else { "No" }
                            ));
                        }
                    }
                }

                if !report.flags.is_empty() {
                    md.push_str("\n## Flags / Indicators\n\n");
                    for f in &report.flags {
                        md.push_str(&format!("- **[!]** {}\n", f));
                    }
                }

                let mut f = File::create(&out_path).expect("Failed to create markdown report");
                f.write_all(md.as_bytes()).expect("Failed to write markdown report");
                println!("\n{}\n", styled_line("green", &format!("Markdown report saved to: {}", out_path.display())));
            }
        }
    } else if !is_gui_mode() {
        println!();
        let line = styled_line("stone", "Output was not saved. Use -o with -t, -j, or -m to export results.");
        println!("{}", line);
        println!();
        let _ = std::io::stdout().flush();
    }

    if std::env::var("MALCHELA_GUI_MODE").is_ok() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
