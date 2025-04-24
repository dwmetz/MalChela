use goblin::pe::PE;
use std::time::{UNIX_EPOCH, Duration};

#[derive(Debug)]
pub struct PEInfo {
    pub summary: String,
    pub compile_time: String,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub sections: Vec<String>,
}

pub fn parse_pe_header(file_content: &[u8]) -> Result<PEInfo, Box<dyn std::error::Error>> {
    let pe = PE::parse(file_content)?;

    // Compile timestamp
    let compile_time_raw = pe.header.coff_header.time_date_stamp;
    let compile_time = UNIX_EPOCH
        .checked_add(Duration::new(compile_time_raw as u64, 0))
        .map(|ts| {
            let datetime: chrono::DateTime<chrono::Utc> = chrono::DateTime::<chrono::Utc>::from(ts);
            datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        })
        .unwrap_or_else(|| "Invalid timestamp".to_string());

    // Section names
    let sections = pe.sections.iter().map(|s| {
        let name = std::str::from_utf8(&s.name)
            .unwrap_or("")
            .trim_end_matches('\u{0}')
            .to_string();
        format!("{} ({} bytes)", name, s.virtual_size)
    }).collect();

    // Imports
    let mut imports = vec![];
    for import in pe.imports {
        imports.push(import.name.to_string());
    }

    // Exports
    let mut exports = vec![];
    for export in &pe.exports {
        if let Some(name) = export.name {
            exports.push(name.to_string());
        }
    }

    Ok(PEInfo {
        summary: format!(
            "Machine: {:#x}, Number of sections: {}",
            pe.header.coff_header.machine,
            pe.header.coff_header.number_of_sections
        ),
        compile_time,
        imports,
        exports,
        sections,
    })
}