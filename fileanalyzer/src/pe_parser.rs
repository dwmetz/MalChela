use std::convert::TryInto;

pub fn parse_pe_header(file_content: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if file_content.len() < 0x40 {
        return Ok("File too short to be a PE file".to_string());
    }

    if !file_content.starts_with(&[0x4D, 0x5A]) {
        return Ok("Not a PE file".to_string());
    }

    let pe_offset = u32::from_le_bytes(file_content[0x3C..0x40].try_into()?);

    if file_content.len() < (pe_offset + 0x18) as usize {
        return Ok("File too short to contain PE header".to_string());
    }

    if !file_content[pe_offset as usize..(pe_offset + 4) as usize].starts_with(&[0x50, 0x45, 0x00, 0x00]) {
        return Ok("Invalid PE signature".to_string());
    }

    let machine = u16::from_le_bytes(file_content[(pe_offset + 4) as usize..(pe_offset + 6) as usize].try_into()?);
    let number_of_sections = u16::from_le_bytes(file_content[(pe_offset + 6) as usize..(pe_offset + 8) as usize].try_into()?);

    Ok(format!("Machine: 0x{:X}, Sections: {}", machine, number_of_sections))
}