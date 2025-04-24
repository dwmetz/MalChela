use goblin::pe::PE;

pub fn check_digital_signature(buffer: &[u8]) -> bool {
    if let Ok(pe) = PE::parse(buffer) {
        if let Some(optional) = &pe.header.optional_header {
            let directories = &optional.data_directories.data_directories;
            if directories.len() > 4 {
                if let Some((_, dir)) = &directories[4] {
                    return dir.size > 0 && dir.virtual_address > 0;
                }
            }
        }
    }
    false
}
