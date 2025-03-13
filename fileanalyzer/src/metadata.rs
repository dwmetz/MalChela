use std::fs;
use std::time::{UNIX_EPOCH, SystemTime};
use chrono::{Utc, TimeZone};

pub fn get_metadata(file_path: &str) -> Result<String, std::io::Error> {
    let metadata = fs::metadata(file_path)?;
    let modified_system_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    let modified_epoch_seconds = modified_system_time
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let datetime = Utc.timestamp_opt(modified_epoch_seconds as i64, 0).unwrap(); // Use timestamp_opt

    // Convert bytes to megabytes (MB)
    let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);

    Ok(format!(
        "Size: {:.2} MB, Last Modified: {}", // Format to 2 decimal places
        size_mb,
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    ))
}