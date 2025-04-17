use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::error::Error;
use std::env;

#[derive(Debug, Deserialize, Default)]
pub struct CommonConfig {
    pub input_type: String,
    pub description: Option<String>,
}

impl CommonConfig {
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let config_content = fs::read_to_string(path)?;
        let config: CommonConfig = serde_yaml::from_str(&config_content)?;
        Ok(config)
    }
}

pub fn get_output_dir(tool_name: &str) -> PathBuf {
    let mut dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    dir.push("saved_output");
    dir.push(tool_name);
    dir
}