use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use serde_yaml;

#[derive(Debug, Deserialize)]
struct SigmaRule {
    title: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detections_yaml_content = fs::read_to_string("detections.yaml")?;
    let sigma_rules: HashMap<String, SigmaRule> = serde_yaml::from_str(&detections_yaml_content)?;

    for rule in sigma_rules.values() {
        println!("{}", rule.title);
    }

    Ok(())
}