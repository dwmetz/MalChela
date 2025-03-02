use reqwest;
use serde_json::Value;
use std::io;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Query a SHA1 Hash against the NSRL Database");

    // Get the SHA1 hash from user input
    println!("Enter the SHA1 hash value:");
    let mut hash = String::new();
    io::stdin().read_line(&mut hash)?;
    let hash = hash.trim(); // Remove trailing newline

    // Construct the URL
    let url = format!("https://hashlookup.circl.lu/lookup/sha1/{}", hash);

    // Make the API request
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    // Check if the request was successful
    if response.status().is_success() {
        // Parse the JSON response
        let json: Value = response.json().await?;

        // Print the JSON response in a pretty format
        println!("Response from CIRCL Hash Lookup:");
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else if response.status().as_u16() == 404 {
        println!("Hash not found in the database.");
    } else {
        println!("Error: {}", response.status());
    }

    Ok(())
}
