use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::str;

async fn fetch_api_data(query_char: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("https://api.pwnedpasswords.com/range/{}", query_char);
    Ok(reqwest::get(&url).await?.text().await?)
}

fn get_password_leaks_count(api_response: &str, hash_to_check: &str) -> u32 {
    let lines = api_response.lines();
    let hash_counts: HashMap<&str, u32> = lines
        .map(|line| {
            let parts: Vec<&str> = line.split(":").collect();
            (parts[0], parts[1].parse().unwrap())
        })
        .collect();
    *hash_counts.get(hash_to_check).unwrap_or(&0)
}

async fn check_password_compromised(password: &str) -> u32 {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let sha1_password = hash
        .iter()
        .map(|b| format!("{:02x}", b).to_uppercase())
        .collect::<String>();

    let first_5_chars = &sha1_password[..5];
    let tail = &sha1_password[5..];
    let api_response = fetch_api_data(first_5_chars).await.unwrap();
    get_password_leaks_count(&api_response, tail)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    for password in &args[1..] {
        let count = check_password_compromised(password).await;
        if count > 0 {
            println!(
                "The password {} was found {} times. Consider changing it!",
                password, count
            );
        } else {
            println!(
                "The password {} was not found. You're good to go!",
                password
            );
        }
    }

    Ok(())
}
