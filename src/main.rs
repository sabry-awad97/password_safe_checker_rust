use reqwest::Error;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::str;

enum PasswordCheckStatus {
    Compromised(u32),
    Safe,
}

async fn fetch_api_data(query_char: &str) -> Result<String, Error> {
    let url = format!("https://api.pwnedpasswords.com/range/{}", query_char);
    reqwest::get(&url).await?.text().await
}

fn get_password_leaks_count(api_response: &str, hash_to_check: &str) -> PasswordCheckStatus {
    let lines = api_response.lines();
    let hash_counts: HashMap<&str, u32> = lines
        .map(|line| {
            let parts: Vec<&str> = line.split(":").collect();
            (parts[0], parts[1].parse().unwrap())
        })
        .collect();
    match hash_counts.get(hash_to_check) {
        Some(count) => PasswordCheckStatus::Compromised(*count),
        None => PasswordCheckStatus::Safe,
    }
}

async fn check_password_compromised(password: &str) -> Result<PasswordCheckStatus, Error> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let sha1_password = hash
        .iter()
        .map(|b| format!("{:02x}", b).to_uppercase())
        .collect::<String>();

    let first_5_chars = &sha1_password[..5];
    let tail = &sha1_password[5..];
    let api_response = fetch_api_data(first_5_chars).await?;
    Ok(get_password_leaks_count(&api_response, tail))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    for password in &args[1..] {
        let result = check_password_compromised(password).await?;
        match result {
            PasswordCheckStatus::Compromised(count) => println!(
                "The password {} was found {} times. Consider changing it!",
                password, count
            ),
            PasswordCheckStatus::Safe => println!(
                "The password {} was not found. You're good to go!",
                password
            ),
        }
    }
    Ok(())
}
