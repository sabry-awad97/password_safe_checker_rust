use reqwest::Error;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::str;

#[derive(Debug)]
enum PasswordCheckStatus {
    Compromised(u32),
    Safe,
}

struct PasswordCheckResult {
    password: String,
    status: PasswordCheckStatus,
}

struct API {
    client: reqwest::Client,
}

impl API {
    async fn get_password_leaks(&self, query_char: &str) -> Result<String, Error> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", query_char);
        self.client.get(&url).send().await?.text().await
    }
}

struct PasswordHasher {
    sha1: Sha1,
}

impl PasswordHasher {
    fn new() -> Self {
        Self { sha1: Sha1::new() }
    }

    fn hash_password(&mut self, password: &str) -> String {
        self.sha1.update(password.as_bytes());
        let hash = self.sha1.clone().finalize();
        hash.iter()
            .map(|b| format!("{:02x}", b).to_uppercase())
            .collect::<String>()
    }
}

fn get_password_status(api_response: &str, hash_to_check: &str) -> PasswordCheckStatus {
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

async fn check_password(
    api: &API,
    password_hasher: &mut PasswordHasher,
    password: &str,
) -> Result<PasswordCheckResult, Error> {
    let sha1_password = password_hasher.hash_password(password);
    let first_5_chars = &sha1_password[..5];
    let tail = &sha1_password[5..];
    let api_response = api.get_password_leaks(first_5_chars).await?;
    Ok(PasswordCheckResult {
        password: password.to_string(),
        status: get_password_status(&api_response, tail),
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let api = API {
        client: reqwest::Client::new(),
    };
    let mut password_hasher = PasswordHasher::new();
    let args: Vec<String> = std::env::args().collect();

    let password = &args[1];

    let result = check_password(&api, &mut password_hasher, password).await;
    match result {
        Ok(PasswordCheckResult { password, status }) => match status {
            PasswordCheckStatus::Compromised(count) => println!(
                "The password: {} has been compromised {} times!. Consider changing it.",
                password, count
            ),
            PasswordCheckStatus::Safe => println!("The password: {} is safe!", password),
        },
        Err(e) => println!("An error occurred: {}", e),
    }

    Ok(())
}
