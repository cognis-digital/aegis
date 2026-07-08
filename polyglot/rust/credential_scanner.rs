use std::fs;
use std::path::Path;
use regex::Regex;

#[derive(Debug)]
enum CredentialType {
    APIKey,
    UsernamePassword,
    Token,
    Secret,
    Other,
}

#[derive(Debug)]
struct Credential {
    type_: CredentialType,
    value: String,
    file_path: String,
    line_number: usize,
}

fn detect_credentials(text: &str) -> Vec<Credential> {
    let mut credentials = Vec::new();

    // Regular expressions for different credential types
    let api_key_re = Regex::new(r#"(?i)(api\s+key|token|secret)\s*:\s*["']?(.+?)["']?"#).unwrap();
    let username_password_re = Regex::new(r#"(?i)(username|user)\s*:\s*["']?(.+?)["']?[\s\S]*?(password|pass)\s*:\s*["']?(.+?)["']?"#).unwrap();
    let token_re = Regex::new(r#"(?i)(token|bearer|access_token)\s*:\s*["']?(.+?)["']?"#).unwrap();
    let secret_re = Regex::new(r#"(?i)(secret|key|password|pass)\s*:\s*["']?(.+?)["']?"#).unwrap();

    // Check for API keys
    for cap in api_key_re.captures_iter(text) {
        if let Some(value) = cap.name("2") {
            credentials.push(Credential {
                type_: CredentialType::APIKey,
                value: value.as_str().to_string(),
                file_path: String::new(),
                line_number: 0,
            });
        }
    }

    // Check for username and password
    for cap in username_password_re.captures_iter(text) {
        if let Some(username) = cap.name("2") && let Some(password) = cap.name("4") {
            credentials.push(Credential {
                type_: CredentialType::UsernamePassword,
                value: format!("{}:{}", username.as_str(), password.as_str()),
                file_path: String::new(),
                line_number: 0,
            });
        }
    }

    // Check for tokens
    for cap in token_re.captures_iter(text) {
        if let Some(value) = cap.name("2") {
            credentials.push(Credential {
                type_: CredentialType::Token,
                value: value.as_str().to_string(),
                file_path: String::new(),
                line_number: 0,
            });
        }
    }

    // Check for secrets
    for cap in secret_re.captures_iter(text) {
        if let Some(value) = cap.name("2") {
            credentials.push(Credential {
                type_: CredentialType::Secret,
                value: value.as_str().to_string(),
                file_path: String::new(),
                line_number: 0,
            });
        }
    }

    // Fallback for any other credential-like patterns
    let other_re = Regex::new(r#"(?i)(key|token|secret|password|pass)\s*:\s*["']?(.+?)["']?"#).unwrap();
    for cap in other_re.captures_iter(text) {
        if let Some(value) = cap.name("2") {
            credentials.push(Credential {
                type_: CredentialType::Other,
                value: value.as_str().to_string(),
                file_path: String::new(),
                line_number: 0,
            });
        }
    }

    credentials
}

fn scan_directory(path: &str) -> Vec<Credential> {
    let mut all_credentials = Vec::new();

    if Path::new(path).is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let content = fs::read_to_string(&path).unwrap();
                let lines: Vec<&str> = content.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    let mut found = detect_credentials(line);
                    for cred in found.iter_mut() {
                        cred.file_path = path.display().to_string();
                        cred.line_number = i + 1;
                    }
                    all_credentials.extend(found);
                }
            }
        }
    }

    all_credentials
}

fn main() {
    // Example usage: scan a directory for credentials
    let credentials = scan_directory("examples");

    if credentials.is_empty() {
        println!("No credentials found.");
    } else {
        println!("Found {} credentials:", credentials.len());
        for cred in &credentials {
            match cred.type_ {
                CredentialType::APIKey => println!("  API Key: {} (Line {}, File: {})", cred.value, cred.line_number, cred.file_path),
                CredentialType::UsernamePassword => println!("  Username/Password: {} (Line {}, File: {})", cred.value, cred.line_number, cred.file_path),
                CredentialType::Token => println!("  Token: {} (Line {}, File: {})", cred.value, cred.line_number, cred.file_path),
                CredentialType::Secret => println!("  Secret: {} (Line {}, File: {})", cred.value, cred.line_number, cred.file_path),
                CredentialType::Other => println!("  Other credential: {} (Line {}, File: {})", cred.value, cred.line_number, cred.file_path),
            }
        }
    }
}