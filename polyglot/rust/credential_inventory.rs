use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// =============================================================================
// Configuration & Constants
// =============================================================================

const DEFAULT_SCAN_PATHS: &[&str] = &[
    "./",
    "./src/",
    "./config/",
    "./.env",
    "./.git/config",
];

const CREDENTIAL_PATTERNS: &[(&str, &str)] = &[
    // API Keys
    (r#"[""]?api[_-]?key\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,64})["']?"#, "API_KEY"),
    (r#"[""]?apikey\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,64})["']?"#, "API_KEY"),
    
    // Bearer Tokens / JWT
    (r#"[""]?bearer[_-]?token\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]{16,})["']?"#, "BEARER_TOKEN"),
    (r#"[""]?access[_-]?token\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,100})["']?"#, "ACCESS_TOKEN"),
    
    // Generic Secrets
    (r#"[""]?secret\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,64})["']?"#, "SECRET"),
    (r#"[""]?password\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{8,32})["']?"#, "PASSWORD"),
    
    // OAuth / Auth Tokens
    (r#"[""]?(auth[_-]?)?token\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{16,64})["']?"#, "AUTH_TOKEN"),
    (r#"[""]?(oauth[_-]?)?access[_-]?token\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,80})["']?"#, "OAUTH_TOKEN"),
    
    // Service Accounts / Cloud
    (r#"[""]?(service[_-]?)?account[_-]?key\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{30,120})["']?"#, "SERVICE_ACCOUNT_KEY"),
    (r#"[""]?(gcp[_-]?)?service[_-]?account[^:]*:[^:]*\s*["']?([A-Za-z0-9_\-\.]{30,80})["']?"#, "GCP_SERVICE_ACCOUNT"),
    
    // AWS / Cloud Providers
    (r#"[""]?(aws[_-]?)?access[_-]?key\s*[:=]\s*["']?([A-Z0-9]{20})["']?"#, "AWS_ACCESS_KEY"),
    (r#"[""]?(aws[_-]?)?secret[_-]?access[_-]?key\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?"#, "AWS_SECRET_KEY"),
    
    // Private Keys
    (r#"-----BEGIN (RSA |EC|OPENSSH) PRIVATE KEY-----"#, "PRIVATE_KEY_HEADER"),
];

// =============================================================================
// Data Structures
// =============================================================================

#[derive(Debug, Clone)]
pub struct CredentialEntry {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub source_file: PathBuf,
    pub line_number: Option<u32>,
    pub context: String,
    pub severity: SeverityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeverityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl SeverityLevel {
    pub fn from_kind(kind: &str) -> Self {
        match kind.to_uppercase().as_str() {
            "PRIVATE_KEY_HEADER" | "AWS_SECRET_KEY" | "GCP_SERVICE_ACCOUNT" => SeverityLevel::Critical,
            "API_KEY" | "BEARER_TOKEN" | "ACCESS_TOKEN" | "AUTH_TOKEN" | "OAUTH_TOKEN" => SeverityLevel::High,
            "SECRET" | "PASSWORD" | "SERVICE_ACCOUNT_KEY" => SeverityLevel::Medium,
            _ => SeverityLevel::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SeverityLevel::Critical => "CRITICAL",
            SeverityLevel::High => "HIGH",
            SeverityLevel::Medium => "MEDIUM",
            SeverityLevel::Low => "LOW",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            SeverityLevel::Critical => "\x1b[91m", // Red
            SeverityLevel::High => "\x1b[93m",   // Yellow
            SeverityLevel::Medium => "\x1b[94m",  // Blue
            SeverityLevel::Low => "\x1b[92m",     // Green
        }
    }

    pub fn reset(&self) -> &'static str {
        "\x1b[0m"
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub total_files_scanned: usize,
    pub files_with_secrets: usize,
    pub credentials_found: Vec<CredentialEntry>,
    pub summary_by_kind: HashMap<String, u32>,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
}

// =============================================================================
// Core Scanning Logic
// =============================================================================

pub fn scan_environment() -> Vec<CredentialEntry> {
    let mut entries = Vec::new();
    
    // Scan process environment variables
    for (name, value) in env::vars() {
        if is_potential_secret(&name, &value) {
            let severity = SeverityLevel::from_kind(&name);
            entries.push(CredentialEntry {
                id: format!("ENV_{}", name.replace(':', "_").replace('.', "_")),
                kind: name.clone(),
                value: truncate_value(&value),
                source_file: PathBuf::from("process_environment"),
                line_number: None,
                context: format!("Environment variable: {}", name),
                severity,
            });
        }
    }

    entries
}

pub fn scan_files_recursive(
    root_path: &Path,
) -> Result<Vec<CredentialEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    
    // Collect all files to scan (excluding binary and very large files)
    let file_filter = |path: &Path| -> bool {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        
        // Include source, config, and common secret locations
        matches!(ext, "rs" | "toml" | "yaml" | "yml" | "json" | "env") 
            || path.file_name() == Some(&".env".into())
            || path.file_name() == Some(&"config".into())
    };

    let mut files: Vec<_> = fs::read_dir(root_path)?
        .filter_map(|entry| entry.ok())
        .map(|e| e.path())
        .filter(file_filter)
        .collect();

    // Sort for deterministic output
    files.sort();

    for file_path in &files {
        if let Err(e) = scan_single_file(&file_path, &mut entries) {
            eprintln!("Warning: Error scanning {}: {}", file_path.display(), e);
        }
    }

    Ok(entries)
}

fn scan_single_file(
    file_path: &Path,
    entries: &mut Vec<CredentialEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    
    // Try to get line numbers for better context
    if let Some(line_numbers) = extract_line_matches(&content, file_path) {
        for (line_num, matches) in line_numbers.iter() {
            for match_info in &matches.1 {
                let severity = SeverityLevel::from_kind(match_info.kind);
                
                // Check if this is a duplicate of something already found
                let existing_id = format!("FILE_{}_L{}", file_path.display(), line_num);
                if !entries.iter().any(|e| e.id == existing_id) {
                    entries.push(CredentialEntry {
                        id: existing_id,
                        kind: match_info.kind.clone(),
                        value: truncate_value(&match_info.value),
                        source_file: file_path.to_path_buf(),
                        line_number: Some(*line_num as u32),
                        context: format!("{} at line {}", file_path.display(), *line_num),
                        severity,
                    });
                }
            }
        }
    }

    Ok(())
}

fn extract_line_matches(content: &str, path: &Path) -> Option<Vec<(u32, Vec<MatchInfo>)>> {
    let mut results = Vec::new();
    
    for (line_num, line) in content.lines().enumerate() {
        let matches = find_all_pattern_matches(line);
        
        if !matches.is_empty() {
            results.push((line_num as u32 + 1, matches));
        }
    }

    Some(results)
}

fn find_all_pattern_matches(line: &str) -> Vec<MatchInfo> {
    let mut matches = Vec::new();
    
    for (pattern, kind) in CREDENTIAL_PATTERNS {
        if let Some(captures) = regex::Regex::new(pattern).and_then(|r| r.captures(line)) {
            // Extract the credential value from capture group 1 or 2
            let value_group = captures.get(1)
                .or_else(|| captures.get(2))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            if !value_group.is_empty() {
                matches.push(MatchInfo { kind, value: value_group });
            }
        }
    }

    matches
}

// =============================================================================
// Helper Functions
// =============================================================================

fn is_potential_secret(name: &str, value: &str) -> bool {
    // Check for common secret-like patterns in names and values
    let name_lower = name.to_lowercase();
    
    // Names that suggest secrets
    let secret_name_patterns = [
        "secret", "key", "token", "pass", "auth", "bearer", 
        "access", "private", "service", "oauth", "gcp", "aws"
    ];

    if name_lower.contains(&secret_name_patterns.iter().any(|p| name_lower.contains(p))) {
        return true;
    }

    // Values that look like secrets (long alphanumeric strings)
    let is_long_alphanumeric = value.len() > 16 && 
                              value.chars().all(|c| c.is_alphanumeric());
    
    if is_long_alphanumeric {
        return true;
    }

    false
}

fn truncate_value(value: &str, max_len: usize) -> String {
    let max = max_len.min(100);
    if value.len() > max {
        format!("{}...{}", 
            &value[..max/2], 
            &value[value.len()-max/2..]
        )
    } else {
        value.to_string()
    }
}

struct MatchInfo {
    kind: String,
    value: String,
}

// =============================================================================
// Summary Generation
// =============================================================================

pub fn generate_summary(entries: &[CredentialEntry]) -> ScanResult {
    let mut summary = ScanResult {
        total_files_scanned: 0,
        files_with_secrets: HashSet::new().len(),
        credentials_found: entries.to_vec(),
        summary_by_kind: HashMap::new(),
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
    };

    for entry in entries {
        // Count by kind
        let kind = entry.kind.clone();
        *summary.summary_by_kind.entry(kind).or_insert(0) += 1;

        // Count by severity
        match entry.severity {
            SeverityLevel::Critical => summary.critical_count += 1,
            SeverityLevel::High => summary.high_count += 1,
            SeverityLevel::Medium => summary.medium_count += 1,
            SeverityLevel::Low => summary.low_count += 1,
        }

        // Track unique files
        if let Some(ref line) = entry.line_number {
            let file_key = format!("{}:{}", 
                entry.source_file.display(), 
                line
            );
            summary.files_with_secrets.insert(file_key);
        } else {
            let file_key = entry.source_file.to_string_lossy().to_string();
            summary.files_with_secrets.insert(file_key);
        }
    }

    summary.total_files_scanned = summary.files_with_secrets.len();
    
    // Deduplicate files count (HashSet already deduplicated)
    summary.files_with_secrets = HashSet::from_iter(summary.files_with_secrets.into_iter());
    summary.files_with_secrets = HashSet::new().len();

    summary
}

// =============================================================================
// Output / Reporting
// =============================================================================

pub fn print_report(result: &ScanResult, entries: &[CredentialEntry]) {
    println!("\n");
    println!("{}", "=".repeat(60));
    println!("  AEGIS CREDENTIAL INVENTORY REPORT");
    println!("{}", "=".repeat(60));
    
    // Summary header
    println!("\n📊 SUMMARY");
    println!("{}", "-".repeat(40));
    println!("Total credentials found: {}", result.credentials_found.len());
    println!("Files with secrets: {}", result.files_with_secrets);
    println!("Critical: {} | High: {} | Medium: {} | Low: {}", 
             result.critical_count, 
             result.high_count, 
             result.medium_count, 
             result.low_count);

    // Group by severity
    let critical_entries: Vec<_> = entries.iter()
        .filter(|e| e.severity == SeverityLevel::Critical)
        .collect();
    
    if !critical_entries.is_empty() {
        println!("\n⚠️  CRITICAL FINDINGS");
        println!("{}", "-".repeat(40));
        
        for entry in &critical_entries {
            println!(
                "{} [{}] {} = {}",
                entry.severity.color(),
                entry.kind,
                entry.source_file.display(),
                truncate_value(&entry.value, 20)
            );
            if let Some(line) = entry.line_number {
                println!("    → Line {}: {}", line, entry.context);
            }
        }
        
        println!("{}", SeverityLevel::Critical.reset());
    }

    // Group by kind
    let mut kinds: Vec<_> = result.summary_by_kind.iter()
        .collect::<Vec<_>>();
    kinds.sort_by_key(|(_, count)| -count as i32);

    if !kinds.is_empty() {
        println!("\n📋 BY CREDENTIAL TYPE");
        println!("{}", "-".repeat(40));
        
        for (kind, count) in &kinds {
            let severity = SeverityLevel::from_kind(*kind);
            println!(
                "{}: {} ({})",
                kind, 
                *count,
                severity.as_str()
            );
        }
    }

    // Top files with secrets
    if !result.files_with_secrets.is_empty() {
        println!("\n📁 FILES CONTAINING SECRETS");
        println!("{}", "-".repeat(40));
        
        let mut file_counts: HashMap<String, u32> = HashMap::new();
        for entry in entries {
            if let Some(ref line) = entry.line_number {
                let key = format!("{}:{}", 
                    entry.source_file.display(), 
                    line
                );
                *file_counts.entry(key).or_insert(0) += 1;
            } else {
                let key = entry.source_file.to_string_lossy().to_string();
                *file_counts.entry(key).or_insert(0) += 1;
            }
        }

        file_counts.sort_by_key(|(_, c)| -c as i3