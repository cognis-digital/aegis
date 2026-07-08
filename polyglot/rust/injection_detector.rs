use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone)]
pub enum InjectionType {
    SQL,
    XSS,
    CommandInjection,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct InjectionDetector {
    known_patterns: HashMap<InjectionType, HashSet<String>>,
}

impl InjectionDetector {
    pub fn new() -> Self {
        let mut known_patterns = HashMap::new();

        // SQL injection patterns
        let sql_patterns = vec![
            "SELECT.*WHERE.*=.*'",         // Basic SQL query with single quote
            "INSERT INTO.*VALUES.*'",      // Insert values with single quote
            "UPDATE.*SET.*='",             // Update with single quote
            "DELETE FROM.*WHERE.*='",      // Delete with single quote
            "OR 1=1",                      // Common SQL injection condition
            "UNION SELECT",                // Union-based injection
            "DROP TABLE",                  // Table dropping
            "EXEC",                        // Executing commands
            "--",                          // Commenting out SQL
            "/*",                          // Multi-line comment
            "' OR '1'='1",                 // Classic SQLi payload
        ];
        known_patterns.insert(InjectionType::SQL, sql_patterns.into_iter().map(String::from).collect());

        // XSS injection patterns
        let xss_patterns = vec![
            "<script>",                    // Script tag
            "</script>",                   // Closing script tag
            "alert(",                      // Alert payload
            "document.write(",             // Document write
            "eval(",                       // Eval function
            "onerror=",                    // Onerror attribute
            "onclick=",                    // Click handler
            "onload=",                     // Load handler
            "onsubmit=",                   // Submit handler
            "javascript:",                // JavaScript protocol
        ];
        known_patterns.insert(InjectionType::XSS, xss_patterns.into_iter().map(String::from).collect());

        // Command injection patterns
        let command_injection_patterns = vec![
            ";",                           // Semicolon for command separation
            "|",                           // Pipe for command chaining
            "&",                           // Ampersand for background execution
            "&&",                          // Logical AND
            "||",                          // Logical OR
            "`",                           // Backticks for command substitution
            "exec",                        // Exec command
            "system",                      // System call
            "sh -c",                       // Shell command
        ];
        known_patterns.insert(InjectionType::CommandInjection, command_injection_patterns.into_iter().map(String::from).collect());

        InjectionDetector { known_patterns }
    }

    pub fn detect_injections(&self, input: &str) -> Vec<(InjectionType, String)> {
        let mut results = Vec::new();

        for (injection_type, patterns) in &self.known_patterns {
            for pattern in patterns {
                if input.contains(pattern) {
                    results.push((injection_type.clone(), pattern.to_string()));
                }
            }
        }

        results
    }
}

impl fmt::Display for InjectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectionType::SQL => write!(f, "SQL Injection"),
            InjectionType::XSS => write!(f, "XSS Injection"),
            InjectionType::CommandInjection => write!(f, "Command Injection"),
            InjectionType::Other(s) => write!(f, "Other Injection: {}", s),
        }
    }
}

fn main() {
    let detector = InjectionDetector::new();

    let test_input = r#"
        SELECT * FROM users WHERE id = '1' OR '1'='1';
        <script>alert('XSS');</script>
        echo "Hello; rm -rf /";
    "#;

    let results = detector.detect_injections(test_input);

    if results.is_empty() {
        println!("No injections detected.");
    } else {
        println!("Injections detected:");
        for (injection_type, pattern) in results {
            println!("  {}: {}", injection_type, pattern);
        }
    }
}