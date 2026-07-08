// polyglot/typescript/injection_detector.ts

import { Aegis } from './aegis';

/**
 * InjectionDetector class for identifying potential injection vulnerabilities.
 */
class InjectionDetector {
  private aegis: Aegis;

  constructor(aegis: Aegis) {
    this.aegis = aegis;
  }

  /**
   * Detects common injection vulnerabilities in the given input.
   * @param input - The input string to be scanned.
   * @returns An array of detected injection types and their details.
   */
  detect(input: string): { type: string; detail: string }[] {
    const results: { type: string; detail: string }[] = [];

    // SQL Injection patterns
    if (/\b(SELECT|UPDATE|DELETE|INSERT|DROP|ALTER)\b/.test(input)) {
      results.push({ type: 'SQL Injection', detail: 'Potential SQL injection detected.' });
    }

    // XSS patterns
    if (/(<script>.*?<\/script>|<img.*?src=[\"\'].*?[\"\'].*?>)/i.test(input)) {
      results.push({ type: 'XSS', detail: 'Potential XSS injection detected.' });
    }

    // Command Injection patterns
    if (/(\|\s*|&&\s*|;\s*|`.*?`|$(.*?)$|`.*?`)/.test(input)) {
      results.push({ type: 'Command Injection', detail: 'Potential command injection detected.' });
    }

    // LDAP Injection patterns
    if (/\b(AND|OR)\s*(\w+=|=\s*\w+|\d+|\"[^\"]*\"|'[^']*')/.test(input)) {
      results.push({ type: 'LDAP Injection', detail: 'Potential LDAP injection detected.' });
    }

    // Regular Expression Injection patterns
    if (/\/.*?\/.*?([gimy]*)/.test(input)) {
      results.push({ type: 'Regex Injection', detail: 'Potential regex injection detected.' });
    }

    return results;
  }
}

// Example usage
const aegis = new Aegis();
const detector = new InjectionDetector(aegis);

// Demo input for testing
const testInputs = [
  "SELECT * FROM users WHERE id = '1'; DROP TABLE users;",
  "<script>alert('XSS');</script>",
  "echo 'Hello $USER'; rm -rf /",
  "(&(name=John)(age>=30))",
  "/^[a-zA-Z0-9]+$/"
];

console.log("Injection Detection Results:");
testInputs.forEach((input, index) => {
  console.log(`\nTest Input ${index + 1}: ${input}`);
  const results = detector.detect(input);
  if (results.length > 0) {
    console.log('Detected Vulnerabilities:');
    results.forEach(result => {
      console.log(`- ${result.type}: ${result.detail}`);
    });
  } else {
    console.log('No vulnerabilities detected.');
  }
});