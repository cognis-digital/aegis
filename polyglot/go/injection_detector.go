package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// InjectionDetector detects common injection patterns in input strings.
type InjectionDetector struct{}

// NewInjectionDetector creates a new instance of InjectionDetector.
func NewInjectionDetector() *InjectionDetector {
	return &InjectionDetector{}
}

// Detect checks if the input string contains any known injection patterns.
func (d *InjectionDetector) Detect(input string) bool {
	patterns := []string{
		"SELECT * FROM users WHERE id = ", // SQL injection
		"DROP TABLE",                       // SQL injection
		"UNION SELECT",                     // SQL injection
		"INSERT INTO",                      // SQL injection
		"EXEC sp_executesql N'",           // SQL injection
		"javascript:alert(",               // XSS
		"<script>",                         // XSS
		"onclick=alert(",                   // XSS
		"eval(",                            // JS injection
		"system('",                          // OS command injection
		"os.system(",                        // OS command injection
		"exec(",                            // OS command injection
		"$$(",                              // Shell injection
		"`",                                // Shell injection
		"$((",                              // Shell injection
		"\\x",                              // Hex injection
		"\\u",                              // Unicode injection
	}

	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}

// RunDemo runs a demo of the InjectionDetector.
func RunDemo() {
	detector := NewInjectionDetector()
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter input to check for injection patterns (type 'exit' to quit):")

	for scanner.Scan() {
		input := scanner.Text()
		if input == "exit" {
			break
		}
		if detector.Detect(input) {
			fmt.Printf("Injection detected in: %s\n", input)
		} else {
			fmt.Printf("No injection detected in: %s\n", input)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading input:", err)
	}
}

func main() {
	RunDemo()
}