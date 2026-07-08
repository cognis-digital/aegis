package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Credential represents a detected credential with its type and source
type Credential struct {
	Type   string
	Value  string
	Source string
}

// Scanner scans for credentials in text input
func ScanCredentials(input string) []Credential {
	var credentials []Credential

	lines := strings.Split(input, "\n")
	for _, line := range lines {
		if strings.Contains(line, "password=") {
			credentials = append(credentials, Credential{
				Type:   "password",
				Value:  extractValue(line, "password="),
				Source: "text",
			})
		} else if strings.Contains(line, "token=") {
			credentials = append(credentials, Credential{
				Type:   "token",
				Value:  extractValue(line, "token="),
				Source: "text",
			})
		} else if strings.Contains(line, "key=") {
			credentials = append(credentials, Credential{
				Type:   "key",
				Value:  extractValue(line, "key="),
				Source: "text",
			})
		}
	}

	return credentials
}

// extractValue extracts the value after the given prefix
func extractValue(line, prefix string) string {
	if idx := strings.Index(line, prefix); idx != -1 {
		value := line[idx+len(prefix):]
		if idx2 := strings.Index(value, " "); idx2 != -1 {
			return value[:idx2]
		}
		return value
	}
	return ""
}

// main function to run the credential scanner
func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter text to scan for credentials (type 'done' to finish):")

	var input strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		input.Write(line)
		if strings.TrimSpace(line) == "done" {
			break
		}
	}

	credentials := ScanCredentials(input.String())

	if len(credentials) > 0 {
		fmt.Println("\nDetected credentials:")
		for _, cred := range credentials {
			fmt.Printf("Type: %s, Value: %s, Source: %s\n", cred.Type, cred.Value, cred.Source)
		}
	} else {
		fmt.Println("No credentials detected.")
	}
}