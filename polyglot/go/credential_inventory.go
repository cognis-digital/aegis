package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Data Models
// ============================================================================

type Credential struct {
	Type       string    `json:"type"`
	Source     string    `json:"source"`
	Path       string    `json:"path,omitempty"`
	Key        string    `json:"key,omitempty"`
	Value      string    `json:"value,omitempty"`
	Masked     bool      `json:"masked"`
	CreatedAt  time.Time `json:"created_at"`
	Confidence float64   `json:"confidence"` // 0.0 - 1.0, how sure we are this is a real credential
}

type InventoryResult struct {
	Total         int              `json:"total"`
	ByType        map[string][]Credential `json:"by_type"`
	HighRisk      []Credential     `json:"high_risk"`
	Summary       string           `json:"summary"`
	ScannedAt     time.Time        `json:"scanned_at"`
}

type Scanner interface {
	Name() string
	Scan(ctx context.Context) ([]Credential, error)
}

// ============================================================================
// Scanners - Real implementations
// ============================================================================

// EnvScanner finds credentials in environment variables.
type EnvScanner struct{}

func (EnvScanner) Name() string { return "Environment Variables" }

var envPatterns = []string{
	"AWS_SECRET_ACCESS_KEY",
	"AWS_ACCESS_KEY_ID",
	"GCP_SERVICE_ACCOUNT_JSON",
	"GCP_APPLICATION_CREDENTIALS",
	"DB_PASSWORD",
	"DATABASE_PASSWORD",
	"MYSQL_ROOT_PASSWORD",
	"POSTGRES_PASSWORD",
	"REDIS_PASSWORD",
	"JWT_SECRET",
	"API_KEY",
	"API_SECRET",
	"CLOUDFLARE_API_TOKEN",
	"STRIPE_SECRET_KEY",
	"SENDGRID_API_KEY",
	"TWILIO_AUTH_TOKEN",
}

func (s EnvScanner) Scan(ctx context.Context) ([]Credential, error) {
	var found []Credential
	
	for _, name := range envPatterns {
		if val := os.Getenv(name); val != "" {
			found = append(found, Credential{
				Type:       "Environment Variable",
				Source:     "OS Environment",
				Key:        name,
				Value:      maskValue(val),
				Masked:     true,
				CreatedAt:  time.Now(),
				Confidence: 0.95,
			})
		}
	}
	
	// Also check for any env var containing "SECRET", "PASSWORD", "TOKEN"
	for _, name := range os.Environ() {
		lowerName := strings.ToLower(name)
		if !strings.Contains(lowerName, "secret") && 
		   !strings.Contains(lowerName, "password") && 
		   !strings.Contains(lowerName, "token") &&
		   !strings.Contains(lowerName, "key") &&
		   !strings.Contains(lowerName, "auth") {
			continue
		}
		
		parts := strings.SplitN(name, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		val := parts[1]
		if val == "" || len(val) < 8 {
			continue
		}
		
		found = append(found, Credential{
			Type:       "Environment Variable (Generic)",
			Source:     "OS Environment",
			Key:        name,
			Value:      maskValue(val),
			Masked:     true,
			CreatedAt:  time.Now(),
			Confidence: 0.75,
		})
	}
	
	return found, nil
}

// ConfigFileScanner finds credentials in configuration files.
type ConfigFileScanner struct {
	Dirs []string
}

func (s *ConfigFileScanner) Name() string { return "Configuration Files" }

func (s *ConfigFileScanner) Scan(ctx context.Context) ([]Credential, error) {
	var found []Credential
	
	// Default directories to scan if none specified
	if len(s.Dirs) == 0 {
		s.Dirs = []string{
			".",
			"/etc",
			"/var/lib",
			"/opt",
			"~/.config",
			"~/Library/Application Support",
		}
	}
	
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	for _, dir := range s.Dirs {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(os.Getenv("HOME"), dir)
		}
		
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			
			if !d.IsDir() {
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".json" || ext == ".yaml" || ext == ".yml" || 
				   ext == ".toml" || ext == ".ini" || ext == ".conf" {
					
					wg.Add(1)
					go func(p string, d fs.DirEntry) {
						defer wg.Done()
						creds, err := s.scanFile(ctx, p, d)
						if err != nil {
							return
						}
						found = append(found, creds...)
					}(path, d)
				}
			}
			
			return nil
		})
		
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: scanning %s failed: %v\n", dir, err)
		}
	}
	
	wg.Wait()
	return found, nil
}

func (s *ConfigFileScanner) scanFile(ctx context.Context, path string, d fs.DirEntry) ([]Credential, error) {
	var creds []Credential
	
	data, err := os.ReadFile(path)
	if err != nil {
		return creds, err
	}
	
	content := string(data)
	
	// Check for common credential patterns in raw content
	patterns := []struct{
		name    string
		pattern *regexp.Regexp
		key     string
	}{
		{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "value"},
		{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*["']?([a-zA-Z0-9_\-\.]+)`)},
		{"Secret Token", regexp.MustCompile(`(?i)(secret[_-]?token|secrets)[\s=:]+"?([^"\n\r]{20,})`), "value"},
		{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.]+)`), "value"},
		{"Private Key Header", regexp.MustCompile(`-----BEGIN (RSA |EC|OPENSSH )?PRIVATE KEY-----`), "key"},
	}
	
	for _, p := range patterns {
		matches := p.pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 3 && match[2] != "" {
				creds = append(creds, Credential{
					Type:       "Configuration File",
					Source:     path,
					Key:        p.name,
					Value:      maskValue(match[2]),
					Masked:     true,
					CreatedAt:  time.Now(),
					Confidence: 0.85,
				})
			}
		}
	}
	
	return creds, nil
}

// ProcessMemoryScanner finds credentials in running processes (Linux).
type ProcessMemoryScanner struct{}

func (s ProcessMemoryScanner) Name() string { return "Process Memory" }

func (s ProcessMemoryScanner) Scan(ctx context.Context) ([]Credential, error) {
	var found []Credential
	
	procDir := "/proc"
	if !filepath.IsAbs(procDir) {
		procDir = filepath.Join(os.Getenv("HOME"), procDir)
	}
	
	files, err := os.ReadDir(procDir)
	if err != nil {
		return found, nil // Not Linux or permission denied
	}
	
	for _, f := range files {
		if !f.IsDir() || !strings.HasPrefix(f.Name(), "proc") {
			continue
		}
		
		pid, _ := strconv.Atoi(f.Name())
		
		// Try to read /proc/<pid>/environ
		environPath := filepath.Join(procDir, f.Name(), "environ")
		data, err := os.ReadFile(environPath)
		if err == nil {
			lines := strings.Split(string(data), "\x00")
			for _, line := range lines {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 && 
				   (strings.Contains(strings.ToLower(parts[1]), "secret") ||
				    strings.Contains(strings.ToLower(parts[1]), "password") ||
				    strings.Contains(strings.ToLower(parts[1]), "token")) {
					
					found = append(found, Credential{
						Type:       "Process Memory",
						Source:     fmt.Sprintf("/proc/%d/environ", pid),
						Key:        parts[0],
						Value:      maskValue(parts[1]),
						Masked:     true,
						CreatedAt:  time.Now(),
						Confidence: 0.80,
					})
				}
			}
		}
		
		// Try to read /proc/<pid>/mem for private keys (Linux)
		memPath := filepath.Join(procDir, f.Name(), "mem")
		if data, err := os.ReadFile(memPath); err == nil {
			content := string(data)
			
			// Look for PEM headers in memory
			if bytes.Contains([]byte(content), []byte("-----BEGIN RSA PRIVATE KEY-----")) ||
			   bytes.Contains([]byte(content), []byte("-----BEGIN EC PRIVATE KEY-----")) {
				
				found = append(found, Credential{
					Type:       "Process Memory",
					Source:     fmt.Sprintf("/proc/%d/mem", pid),
					Key:        "Private Key in Process Memory",
					Value:      maskValue(string(content[:min(100, len(content))])),
					Masked:     true,
					CreatedAt:  time.Now(),
					Confidence: 0.95,
				})
			}
		}
	}
	
	return found, nil
}

// ============================================================================
// Utility Functions
// ============================================================================

func maskValue(v string) string {
	if len(v) <= 8 {
		return v
	}
	return v[:4] + "•" + strings.Repeat("•", 2) + v[len(v)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Risk Assessment
// ============================================================================

type RiskLevel string

const (
	RiskLow    RiskLevel = "LOW"
	RiskMedium RiskLevel = "MEDIUM" 
	RiskHigh   RiskLevel = "HIGH"
)

func AssessRisk(cred Credential) RiskLevel {
	if cred.Confidence < 0.7 {
		return RiskLow
	}
	
	riskScore := 1.0
	
	// Higher risk for certain types
	switch strings.ToLower(cred.Type) {
	case "process memory":
		riskScore += 0.3
	case "configuration file":
		if strings.Contains(strings.ToLower(cred.Source), "/etc") ||
		   strings.Contains(strings.ToLower(cred.Source), "/var/lib") {
			riskScore += 0.2
		}
	}
	
	// Higher risk for certain keys
	lowerKey := strings.ToLower(cred.Key)
	if strings.Contains(lowerKey, "root") || 
	   strings.Contains(lowerKey, "admin") ||
	   strings.Contains(lowerKey, "master") {
		riskScore += 0.2
	}
	
	if riskScore >= 1.5 {
		return RiskHigh
	} else if riskScore >= 1.0 {
		return RiskMedium
	}
	return RiskLow
}

// ============================================================================
// Report Generation
// ============================================================================

func (r *InventoryResult) GenerateSummary() string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("Scanned at %s\n", r.ScannedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Total credentials found: %d\n", r.Total))
	
	if len(r.HighRisk) > 0 {
		sb.WriteString(fmt.Sprintf("HIGH RISK items: %d\n", len(r.HighRisk)))
		
		for _, c := range r.HighRisk[:5] { // Limit to first 5
			sb.WriteString(fmt.Sprintf("  - [%s] %s = %s\n", 
				c.Type, c.Key, maskValue(c.Value)))
		}
	}
	
	return sb.String()
}

func (r *InventoryResult) MarshalJSON() ([]byte, error) {
	type Alias InventoryResult
	return json.Marshal(&struct {
		Summary string `json:"summary"`
		*Alias
	}{
		Summary: r.GenerateSummary(),
		Alias:   (*Alias)(r),
	})
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	fmt.Println("=== AEGIS Credential Inventory ===")
	fmt.Printf("Started at %s\n\n", time.Now().Format(time.RFC3339))
	
	ctx := context.Background()
	
	// Create scanner with default directories
	scanner := &ConfigFileScanner{
		Dirs: []string{"."}, // Start in current directory
	}
	
	// Run all scanners
	envCreds, err := EnvScanner{}.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Env scan error: %v\n", err)
	} else {
		fmt.Printf("Environment variables: found %d items\n", len(envCreds))
		for _, c := range envCreds[:3] { // Show first 3
			fmt.Printf("  - %s = %s\n", c.Key, maskValue(c.Value))
		}
		if len(envCreds) > 3 {
			fmt.Println("    ... and more")
		}
	}
	
	configCreds, err := scanner.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config scan error: %v\n", err)
	} else {
		fmt.Printf("Configuration files: found %d items\n", len(configCreds))
		for _, c := range configCreds[:3] {
			fmt.Printf("  - [%s] in %s = %s\n", 
				c.Type, filepath.Base(c.Source), maskValue(c.Value))
		}
		if len(configCreds) > 3 {
			fmt.Println("    ... and more")
		}
	}
	
	memCreds, err := ProcessMemoryScanner{}.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Memory scan error: %v\n", err)
	} else {
		fmt.Printf("Process memory: found %d items\n", len(memCreds))
		for _, c := range memCreds[:3] {
			risk := AssessRisk(c)
			fmt.Printf("  - [%s] (risk: %s) = %s\n", 
				c.Type, risk, maskValue(c.Value))
		}
		if len(memCreds) > 3 {
			fmt.Println("    ... and more")
		}
	}
	
	// Compile results
	total := len(envCreds) + len(configCreds) + len(memCreds)
	var highRisk []Credential
	
	for _, c := range envCreds {
		if AssessRisk(c) == RiskHigh {
			highRisk = append(highRisk, c)
		}
	}
	for _, c := range config