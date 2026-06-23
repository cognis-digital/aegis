// AEGIS — Go port of the agent-manifest trifecta auditor.
//
// Mirrors the primary `aegis audit <manifest.json>` command from the Python
// reference: it loads an AI-agent manifest, classifies every capability along
// the three lethal-trifecta axes (credentials + injection + reach), and reports
// agents that hold all three (critical) or two of three (high). Pure stdlib,
// zero dependencies, single static binary.
//
// Usage:
//
//	go run . ../../demos/01-basic/agents.json
//	aegis-go --format json manifest.json
//
// Exit codes: 0 = clean, 1 = critical/high finding present, 2 = bad manifest.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var axes = []string{"credentials", "injection", "reach"}

var signatures = map[string][]string{
	"credentials": {
		"secret", "credential", "password", "token", "api_key", "apikey",
		"private_key", "privatekey", "ssh", "keychain", "vault", "env",
		"environ", "dotenv", ".env", "oauth", "access_key", "aws_", "gcp",
		"read_file", "readfile", "fs.read", "filesystem", "file_read",
		"database", "db_query", "sql", "private", "pii", "customer_data",
		"financial", "billing", "payment", "ssn", "cookie", "session",
	},
	"injection": {
		"web", "fetch", "http_get", "browse", "crawl", "scrape", "url",
		"email_read", "read_email", "inbox", "mail", "rss", "webhook",
		"untrusted", "user_input", "document", "pdf", "parse", "ingest",
		"search", "rag", "retrieve", "comment", "issue", "ticket",
		"slack_read", "channel", "message_read", "transcribe", "ocr",
	},
	"reach": {
		"send", "post", "http_post", "email_send", "send_email", "sendmail",
		"sms", "publish", "upload", "write_file", "writefile", "fs.write",
		"exec", "shell", "command", "subprocess", "deploy", "delete",
		"transfer", "payment_send", "wire", "purchase", "order", "webhook",
		"api_call", "external", "network", "dns", "socket", "git_push",
		"commit", "create_pr", "tweet", "dm", "call_tool",
	},
}

var explicitScope = map[string]string{
	"read:secrets": "credentials", "read:files": "credentials", "read:db": "credentials",
	"read:web": "injection", "read:email": "injection",
	"net:outbound": "reach", "write:files": "reach", "exec:shell": "reach", "send:email": "reach",
}

var execTokens = map[string]bool{"exec": true, "shell": true, "command": true, "subprocess": true, "deploy": true}

var normRe = regexp.MustCompile(`[^a-z0-9_.: ]+`)

// Finding mirrors the Python AuditReport finding shape.
type Finding struct {
	Agent        string              `json:"agent"`
	Severity     string              `json:"severity"`
	Axes         []string            `json:"axes"`
	Title        string              `json:"title"`
	Detail       string              `json:"detail"`
	Capabilities map[string][]string `json:"capabilities"`
}

type Report struct {
	AgentsScanned int       `json:"agents_scanned"`
	FindingCount  int       `json:"finding_count"`
	WorstSeverity string    `json:"worst_severity"`
	Findings      []Finding `json:"findings"`
}

func normalize(parts ...interface{}) string {
	var chunks []string
	var add func(v interface{})
	add = func(v interface{}) {
		switch t := v.(type) {
		case nil:
		case string:
			chunks = append(chunks, t)
		case []interface{}:
			for _, e := range t {
				add(e)
			}
		case map[string]interface{}:
			for k, val := range t {
				chunks = append(chunks, fmt.Sprintf("%s %v", k, val))
			}
		default:
			chunks = append(chunks, fmt.Sprintf("%v", t))
		}
	}
	for _, p := range parts {
		add(p)
	}
	s := strings.ToLower(strings.Join(chunks, " "))
	return normRe.ReplaceAllString(s, " ")
}

func classify(cap map[string]interface{}) map[string][]string {
	matched := map[string][]string{}
	hay := normalize(cap["name"], cap["tool"], cap["description"], cap["scopes"], cap["permissions"])

	if scopes, ok := cap["scopes"].([]interface{}); ok {
		for _, s := range scopes {
			key := strings.ToLower(fmt.Sprintf("%v", s))
			if axis, ok := explicitScope[key]; ok {
				matched[axis] = appendUnique(matched[axis], key)
			}
		}
	}
	for _, axis := range axes {
		for _, tok := range signatures[axis] {
			if strings.Contains(hay, tok) {
				matched[axis] = appendUnique(matched[axis], tok)
			}
		}
	}
	return matched
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

func capabilitiesOf(agent map[string]interface{}) []map[string]interface{} {
	var raw interface{}
	for _, key := range []string{"capabilities", "tools", "permissions"} {
		if v, ok := agent[key]; ok && v != nil {
			raw = v
			break
		}
	}
	var out []map[string]interface{}
	if list, ok := raw.([]interface{}); ok {
		for _, c := range list {
			switch t := c.(type) {
			case string:
				out = append(out, map[string]interface{}{"name": t})
			case map[string]interface{}:
				out = append(out, t)
			}
		}
	}
	return out
}

func coerceAgents(data interface{}) ([]map[string]interface{}, error) {
	switch t := data.(type) {
	case map[string]interface{}:
		if a, ok := t["agents"]; ok {
			if list, ok := a.([]interface{}); ok {
				return toAgentList(list), nil
			}
			return nil, fmt.Errorf("'agents' must be a list")
		}
		return []map[string]interface{}{t}, nil
	case []interface{}:
		return toAgentList(t), nil
	}
	return nil, fmt.Errorf("manifest must be an object or a list of agents")
}

func toAgentList(list []interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, a := range list {
		if m, ok := a.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func hasExec(reach []string) bool {
	for _, e := range reach {
		if execTokens[e] {
			return true
		}
	}
	return false
}

var sevRank = map[string]int{"critical": 3, "high": 2, "medium": 1, "low": 0}

func audit(agents []map[string]interface{}) Report {
	rep := Report{}
	for _, agent := range agents {
		rep.AgentsScanned++
		name := firstString(agent, "name", "id")
		if name == "" {
			name = "unnamed-agent"
		}
		axisCaps := map[string]map[string][]string{}
		for _, a := range axes {
			axisCaps[a] = map[string][]string{}
		}
		for _, cap := range capabilitiesOf(agent) {
			capName := firstString(cap, "name", "tool")
			if capName == "" {
				capName = "unnamed-tool"
			}
			for axis, ev := range classify(cap) {
				axisCaps[axis][capName] = ev
			}
		}
		var present []string
		for _, a := range axes {
			if len(axisCaps[a]) > 0 {
				present = append(present, a)
			}
		}
		caps := func(sel []string) map[string][]string {
			out := map[string][]string{}
			for _, a := range sel {
				for k := range axisCaps[a] {
					out[a] = append(out[a], k)
				}
				sort.Strings(out[a])
			}
			return out
		}
		switch len(present) {
		case 3:
			rep.Findings = append(rep.Findings, Finding{
				Agent: name, Severity: "critical", Axes: present,
				Title:        "Lethal trifecta: credentials + injection + reach",
				Detail:       "Access to sensitive data + untrusted input + external reach: one prompt injection exfiltrates end-to-end. Remove one axis.",
				Capabilities: caps(present),
			})
		case 2:
			var missing []string
			for _, a := range axes {
				if !contains(present, a) {
					missing = append(missing, a)
				}
			}
			rep.Findings = append(rep.Findings, Finding{
				Agent: name, Severity: "high", Axes: present,
				Title:        "Two of three trifecta axes present",
				Detail:       "One capability away from the lethal trifecta. Missing: " + strings.Join(missing, ", "),
				Capabilities: caps(present),
			})
		}
		var reachEv []string
		for _, ev := range axisCaps["reach"] {
			reachEv = append(reachEv, ev...)
		}
		if len(axisCaps["injection"]) > 0 && hasExec(reachEv) {
			rep.Findings = append(rep.Findings, Finding{
				Agent: name, Severity: "critical", Axes: []string{"injection", "reach"},
				Title:        "Untrusted input can reach code execution",
				Detail:       "Agent ingests untrusted content and holds a shell/exec/deploy capability. Injection -> RCE. Require human approval on execution tools.",
				Capabilities: caps([]string{"injection", "reach"}),
			})
		}
	}
	rep.FindingCount = len(rep.Findings)
	worst := ""
	for _, f := range rep.Findings {
		if worst == "" || sevRank[f.Severity] > sevRank[worst] {
			worst = f.Severity
		}
	}
	rep.WorstSeverity = worst
	return rep
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

func main() {
	format := "table"
	var path string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json" || a == "--format=json":
			format = "json"
		case a == "--format":
			if i+1 < len(args) {
				i++
				if args[i] == "json" {
					format = "json"
				}
			}
		case !strings.HasPrefix(a, "--"):
			path = a
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: aegis-go [--format json] <manifest.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: manifest not found: %s\n", path)
		os.Exit(2)
	}
	var data interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		fmt.Fprintf(os.Stderr, "aegis: invalid manifest: %v\n", err)
		os.Exit(2)
	}
	agents, err := coerceAgents(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: invalid manifest: %v\n", err)
		os.Exit(2)
	}
	rep := audit(agents)

	if format == "json" {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("AEGIS audit | agents: %d | findings: %d | worst: %s\n",
			rep.AgentsScanned, rep.FindingCount, orNone(rep.WorstSeverity))
		for _, f := range rep.Findings {
			fmt.Printf("[%-8s] %s: %s\n", strings.ToUpper(f.Severity), f.Agent, f.Title)
		}
	}
	if rep.WorstSeverity == "critical" || rep.WorstSeverity == "high" {
		os.Exit(1)
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
