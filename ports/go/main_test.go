package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadDemo(t *testing.T, rel string) []map[string]interface{} {
	t.Helper()
	path := filepath.Join("..", "..", "demos", rel)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var data interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	agents, err := coerceAgents(data)
	if err != nil {
		t.Fatalf("coerce: %v", err)
	}
	return agents
}

func TestBasicDemoTrifecta(t *testing.T) {
	rep := audit(loadDemo(t, "01-basic/agents.json"))
	if rep.AgentsScanned != 4 {
		t.Fatalf("want 4 agents, got %d", rep.AgentsScanned)
	}
	if rep.WorstSeverity != "critical" {
		t.Fatalf("want worst=critical, got %s", rep.WorstSeverity)
	}
	byAgent := map[string][]Finding{}
	for _, f := range rep.Findings {
		byAgent[f.Agent] = append(byAgent[f.Agent], f)
	}
	if len(byAgent["support-bot"]) == 0 || byAgent["support-bot"][0].Severity != "critical" {
		t.Fatalf("support-bot should be critical trifecta")
	}
	if _, ok := byAgent["calculator"]; ok {
		t.Fatalf("calculator should be clean")
	}
	foundRCE := false
	for _, f := range byAgent["deploy-agent"] {
		if f.Title == "Untrusted input can reach code execution" {
			foundRCE = true
		}
	}
	if !foundRCE {
		t.Fatalf("deploy-agent should flag injection->RCE")
	}
}

func TestClassifyAxes(t *testing.T) {
	inj := classify(map[string]interface{}{"name": "web_fetch", "description": "fetch a url"})
	if len(inj["injection"]) == 0 {
		t.Fatalf("web_fetch should be injection")
	}
	cred := classify(map[string]interface{}{"name": "billing_db_query", "scopes": []interface{}{"read:db"}})
	if len(cred["credentials"]) == 0 {
		t.Fatalf("billing_db_query should be credentials")
	}
	reach := classify(map[string]interface{}{"name": "send_email", "scopes": []interface{}{"send:email"}})
	if len(reach["reach"]) == 0 {
		t.Fatalf("send_email should be reach")
	}
}

func TestCleanAgentNoFindings(t *testing.T) {
	rep := audit(loadDemo(t, "03-analytics-agent-clean/mcp.json"))
	if rep.FindingCount != 0 {
		t.Fatalf("clean agent should have 0 findings, got %d", rep.FindingCount)
	}
}
