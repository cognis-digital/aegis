// Smoke tests for the AEGIS JavaScript port. Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { auditFile, classifyCapability, coerceAgents, auditManifest } from "./index.js";

const here = dirname(fileURLToPath(import.meta.url));
const demo = (rel) => join(here, "..", "..", "demos", rel);

test("basic demo: 4 agents, critical worst", () => {
  const r = auditFile(demo("01-basic/agents.json"));
  assert.equal(r.agents_scanned, 4);
  assert.equal(r.worst_severity, "critical");
});

test("support-bot is a critical lethal trifecta", () => {
  const r = auditFile(demo("01-basic/agents.json"));
  const f = r.findings.find((x) => x.agent === "support-bot");
  assert.ok(f);
  assert.equal(f.severity, "critical");
  assert.deepEqual([...f.axes].sort(), ["credentials", "injection", "reach"]);
});

test("calculator produces no finding", () => {
  const r = auditFile(demo("01-basic/agents.json"));
  assert.ok(!r.findings.some((x) => x.agent === "calculator"));
});

test("deploy-agent flags injection -> RCE", () => {
  const r = auditFile(demo("01-basic/agents.json"));
  const f = r.findings.find(
    (x) => x.agent === "deploy-agent" && x.title.includes("code execution")
  );
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

test("summarizer is two-axis high", () => {
  const r = auditFile(demo("01-basic/agents.json"));
  const f = r.findings.find((x) => x.agent === "summarizer");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

test("classify axes", () => {
  assert.ok("injection" in classifyCapability({ name: "web_fetch", description: "fetch a url" }));
  assert.ok("credentials" in classifyCapability({ name: "billing_db_query", scopes: ["read:db"] }));
  assert.ok("reach" in classifyCapability({ name: "send_email", scopes: ["send:email"] }));
});

test("clean agent has no findings", () => {
  const r = auditFile(demo("03-analytics-agent-clean/mcp.json"));
  assert.equal(r.finding_count, 0);
});

test("coerceAgents accepts list, object, and {agents:[...]}", () => {
  assert.equal(coerceAgents([{ name: "a" }]).length, 1);
  assert.equal(coerceAgents({ name: "a" }).length, 1);
  assert.equal(coerceAgents({ agents: [{}, {}] }).length, 2);
  assert.throws(() => coerceAgents(42));
});

test("empty manifest is clean", () => {
  const r = auditManifest([]);
  assert.equal(r.finding_count, 0);
  assert.equal(r.worst_severity, null);
});
