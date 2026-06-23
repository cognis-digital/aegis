#!/usr/bin/env node
// AEGIS — JavaScript/Node port of the agent-manifest trifecta auditor.
//
// Mirrors the primary `aegis audit <manifest.json>` command: load an AI-agent
// manifest, classify every capability along the three lethal-trifecta axes
// (credentials + injection + reach), and report agents holding all three
// (critical) or two of three (high). Zero dependencies — Node stdlib only.
//
//   node index.js ../../demos/01-basic/agents.json
//   node index.js --format json manifest.json
//
// Exit: 0 clean · 1 critical/high finding · 2 bad manifest.
import { readFileSync } from "fs";

export const AXES = ["credentials", "injection", "reach"];

const SIGNATURES = {
  credentials: [
    "secret", "credential", "password", "token", "api_key", "apikey",
    "private_key", "privatekey", "ssh", "keychain", "vault", "env",
    "environ", "dotenv", ".env", "oauth", "access_key", "aws_", "gcp",
    "read_file", "readfile", "fs.read", "filesystem", "file_read",
    "database", "db_query", "sql", "private", "pii", "customer_data",
    "financial", "billing", "payment", "ssn", "cookie", "session",
  ],
  injection: [
    "web", "fetch", "http_get", "browse", "crawl", "scrape", "url",
    "email_read", "read_email", "inbox", "mail", "rss", "webhook",
    "untrusted", "user_input", "document", "pdf", "parse", "ingest",
    "search", "rag", "retrieve", "comment", "issue", "ticket",
    "slack_read", "channel", "message_read", "transcribe", "ocr",
  ],
  reach: [
    "send", "post", "http_post", "email_send", "send_email", "sendmail",
    "sms", "publish", "upload", "write_file", "writefile", "fs.write",
    "exec", "shell", "command", "subprocess", "deploy", "delete",
    "transfer", "payment_send", "wire", "purchase", "order", "webhook",
    "api_call", "external", "network", "dns", "socket", "git_push",
    "commit", "create_pr", "tweet", "dm", "call_tool",
  ],
};

const EXPLICIT_SCOPE = {
  "read:secrets": "credentials", "read:files": "credentials", "read:db": "credentials",
  "read:web": "injection", "read:email": "injection",
  "net:outbound": "reach", "write:files": "reach", "exec:shell": "reach", "send:email": "reach",
};

const EXEC_TOKENS = new Set(["exec", "shell", "command", "subprocess", "deploy"]);
const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

function normalize(...parts) {
  const chunks = [];
  const add = (v) => {
    if (v === null || v === undefined) return;
    if (Array.isArray(v)) v.forEach(add);
    else if (typeof v === "object") for (const [k, val] of Object.entries(v)) chunks.push(`${k} ${val}`);
    else chunks.push(String(v));
  };
  parts.forEach(add);
  return chunks.join(" ").toLowerCase().replace(/[^a-z0-9_.: ]+/g, " ");
}

export function classifyCapability(cap) {
  const matched = {};
  const hay = normalize(cap.name, cap.tool, cap.description, cap.scopes, cap.permissions);
  for (const scope of cap.scopes || []) {
    const key = String(scope).toLowerCase();
    const axis = EXPLICIT_SCOPE[key];
    if (axis) {
      matched[axis] ||= [];
      if (!matched[axis].includes(key)) matched[axis].push(key);
    }
  }
  for (const axis of AXES) {
    for (const tok of SIGNATURES[axis]) {
      if (hay.includes(tok)) {
        matched[axis] ||= [];
        if (!matched[axis].includes(tok)) matched[axis].push(tok);
      }
    }
  }
  return matched;
}

function capabilitiesOf(agent) {
  let raw = agent.capabilities || agent.tools || agent.permissions || [];
  // Mirror Python: iterating a dict yields its keys (treated as string caps).
  if (raw && typeof raw === "object" && !Array.isArray(raw)) raw = Object.keys(raw);
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const c of raw) {
    if (typeof c === "string") out.push({ name: c });
    else if (c && typeof c === "object") out.push(c);
  }
  return out;
}

export function coerceAgents(data) {
  if (data && typeof data === "object" && !Array.isArray(data) && "agents" in data) {
    if (!Array.isArray(data.agents)) throw new Error("'agents' must be a list");
    return data.agents;
  }
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object") return [data];
  throw new Error("manifest must be an object or a list of agents");
}

function hasExec(reachCaps) {
  return Object.values(reachCaps).some((ev) => ev.some((t) => EXEC_TOKENS.has(t)));
}

export function auditManifest(agents) {
  const findings = [];
  for (const agent of agents) {
    const name = agent.name || agent.id || "unnamed-agent";
    const axisCaps = { credentials: {}, injection: {}, reach: {} };
    for (const cap of capabilitiesOf(agent)) {
      const capName = cap.name || cap.tool || "unnamed-tool";
      for (const [axis, ev] of Object.entries(classifyCapability(cap))) {
        axisCaps[axis][capName] = ev;
      }
    }
    const present = AXES.filter((a) => Object.keys(axisCaps[a]).length > 0);
    const capsOf = (sel) => Object.fromEntries(sel.map((a) => [a, Object.keys(axisCaps[a]).sort()]));
    if (present.length === 3) {
      findings.push({
        agent: name, severity: "critical", axes: present,
        title: "Lethal trifecta: credentials + injection + reach",
        detail: "Sensitive data + untrusted input + external reach: one prompt injection exfiltrates end-to-end. Remove one axis.",
        capabilities: capsOf(present),
      });
    } else if (present.length === 2) {
      const missing = AXES.filter((a) => !present.includes(a));
      findings.push({
        agent: name, severity: "high", axes: present,
        title: "Two of three trifecta axes present",
        detail: `One capability away from the lethal trifecta. Missing: ${missing.join(", ")}`,
        capabilities: capsOf(present),
      });
    }
    if (Object.keys(axisCaps.injection).length && hasExec(axisCaps.reach)) {
      findings.push({
        agent: name, severity: "critical", axes: ["injection", "reach"],
        title: "Untrusted input can reach code execution",
        detail: "Agent ingests untrusted content and holds a shell/exec/deploy capability. Injection -> RCE.",
        capabilities: capsOf(["injection", "reach"]),
      });
    }
  }
  let worst = null;
  for (const f of findings) {
    if (worst === null || SEV_RANK[f.severity] > SEV_RANK[worst]) worst = f.severity;
  }
  return { agents_scanned: agents.length, finding_count: findings.length, worst_severity: worst, findings };
}

export function auditFile(path) {
  return auditManifest(coerceAgents(JSON.parse(readFileSync(path, "utf8"))));
}

function main(argv) {
  let format = "table";
  let path = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json" || a === "--format=json") format = "json";
    else if (a === "--format") { if (argv[++i] === "json") format = "json"; }
    else if (!a.startsWith("--")) path = a;
  }
  if (!path) { console.error("usage: aegis [--format json] <manifest.json>"); return 2; }
  let report;
  try {
    report = auditFile(path);
  } catch (e) {
    if (e.code === "ENOENT") console.error(`aegis: manifest not found: ${path}`);
    else console.error(`aegis: invalid manifest: ${e.message}`);
    return 2;
  }
  if (format === "json") {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`AEGIS audit | agents: ${report.agents_scanned} | findings: ${report.finding_count} | worst: ${report.worst_severity || "none"}`);
    for (const f of report.findings) console.log(`[${f.severity.toUpperCase().padEnd(8)}] ${f.agent}: ${f.title}`);
  }
  return ["critical", "high"].includes(report.worst_severity) ? 1 : 0;
}

const invoked = process.argv[1] && process.argv[1].endsWith("index.js");
if (invoked) {
  process.exit(main(process.argv.slice(2)));
}
