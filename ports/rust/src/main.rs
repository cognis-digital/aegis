// AEGIS — Rust port of the agent-manifest trifecta auditor.
//
// Mirrors the primary `aegis audit <manifest.json>` command: load an AI-agent
// manifest, classify every capability along the three lethal-trifecta axes
// (credentials + injection + reach), and report agents holding all three
// (critical) or two of three (high). Zero external crates — includes a tiny
// stdlib-only JSON parser so it builds as a single static binary anywhere.
//
// Usage:   aegis ../../demos/01-basic/agents.json
//          aegis --format json manifest.json
// Exit:    0 clean · 1 critical/high finding · 2 bad manifest.

use std::collections::BTreeMap;
use std::{env, fs, process};

// ── Minimal JSON value + parser (object/array/string/number/bool/null) ───────
#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

struct Parser {
    b: Vec<char>,
    i: usize,
}

impl Parser {
    fn new(s: &str) -> Self {
        Parser { b: s.chars().collect(), i: 0 }
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_whitespace() {
            self.i += 1;
        }
    }
    fn parse(&mut self) -> Result<Json, String> {
        self.ws();
        let v = self.value()?;
        self.ws();
        Ok(v)
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.b.get(self.i) {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') | Some('f') => self.boolean(),
            Some('n') => self.null(),
            Some(c) if *c == '-' || c.is_ascii_digit() => self.number(),
            _ => Err("unexpected token".into()),
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1; // {
        let mut m = BTreeMap::new();
        self.ws();
        if self.b.get(self.i) == Some(&'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&':') {
                return Err("expected ':'".into());
            }
            self.i += 1;
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.b.get(self.i) {
                Some(',') => self.i += 1,
                Some('}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected ',' or '}'".into()),
            }
        }
        Ok(Json::Obj(m))
    }
    fn array(&mut self) -> Result<Json, String> {
        self.i += 1; // [
        let mut a = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            let v = self.value()?;
            a.push(v);
            self.ws();
            match self.b.get(self.i) {
                Some(',') => self.i += 1,
                Some(']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected ',' or ']'".into()),
            }
        }
        Ok(Json::Arr(a))
    }
    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&'"') {
            return Err("expected string".into());
        }
        self.i += 1;
        let mut s = String::new();
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                '"' => return Ok(s),
                '\\' => {
                    if let Some(&e) = self.b.get(self.i) {
                        self.i += 1;
                        match e {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '"' => s.push('"'),
                            '\\' => s.push('\\'),
                            '/' => s.push('/'),
                            'u' => {
                                let hex: String = self.b[self.i..self.i + 4].iter().collect();
                                self.i += 4;
                                if let Ok(n) = u32::from_str_radix(&hex, 16) {
                                    if let Some(ch) = char::from_u32(n) {
                                        s.push(ch);
                                    }
                                }
                            }
                            other => s.push(other),
                        }
                    }
                }
                other => s.push(other),
            }
        }
        Err("unterminated string".into())
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while let Some(&c) = self.b.get(self.i) {
            if c.is_ascii_digit() || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
                self.i += 1;
            } else {
                break;
            }
        }
        let s: String = self.b[start..self.i].iter().collect();
        s.parse::<f64>().map(Json::Num).map_err(|_| "bad number".into())
    }
    fn boolean(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(&['t', 'r', 'u', 'e']) {
            self.i += 4;
            Ok(Json::Bool(true))
        } else if self.b[self.i..].starts_with(&['f', 'a', 'l', 's', 'e']) {
            self.i += 5;
            Ok(Json::Bool(false))
        } else {
            Err("bad bool".into())
        }
    }
    fn null(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(&['n', 'u', 'l', 'l']) {
            self.i += 4;
            Ok(Json::Null)
        } else {
            Err("bad null".into())
        }
    }
}

// ── Trifecta classifier ──────────────────────────────────────────────────────
const AXES: [&str; 3] = ["credentials", "injection", "reach"];

fn signatures(axis: &str) -> &'static [&'static str] {
    match axis {
        "credentials" => &[
            "secret", "credential", "password", "token", "api_key", "apikey",
            "private_key", "privatekey", "ssh", "keychain", "vault", "env",
            "environ", "dotenv", ".env", "oauth", "access_key", "aws_", "gcp",
            "read_file", "readfile", "fs.read", "filesystem", "file_read",
            "database", "db_query", "sql", "private", "pii", "customer_data",
            "financial", "billing", "payment", "ssn", "cookie", "session",
        ],
        "injection" => &[
            "web", "fetch", "http_get", "browse", "crawl", "scrape", "url",
            "email_read", "read_email", "inbox", "mail", "rss", "webhook",
            "untrusted", "user_input", "document", "pdf", "parse", "ingest",
            "search", "rag", "retrieve", "comment", "issue", "ticket",
            "slack_read", "channel", "message_read", "transcribe", "ocr",
        ],
        _ => &[
            "send", "post", "http_post", "email_send", "send_email", "sendmail",
            "sms", "publish", "upload", "write_file", "writefile", "fs.write",
            "exec", "shell", "command", "subprocess", "deploy", "delete",
            "transfer", "payment_send", "wire", "purchase", "order", "webhook",
            "api_call", "external", "network", "dns", "socket", "git_push",
            "commit", "create_pr", "tweet", "dm", "call_tool",
        ],
    }
}

fn explicit_scope(s: &str) -> Option<&'static str> {
    match s {
        "read:secrets" | "read:files" | "read:db" => Some("credentials"),
        "read:web" | "read:email" => Some("injection"),
        "net:outbound" | "write:files" | "exec:shell" | "send:email" => Some("reach"),
        _ => None,
    }
}

fn exec_token(t: &str) -> bool {
    matches!(t, "exec" | "shell" | "command" | "subprocess" | "deploy")
}

fn normalize(parts: &[&Json]) -> String {
    let mut chunks: Vec<String> = Vec::new();
    fn add(v: &Json, out: &mut Vec<String>) {
        match v {
            Json::Str(s) => out.push(s.clone()),
            Json::Num(n) => out.push(n.to_string()),
            Json::Bool(b) => out.push(b.to_string()),
            Json::Arr(a) => a.iter().for_each(|e| add(e, out)),
            Json::Obj(m) => m.iter().for_each(|(k, val)| {
                out.push(format!("{} {}", k, json_str(val)));
            }),
            Json::Null => {}
        }
    }
    for p in parts {
        add(p, &mut chunks);
    }
    let joined = chunks.join(" ").to_lowercase();
    joined
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "_.: ".contains(c) { c } else { ' ' })
        .collect()
}

fn json_str(v: &Json) -> String {
    match v {
        Json::Str(s) => s.clone(),
        Json::Num(n) => n.to_string(),
        Json::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn get<'a>(obj: &'a Json, key: &str) -> Option<&'a Json> {
    if let Json::Obj(m) = obj {
        m.get(key)
    } else {
        None
    }
}

fn classify(cap: &Json) -> BTreeMap<String, Vec<String>> {
    let mut matched: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let empty = Json::Null;
    let parts: Vec<&Json> = ["name", "tool", "description", "scopes", "permissions"]
        .iter()
        .map(|k| get(cap, k).unwrap_or(&empty))
        .collect();
    let hay = normalize(&parts);

    if let Some(Json::Arr(scopes)) = get(cap, "scopes") {
        for s in scopes {
            let key = json_str(s).to_lowercase();
            if let Some(axis) = explicit_scope(&key) {
                let e = matched.entry(axis.to_string()).or_default();
                if !e.contains(&key) {
                    e.push(key);
                }
            }
        }
    }
    for axis in AXES.iter() {
        for tok in signatures(axis) {
            if hay.contains(tok) {
                let e = matched.entry(axis.to_string()).or_default();
                if !e.contains(&tok.to_string()) {
                    e.push(tok.to_string());
                }
            }
        }
    }
    matched
}

fn first_string(obj: &Json, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(Json::Str(s)) = get(obj, k) {
            if !s.is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

fn capabilities_of(agent: &Json) -> Vec<Json> {
    for key in ["capabilities", "tools", "permissions"] {
        if let Some(Json::Arr(list)) = get(agent, key) {
            return list
                .iter()
                .filter_map(|c| match c {
                    Json::Str(s) => {
                        let mut m = BTreeMap::new();
                        m.insert("name".to_string(), Json::Str(s.clone()));
                        Some(Json::Obj(m))
                    }
                    Json::Obj(_) => Some(c.clone()),
                    _ => None,
                })
                .collect();
        }
    }
    Vec::new()
}

fn coerce_agents(data: &Json) -> Result<Vec<Json>, String> {
    match data {
        Json::Obj(m) => {
            if let Some(Json::Arr(list)) = m.get("agents") {
                Ok(list.clone())
            } else if m.contains_key("agents") {
                Err("'agents' must be a list".into())
            } else {
                Ok(vec![data.clone()])
            }
        }
        Json::Arr(list) => Ok(list.clone()),
        _ => Err("manifest must be an object or a list of agents".into()),
    }
}

#[derive(Clone)]
struct Finding {
    agent: String,
    severity: String,
    title: String,
}

fn sev_rank(s: &str) -> i32 {
    match s {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn audit(agents: &[Json]) -> (usize, Vec<Finding>) {
    let mut findings = Vec::new();
    for agent in agents {
        let name = first_string(agent, &["name", "id"]).unwrap_or_else(|| "unnamed-agent".into());
        let mut axis_caps: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for a in AXES.iter() {
            axis_caps.insert(a.to_string(), BTreeMap::new());
        }
        for cap in capabilities_of(agent) {
            let cap_name =
                first_string(&cap, &["name", "tool"]).unwrap_or_else(|| "unnamed-tool".into());
            for (axis, ev) in classify(&cap) {
                axis_caps.get_mut(&axis).unwrap().insert(cap_name.clone(), ev);
            }
        }
        let present: Vec<&str> = AXES
            .iter()
            .filter(|a| !axis_caps[**a].is_empty())
            .copied()
            .collect();
        if present.len() == 3 {
            findings.push(Finding {
                agent: name.clone(),
                severity: "critical".into(),
                title: "Lethal trifecta: credentials + injection + reach".into(),
            });
        } else if present.len() == 2 {
            findings.push(Finding {
                agent: name.clone(),
                severity: "high".into(),
                title: "Two of three trifecta axes present".into(),
            });
        }
        let inj = !axis_caps["injection"].is_empty();
        let has_exec = axis_caps["reach"].values().any(|ev| ev.iter().any(|t| exec_token(t)));
        if inj && has_exec {
            findings.push(Finding {
                agent: name.clone(),
                severity: "critical".into(),
                title: "Untrusted input can reach code execution".into(),
            });
        }
    }
    (agents.len(), findings)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut format = "table";
    let mut path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" | "--format=json" => format = "json",
            "--format" => {
                i += 1;
                if args.get(i).map(|s| s.as_str()) == Some("json") {
                    format = "json";
                }
            }
            a if !a.starts_with("--") => path = Some(a.to_string()),
            _ => {}
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("usage: aegis [--format json] <manifest.json>");
            process::exit(2);
        }
    };
    let raw = match fs::read_to_string(&path) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("aegis: manifest not found: {}", path);
            process::exit(2);
        }
    };
    let data = match Parser::new(&raw).parse() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aegis: invalid manifest: {}", e);
            process::exit(2);
        }
    };
    let agents = match coerce_agents(&data) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aegis: invalid manifest: {}", e);
            process::exit(2);
        }
    };
    let (scanned, findings) = audit(&agents);
    let worst = findings
        .iter()
        .map(|f| (sev_rank(&f.severity), f.severity.clone()))
        .max_by_key(|(r, _)| *r)
        .map(|(_, s)| s)
        .unwrap_or_else(|| "none".into());

    if format == "json" {
        // Hand-rolled JSON output to stay dependency-free.
        let mut out = String::from("{\n");
        out.push_str(&format!("  \"agents_scanned\": {},\n", scanned));
        out.push_str(&format!("  \"finding_count\": {},\n", findings.len()));
        out.push_str(&format!("  \"worst_severity\": \"{}\",\n", worst));
        out.push_str("  \"findings\": [\n");
        for (idx, f) in findings.iter().enumerate() {
            out.push_str(&format!(
                "    {{\"agent\": \"{}\", \"severity\": \"{}\", \"title\": \"{}\"}}{}\n",
                f.agent,
                f.severity,
                f.title,
                if idx + 1 < findings.len() { "," } else { "" }
            ));
        }
        out.push_str("  ]\n}");
        println!("{}", out);
    } else {
        println!(
            "AEGIS audit | agents: {} | findings: {} | worst: {}",
            scanned,
            findings.len(),
            worst
        );
        for f in &findings {
            println!("[{:<8}] {}: {}", f.severity.to_uppercase(), f.agent, f.title);
        }
    }
    if worst == "critical" || worst == "high" {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(rel: &str) -> Vec<Json> {
        let path = format!("../../demos/{}", rel);
        let raw = fs::read_to_string(&path).expect("read demo");
        let data = Parser::new(&raw).parse().expect("parse demo");
        coerce_agents(&data).expect("coerce")
    }

    #[test]
    fn parses_nested_manifest() {
        let agents = load("01-basic/agents.json");
        assert_eq!(agents.len(), 4);
    }

    #[test]
    fn basic_demo_trifecta() {
        let agents = load("01-basic/agents.json");
        let (scanned, findings) = audit(&agents);
        assert_eq!(scanned, 4);
        let support: Vec<&Finding> = findings.iter().filter(|f| f.agent == "support-bot").collect();
        assert!(support.iter().any(|f| f.severity == "critical"));
        let calc: Vec<&Finding> = findings.iter().filter(|f| f.agent == "calculator").collect();
        assert!(calc.is_empty(), "calculator must be clean");
        let deploy: Vec<&Finding> = findings.iter().filter(|f| f.agent == "deploy-agent").collect();
        assert!(deploy.iter().any(|f| f.title.contains("code execution")));
    }

    #[test]
    fn classify_axes() {
        let mut cap = BTreeMap::new();
        cap.insert("name".to_string(), Json::Str("web_fetch".into()));
        cap.insert("description".to_string(), Json::Str("fetch a url".into()));
        let m = classify(&Json::Obj(cap));
        assert!(m.contains_key("injection"));

        let mut cap2 = BTreeMap::new();
        cap2.insert("name".to_string(), Json::Str("billing_db_query".into()));
        cap2.insert("scopes".to_string(), Json::Arr(vec![Json::Str("read:db".into())]));
        let m2 = classify(&Json::Obj(cap2));
        assert!(m2.contains_key("credentials"));
    }

    #[test]
    fn clean_agent_no_findings() {
        let agents = load("03-analytics-agent-clean/mcp.json");
        let (_, findings) = audit(&agents);
        assert!(findings.is_empty());
    }

    #[test]
    fn json_parser_roundtrip() {
        let v = Parser::new(r#"{"a": [1, "x", true, null], "b": {"c": 2.5}}"#)
            .parse()
            .unwrap();
        if let Json::Obj(m) = v {
            assert!(matches!(m.get("a"), Some(Json::Arr(_))));
        } else {
            panic!("expected object");
        }
    }
}
