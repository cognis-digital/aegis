"""Core engine for AEGIS.

Parses an AI agent manifest (JSON) describing the tools/capabilities an agent
is granted, classifies each capability along three risk axes, and flags agents
that possess the "lethal trifecta": access to credentials/private data,
exposure to untrusted input, and the reach to exfiltrate or take external
actions. An agent holding all three is exploitable end-to-end by a single
prompt injection.

No third-party imports. Pure standard library.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

# The three axes of the lethal trifecta.
CAPABILITY_AXES = ("credentials", "injection", "reach")

# Keyword signatures used to infer what an axis a capability touches. Matched
# against the tool name, description, scopes and declared permissions. Ordered
# roughly by specificity; matching is substring-based on a normalized string.
_SIGNATURES: dict[str, tuple[str, ...]] = {
    "credentials": (
        "secret", "credential", "password", "token", "api_key", "apikey",
        "private_key", "privatekey", "ssh", "keychain", "vault", "env",
        "environ", "dotenv", ".env", "oauth", "access_key", "aws_", "gcp",
        "read_file", "readfile", "fs.read", "filesystem", "file_read",
        "database", "db_query", "sql", "private", "pii", "customer_data",
        "financial", "billing", "payment", "ssn", "cookie", "session",
    ),
    "injection": (
        "web", "fetch", "http_get", "browse", "crawl", "scrape", "url",
        "email_read", "read_email", "inbox", "mail", "rss", "webhook",
        "untrusted", "user_input", "document", "pdf", "parse", "ingest",
        "search", "rag", "retrieve", "comment", "issue", "ticket",
        "slack_read", "channel", "message_read", "transcribe", "ocr",
    ),
    "reach": (
        "send", "post", "http_post", "email_send", "send_email", "sendmail",
        "sms", "publish", "upload", "write_file", "writefile", "fs.write",
        "exec", "shell", "command", "subprocess", "deploy", "delete",
        "transfer", "payment_send", "wire", "purchase", "order", "webhook",
        "api_call", "external", "network", "dns", "socket", "git_push",
        "commit", "create_pr", "tweet", "dm", "call_tool",
    ),
}

# Some declared scope strings map directly onto an axis regardless of keywords.
_EXPLICIT_SCOPE_AXIS: dict[str, str] = {
    "read:secrets": "credentials",
    "read:files": "credentials",
    "read:db": "credentials",
    "read:web": "injection",
    "read:email": "injection",
    "net:outbound": "reach",
    "write:files": "reach",
    "exec:shell": "reach",
    "send:email": "reach",
}

_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _normalize(*parts: Any) -> str:
    """Flatten arbitrary capability metadata into one lowercased search string."""
    chunks: list[str] = []
    for p in parts:
        if p is None:
            continue
        if isinstance(p, (list, tuple, set)):
            chunks.extend(str(x) for x in p)
        elif isinstance(p, dict):
            chunks.extend(f"{k} {v}" for k, v in p.items())
        else:
            chunks.append(str(p))
    return re.sub(r"[^a-z0-9_.: ]+", " ", " ".join(chunks).lower())


def classify_capability(capability: dict[str, Any]) -> dict[str, list[str]]:
    """Return the set of risk axes a capability touches, with matched evidence.

    The result maps each matched axis -> list of matched signature tokens.
    """
    name = capability.get("name") or capability.get("tool") or ""
    haystack = _normalize(
        name,
        capability.get("description"),
        capability.get("scopes"),
        capability.get("permissions"),
        capability.get("category"),
        capability.get("action"),
    )
    matched: dict[str, list[str]] = {}

    # Explicit author-declared axis wins immediately.
    declared = capability.get("risk") or capability.get("axes")
    if isinstance(declared, (list, tuple)):
        for axis in declared:
            axis = str(axis).lower()
            if axis in CAPABILITY_AXES:
                matched.setdefault(axis, []).append("declared")

    # Explicit scope -> axis mapping.
    for scope in capability.get("scopes", []) or []:
        axis = _EXPLICIT_SCOPE_AXIS.get(str(scope).lower())
        if axis:
            matched.setdefault(axis, []).append(str(scope).lower())

    # Keyword signature matching.
    for axis, tokens in _SIGNATURES.items():
        for tok in tokens:
            if tok in haystack:
                hits = matched.setdefault(axis, [])
                if tok not in hits:
                    hits.append(tok)
    return matched


@dataclass
class Finding:
    agent: str
    severity: str  # critical | high | medium | low
    axes: list[str]
    title: str
    detail: str
    capabilities: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)
    agents_scanned: int = 0

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def worst_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: _SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "agents_scanned": self.agents_scanned,
            "finding_count": len(self.findings),
            "worst_severity": self.worst_severity,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_manifest(path: str) -> list[dict[str, Any]]:
    """Load an agent manifest file. Accepts a single agent object or a list.

    Supported shapes:
      {"agents": [ {...}, {...} ]}
      [ {...}, {...} ]
      { "name": ..., "capabilities": [...] }   # single agent
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return _coerce_agents(data)


def _coerce_agents(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and "agents" in data:
        agents = data["agents"]
    elif isinstance(data, list):
        agents = data
    elif isinstance(data, dict):
        agents = [data]
    else:
        raise ValueError("manifest must be an object or a list of agents")
    if not isinstance(agents, list):
        raise ValueError("'agents' must be a list")
    return agents


def _capabilities_of(agent: dict[str, Any]) -> list[dict[str, Any]]:
    caps = (
        agent.get("capabilities")
        or agent.get("tools")
        or agent.get("permissions")
        or []
    )
    out: list[dict[str, Any]] = []
    for c in caps:
        if isinstance(c, str):
            out.append({"name": c})
        elif isinstance(c, dict):
            out.append(c)
    return out


def audit_manifest(agents: Iterable[dict[str, Any]]) -> AuditReport:
    """Audit a collection of agent definitions for the lethal trifecta."""
    report = AuditReport()
    for agent in agents:
        report.agents_scanned += 1
        agent_name = agent.get("name") or agent.get("id") or "unnamed-agent"
        caps = _capabilities_of(agent)

        # axis -> {capability_name: [evidence tokens]}
        axis_caps: dict[str, dict[str, list[str]]] = {a: {} for a in CAPABILITY_AXES}
        for cap in caps:
            cap_name = cap.get("name") or cap.get("tool") or "unnamed-tool"
            for axis, evidence in classify_capability(cap).items():
                axis_caps[axis][cap_name] = evidence

        present_axes = [a for a in CAPABILITY_AXES if axis_caps[a]]

        # The headline check: all three axes present == lethal trifecta.
        if len(present_axes) == 3:
            report.findings.append(
                Finding(
                    agent=agent_name,
                    severity="critical",
                    axes=list(present_axes),
                    title="Lethal trifecta: credentials + injection + reach",
                    detail=(
                        "This agent can access sensitive data, ingest untrusted "
                        "input, AND act on the outside world. A single prompt "
                        "injection can exfiltrate secrets end-to-end. Break the "
                        "trifecta by removing one axis (e.g. sandbox outbound "
                        "reach, or strip credential access on this agent)."
                    ),
                    capabilities={a: list(axis_caps[a]) for a in present_axes},
                )
            )
        elif len(present_axes) == 2:
            report.findings.append(
                Finding(
                    agent=agent_name,
                    severity="high",
                    axes=list(present_axes),
                    title="Two of three trifecta axes present",
                    detail=(
                        "One capability away from the lethal trifecta. Audit "
                        "future grants before adding the missing axis: "
                        + ", ".join(a for a in CAPABILITY_AXES if a not in present_axes)
                    ),
                    capabilities={a: list(axis_caps[a]) for a in present_axes},
                )
            )

        # Independent finding: untrusted input feeding shell/exec is RCE-class.
        if axis_caps["injection"] and _has_exec(axis_caps["reach"]):
            report.findings.append(
                Finding(
                    agent=agent_name,
                    severity="critical",
                    axes=["injection", "reach"],
                    title="Untrusted input can reach code execution",
                    detail=(
                        "Agent ingests untrusted content and holds a "
                        "shell/exec/deploy capability. Injection -> RCE. "
                        "Require human approval on execution tools."
                    ),
                    capabilities={
                        "injection": list(axis_caps["injection"]),
                        "reach": list(axis_caps["reach"]),
                    },
                )
            )
    return report


def _has_exec(reach_caps: dict[str, list[str]]) -> bool:
    exec_tokens = {"exec", "shell", "command", "subprocess", "deploy"}
    for evidence in reach_caps.values():
        if exec_tokens.intersection(evidence):
            return True
    return False


def audit_file(path: str) -> AuditReport:
    """Convenience: load a manifest file and audit it."""
    return audit_manifest(load_manifest(path))
