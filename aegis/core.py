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
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, TYPE_CHECKING

if TYPE_CHECKING:  # avoids a runtime import cycle (models -> core)
    from aegis.models import Finding, ScanResult

# ── Tool identity ────────────────────────────────────────────────────────────
# Read from the VERSION file at the repo root when available so the packaged
# wheel, the CLI, and the SARIF/HTML reports all report a single version.
TOOL_NAME = "aegis"


def _read_version() -> str:
    for parent in (Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent):
        vf = parent / "VERSION"
        try:
            text = vf.read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            continue
    return "0.1.2"


TOOL_VERSION = _read_version()

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


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem scan engine
#
# `audit_*` above is the manifest engine (one JSON file -> trifecta findings).
# `scan()` below is the *project* engine: it walks a directory tree, dispatches
# each file to the right framework parser (MCP / LangChain / OpenAI-Assistant /
# CrewAI), runs the static detectors (injection / secret / reach-AST), computes
# a deterministic composite score, and detects Simon Willison's lethal trifecta
# per discovered agent. It returns a rich `ScanResult` that the exporters render
# to console / JSON / SARIF / HTML / Markdown.
#
# Strictly passive and offline: read-only file access, no network, no execution
# of scanned code (the reach analyzer parses the AST, it never runs it).
# ─────────────────────────────────────────────────────────────────────────────

# Files we never descend into — keeps a scan fast and avoids vendored noise.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".tox",
    ".idea", ".vscode", "site-packages", ".cache",
}

# Map every reference a finding cites onto the compliance framework controls it
# supports, so a scan doubles as audit evidence.
_COMPLIANCE_CROSSWALK: dict[str, tuple[str, ...]] = {
    "OWASP LLM01": ("OWASP LLM Top 10 — LLM01 Prompt Injection",),
    "OWASP LLM02": ("OWASP LLM Top 10 — LLM02 Sensitive Information Disclosure",),
    "OWASP LLM06": ("OWASP LLM Top 10 — LLM06 Excessive Agency",),
    "CWE-78": ("CWE-78 OS Command Injection", "NIST SP 800-53 SI-10"),
    "CWE-95": ("CWE-95 Eval Injection",),
    "CWE-502": ("CWE-502 Deserialization of Untrusted Data",),
    "CWE-798": ("CWE-798 Use of Hard-coded Credentials", "NIST SP 800-53 IA-5"),
    "MITRE ATLAS AML.T0051": ("MITRE ATLAS AML.T0051 LLM Prompt Injection",),
}

_MAX_FILE_BYTES = 2_000_000  # skip pathologically large blobs


def _iter_files(root: Path):
    """Yield candidate files under root, skipping noise/vendor directories."""
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _looks_like(path: Path) -> str:
    """Classify a file by name/extension to pick a parser. Cheap, no I/O."""
    name = path.name.lower()
    if name in ("mcp.json", "claude_desktop_config.json") or name.endswith(".mcp.json"):
        return "mcp"
    if path.suffix == ".json":
        return "json"  # could be MCP, OpenAI assistant, or an aegis manifest
    if path.suffix == ".py":
        return "python"
    if path.suffix in (".yaml", ".yml"):
        return "yaml"
    return "other"


def scan(target, *, follow_symlinks: bool = False) -> "ScanResult":
    """Statically audit a directory (or single file) for agent-security risk.

    Read-only and offline. Returns a populated :class:`ScanResult`.
    """
    # Imports are local to keep the manifest engine importable even if the
    # richer model/detector stack is ever stripped from a minimal build.
    from aegis.models import Agent, ScanResult  # noqa: WPS433
    from aegis import detectors as _det
    from aegis import parsers as _par
    from aegis import scoring as _sc

    root = Path(target)
    started = time.perf_counter()
    result = ScanResult(target=str(root), aegis_version=TOOL_VERSION)

    if not root.exists():
        raise FileNotFoundError(f"scan target not found: {root}")

    files_scanned = 0
    for path in _iter_files(root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        kind = _looks_like(path)
        if kind == "other":
            continue
        files_scanned += 1

        if kind in ("mcp", "json"):
            agent = _par.parse_mcp_config(path)
            if agent is None:
                agent = _par.parse_openai_assistant_json(path)
            if agent is not None:
                result.agents.append(agent)
                continue
            # An aegis-style capability manifest? Fold its findings in globally.
            try:
                rep = audit_file(str(path))
            except (ValueError, json.JSONDecodeError, OSError):
                rep = None
            if rep is not None and rep.findings:
                for f in rep.findings:
                    result.global_findings.append(
                        _trifecta_finding_to_model(f, str(path))
                    )
        elif kind == "python":
            tools = _par.parse_langchain_source(path)
            result.global_findings.extend(_det.scan_python_file_for_reach(path))
            if tools:
                agent = Agent(name=f"python:{path.name}", framework="langchain")
                agent.tools.extend(tools)
                result.agents.append(agent)
        elif kind == "yaml":
            agent = _par.parse_crewai_yaml(path)
            if agent is not None:
                result.agents.append(agent)

    # Per-agent trifecta detection + scoring.
    trifecta_agents: list[str] = []
    for agent in result.agents:
        agent.trifecta = _sc.detect_lethal_trifecta(agent.tools)
        if agent.trifecta.get("trifecta_present"):
            trifecta_agents.append(agent.name)
            agent.findings.append(_trifecta_model_finding(agent.name))
        agent_findings = list(agent.findings)
        for t in agent.tools:
            agent_findings.extend(t.findings)
        agent.composite_score, agent.risk_level = _sc.score(agent_findings)

    result.lethal_trifecta_present = trifecta_agents
    result.composite_score, result.risk_level = _sc.score(result.all_findings())
    result.compliance_crosswalk = _build_crosswalk(result.all_findings())
    result.files_scanned = files_scanned
    result.scan_duration_ms = int((time.perf_counter() - started) * 1000)
    return result


def _trifecta_model_finding(agent_name: str):
    """Build a ScanResult-model Finding announcing a lethal trifecta agent."""
    from aegis.models import Finding  # noqa: WPS433
    return Finding(
        id="AEG-TRIFECTA-001",
        severity="critical",
        weight=3.0,
        title="Lethal trifecta: private data + untrusted content + external comms",
        description=(
            f"Agent `{agent_name}` can access private data, ingest untrusted "
            "content, AND communicate externally. A single prompt injection can "
            "exfiltrate data end-to-end."
        ),
        location=agent_name,
        remediation=(
            "Break the trifecta by removing one axis: sandbox outbound reach, "
            "strip private-data access, or quarantine untrusted ingestion."
        ),
        references=["OWASP LLM06", "OWASP LLM01"],
        category="lethal-trifecta",
    )


def _trifecta_finding_to_model(f: "Finding", location: str):
    """Convert a manifest-engine `Finding` into a ScanResult-model `Finding`."""
    from aegis.models import Finding as ModelFinding  # noqa: WPS433
    weight = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}.get(f.severity, 1.0)
    return ModelFinding(
        id="AEG-MANIFEST-001",
        severity=f.severity,
        weight=weight,
        title=f.title,
        description=f"{f.agent}: {', '.join(f.axes)}",
        location=location,
        remediation=f.detail,
        references=["OWASP LLM06"],
        category="lethal-trifecta",
    )


def _build_crosswalk(findings) -> dict[str, int]:
    """Count findings per compliance control via their cited references."""
    counts: dict[str, int] = {}
    for f in findings:
        for ref in getattr(f, "references", []) or []:
            for control in _COMPLIANCE_CROSSWALK.get(ref, (ref,)):
                counts[control] = counts.get(control, 0) + 1
    return counts
