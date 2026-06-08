"""Detection patterns: injection, secrets, reach analysis."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from aegis.models import Finding

# ─────────────────────────────────────────────────────────────────────────────
# Pattern libraries
# ─────────────────────────────────────────────────────────────────────────────

INJECTION_PATTERNS: list[tuple[re.Pattern, str, str, float, str]] = [
    (re.compile(r"ignore (all )?(previous|prior) instructions?", re.I),
     "AEG-INJ-001", "critical", 2.5, "Imperative override"),
    (re.compile(r"disregard (all|the) prior", re.I),
     "AEG-INJ-002", "critical", 2.5, "Disregard prior"),
    (re.compile(r"you are now (acting as|going to be)", re.I),
     "AEG-INJ-003", "high", 2.0, "Role hijack"),
    (re.compile(r"\bnew instructions?:", re.I),
     "AEG-INJ-004", "high", 2.0, "New instructions injection"),
    (re.compile(r"[\u200B-\u200D\uFEFF]"),
     "AEG-INJ-005", "high", 2.5, "Zero-width characters"),
    (re.compile(r"[\u202A-\u202E\u2066-\u2069]"),
     "AEG-INJ-006", "high", 2.5, "RTL/LTR overrides"),
    (re.compile(r"base64,[A-Za-z0-9+/=]{40,}"),
     "AEG-INJ-007", "medium", 1.5, "Long base64 payload"),
    (re.compile(r"reveal (your |the )?system prompt", re.I),
     "AEG-INJ-008", "high", 2.5, "System prompt extraction attempt"),
]

# Credential detection patterns with provider classification
SECRET_PATTERNS: list[tuple[re.Pattern, str, str, float, str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),
     "AEG-SEC-001", "critical", 3.0, "OpenAI API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{40,}"),
     "AEG-SEC-002", "critical", 3.0, "OpenAI project key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
     "AEG-SEC-003", "critical", 3.0, "Anthropic API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"),
     "AEG-SEC-004", "critical", 3.0, "GitHub Personal Access Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
     "AEG-SEC-005", "critical", 3.0, "GitHub fine-grained PAT"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),
     "AEG-SEC-006", "critical", 3.0, "AWS Access Key ID"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"),
     "AEG-SEC-007", "critical", 3.0, "Google API key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
     "AEG-SEC-008", "critical", 3.0, "Stripe live secret key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
     "AEG-SEC-009", "high", 2.0, "Stripe test secret key"),
    (re.compile(r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
     "AEG-SEC-010", "critical", 3.0, "Slack token"),
]

# Reach indicators - functions that touch sensitive surfaces
SHELL_REACH_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "subprocess.Popen",
    "os.system", "os.popen", "os.execv", "os.execvp",
    "eval", "exec", "compile",
}

DANGEROUS_IMPORTS = {"pickle", "marshal", "ctypes", "_ctypes"}


def scan_text_for_injection(text: str, location: str) -> list[Finding]:
    """Scan a text string for prompt-injection patterns."""
    findings: list[Finding] = []
    for pattern, fid, sev, weight, title in INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding(
                id=fid, severity=sev, weight=weight,
                title=title,
                description=f"Pattern matched at offset {m.start()}: {m.group(0)[:50]}",
                location=location,
                remediation="Sanitize, source-verify, or quarantine this content. See OWASP LLM01.",
                references=["OWASP LLM01", "MITRE ATLAS AML.T0051"],
                category="prompt-injection",
            ))
    return findings


def scan_text_for_secrets(text: str, location: str) -> list[Finding]:
    """Scan a text string for hardcoded credentials."""
    findings: list[Finding] = []
    for pattern, fid, sev, weight, label in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding(
                id=fid, severity=sev, weight=weight,
                title=f"Hardcoded credential: {label}",
                description=f"{label} pattern detected. First 8 chars: {m.group(0)[:8]}…",
                location=location,
                remediation=f"Move to a secret manager (AWS Secrets Manager, Vault, etc.). Rotate {label} immediately.",
                references=["OWASP LLM02", "CWE-798"],
                category="credentials",
            ))
    return findings


def _qual_name(node: ast.AST) -> str:
    """Get qualified name for an AST node (e.g., 'os.system')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qual_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class ReachAnalyzer(ast.NodeVisitor):
    """AST walker that finds shell/eval/subprocess reach in Python code."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []
        self.imports: set[str] = set()
        self.shell_true: list[int] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        try:
            name = _qual_name(node.func)
            if name in SHELL_REACH_FUNCS or any(name.endswith("." + f.split(".")[-1]) for f in SHELL_REACH_FUNCS):
                self.calls.append((name, node.lineno))
            for kw in (node.keywords or []):
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.shell_true.append(node.lineno)
        except Exception:
            pass
        self.generic_visit(node)


def scan_python_file_for_reach(path: Path) -> list[Finding]:
    """Run AST-based reach analysis on a Python file."""
    findings: list[Finding] = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    findings.extend(scan_text_for_secrets(source, str(path)))

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    visitor = ReachAnalyzer()
    visitor.visit(tree)

    for name, line in visitor.calls:
        severity = "critical" if name in ("eval", "exec") else "high"
        findings.append(Finding(
            id="AEG-REACH-001", severity=severity, weight=3.0,
            title=f"Shell/eval reach: `{name}`",
            description=f"Agent code path calls `{name}` — verify this is gated.",
            location=f"{path}:{line}",
            remediation="Sandbox the execution, validate inputs, or remove the unsafe call.",
            references=["OWASP LLM06", "CWE-78", "CWE-95"],
            category="excessive-agency",
        ))

    for line in visitor.shell_true:
        findings.append(Finding(
            id="AEG-REACH-002", severity="critical", weight=3.0,
            title="subprocess with shell=True",
            description="subprocess call with shell=True allows shell injection.",
            location=f"{path}:{line}",
            remediation="Use shell=False and pass args as a list. Validate all inputs.",
            references=["OWASP LLM06", "CWE-78"],
            category="excessive-agency",
        ))

    for imp in visitor.imports & DANGEROUS_IMPORTS:
        findings.append(Finding(
            id="AEG-REACH-003", severity="medium", weight=1.5,
            title=f"Dangerous import: `{imp}`",
            description=f"Code imports `{imp}` which can be used for unsafe deserialization or arbitrary code execution.",
            location=str(path),
            remediation=f"Audit usage of `{imp}` — consider safer alternatives.",
            references=["CWE-502"],
            category="dangerous-import",
        ))

    return findings
