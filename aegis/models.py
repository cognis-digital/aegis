"""Data models for AEGIS findings, tools, agents, and scan results."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Literal, Optional

Severity = Literal["info", "low", "medium", "high", "critical"]
Framework = Literal["mcp", "langchain", "llamaindex", "openai-assistant", "crewai", "autogen", "generic"]


@dataclass
class Finding:
    """A single finding produced by an analyzer."""
    id: str
    severity: Severity
    weight: float
    title: str
    description: str
    location: str
    remediation: str
    references: list[str] = field(default_factory=list)
    category: str = "general"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReachProfile:
    """What an agent's tool can reach (filesystem, network, shell)."""
    filesystem_read: bool = False
    filesystem_write: bool = False
    filesystem_write_paths: list[str] = field(default_factory=list)
    network_egress: bool = False
    network_endpoints: list[str] = field(default_factory=list)
    shell_exec: bool = False
    subprocess: bool = False
    eval_or_exec: bool = False
    sensitive_imports: list[str] = field(default_factory=list)


@dataclass
class Tool:
    """A tool/function callable by an agent."""
    name: str
    framework: Framework
    description: str = ""
    source_file: str = ""
    source_line: int = 0
    parameters: dict = field(default_factory=dict)
    reach: ReachProfile = field(default_factory=ReachProfile)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Agent:
    """An agent definition with its tools, system prompt, and memory config."""
    name: str
    framework: Framework
    model: Optional[str] = None
    tools: list[Tool] = field(default_factory=list)
    system_prompt: Optional[str] = None
    memory_config: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    composite_score: float = 0.0
    risk_level: str = "Minimal"
    trifecta: dict = field(default_factory=dict)  # lethal trifecta detection


@dataclass
class ScanResult:
    """Top-level result of an AEGIS scan."""
    target: str
    aegis_version: str
    scan_duration_ms: int = 0
    files_scanned: int = 0
    agents: list[Agent] = field(default_factory=list)
    global_findings: list[Finding] = field(default_factory=list)
    composite_score: float = 0.0
    risk_level: str = "Minimal"
    compliance_crosswalk: dict = field(default_factory=dict)
    lethal_trifecta_present: list[str] = field(default_factory=list)

    def total_tools(self) -> int:
        return sum(len(a.tools) for a in self.agents)

    def total_findings(self) -> int:
        count = len(self.global_findings)
        for a in self.agents:
            count += len(a.findings)
            for t in a.tools:
                count += len(t.findings)
        return count

    def all_findings(self) -> list[Finding]:
        out = list(self.global_findings)
        for a in self.agents:
            out.extend(a.findings)
            for t in a.tools:
                out.extend(t.findings)
        return out

    def findings_by_severity(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.all_findings():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
