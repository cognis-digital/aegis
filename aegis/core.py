"""Core AEGIS scan orchestrator."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator

from aegis.models import ScanResult, Agent, Tool
from aegis.detectors import scan_python_file_for_reach
from aegis.parsers import (
    parse_mcp_config,
    parse_langchain_source,
    parse_openai_assistant_json,
    parse_crewai_yaml,
)
from aegis.scoring import score, detect_lethal_trifecta

__version__ = "0.1.0"

SKIP_DIRS = {"venv", ".venv", "node_modules", ".git", "__pycache__",
             ".pytest_cache", ".ruff_cache", ".tox", "dist", "build"}


def _walk(root: Path) -> Iterator[Path]:
    """Walk a directory tree, skipping common cache/dep dirs."""
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and not any(part in SKIP_DIRS for part in p.parts):
            yield p


def scan(target: str | Path) -> ScanResult:
    """Run a full AEGIS scan against the target path."""
    start = time.time()
    root = Path(target).resolve()
    result = ScanResult(target=str(root), aegis_version=__version__)

    files = list(_walk(root))
    result.files_scanned = len(files)

    # MCP configs
    for p in files:
        if p.suffix == ".json" and ("mcp" in p.name.lower() or p.name in ("claude_desktop_config.json",)):
            agent = parse_mcp_config(p)
            if agent:
                result.agents.append(agent)

    # OpenAI Assistant JSON exports
    for p in files:
        if p.suffix == ".json" and "assistant" in p.name.lower():
            agent = parse_openai_assistant_json(p)
            if agent:
                result.agents.append(agent)

    # CrewAI YAML
    for p in files:
        if p.name in ("agents.yaml", "agents.yml", "crew.yaml", "crew.yml"):
            agent = parse_crewai_yaml(p)
            if agent:
                result.agents.append(agent)

    # LangChain Python sources + global Python file reach analysis
    lc_tools: list[Tool] = []
    for p in [f for f in files if f.suffix == ".py"]:
        lc_tools.extend(parse_langchain_source(p))
        result.global_findings.extend(scan_python_file_for_reach(p))

    if lc_tools:
        result.agents.append(Agent(
            name="langchain-detected-tools",
            framework="langchain",
            tools=lc_tools,
        ))

    # Per-agent scoring + lethal trifecta detection
    for agent in result.agents:
        agent_findings = list(agent.findings)
        for tool in agent.tools:
            agent_findings.extend(tool.findings)
        agent.composite_score, agent.risk_level = score(agent_findings)
        agent.trifecta = detect_lethal_trifecta(agent.tools)
        if agent.trifecta.get("trifecta_present"):
            result.lethal_trifecta_present.append(agent.name)

    # Composite score across everything
    result.composite_score, result.risk_level = score(result.all_findings())

    # Compliance crosswalk - count findings by reference framework
    crosswalk: dict[str, int] = {}
    for f in result.all_findings():
        for ref in f.references:
            crosswalk[ref] = crosswalk.get(ref, 0) + 1
    result.compliance_crosswalk = crosswalk

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return result
