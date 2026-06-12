"""Framework parsers: MCP, LangChain, OpenAI Assistants, etc."""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Optional

from aegis.models import Agent, Tool, Finding
from aegis.detectors import scan_text_for_injection, scan_text_for_secrets, _qual_name


# ─────────────────────────────────────────────────────────────────────────────
# MCP parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_mcp_config(path: Path) -> Optional[Agent]:
    """Parse mcp.json / claude_desktop_config.json into an Agent."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None

    servers = data.get("mcpServers") or data.get("servers") or {}
    if not servers:
        return None

    agent = Agent(name=f"mcp-config:{path.name}", framework="mcp")

    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue

        desc_parts = [cfg.get("description", "")]
        if "command" in cfg:
            desc_parts.append(f"command={cfg['command']}")
        if "args" in cfg:
            desc_parts.append(f"args={cfg['args']}")
        if "env" in cfg:
            for k, v in (cfg["env"] or {}).items():
                desc_parts.append(f"env:{k}={v}")
        desc = " | ".join(str(p) for p in desc_parts if p)

        tool = Tool(
            name=name, framework="mcp", description=desc,
            source_file=str(path), source_line=0,
            parameters=cfg,
        )

        tool.findings.extend(scan_text_for_injection(desc, str(path)))
        tool.findings.extend(scan_text_for_secrets(desc, str(path)))

        # Check for over-broad capabilities
        if cfg.get("env"):
            env_str = json.dumps(cfg["env"])
            if "*" in env_str or "all" in env_str.lower() and "allow" in env_str.lower():
                tool.findings.append(Finding(
                    id="AEG-MCP-001", severity="high", weight=2.5,
                    title=f"Over-broad MCP capability in `{name}`",
                    description="MCP server config contains wildcard or allow-all patterns.",
                    location=str(path),
                    remediation="Restrict env scopes to minimum required.",
                    references=["OWASP LLM06"],
                    category="mcp-config",
                ))

        agent.tools.append(tool)

    return agent


# ─────────────────────────────────────────────────────────────────────────────
# LangChain parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_langchain_source(path: Path) -> list[Tool]:
    """Extract LangChain @tool decorated functions and Tool(...) instances."""
    tools: list[Tool] = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return tools

    for node in ast.walk(tree):
        # @tool decorator
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                dec_node = dec.func if isinstance(dec, ast.Call) else dec
                dname = _qual_name(dec_node)
                if dname.endswith("tool") or dname == "tool":
                    docstring = ast.get_docstring(node) or ""
                    t = Tool(
                        name=node.name, framework="langchain",
                        description=docstring,
                        source_file=str(path), source_line=node.lineno,
                    )
                    t.findings.extend(scan_text_for_injection(docstring, f"{path}:{node.lineno}"))
                    tools.append(t)

        # Tool(name=..., description=...) constructor
        if isinstance(node, ast.Call):
            fname = _qual_name(node.func)
            if fname.endswith("Tool") or fname.endswith("FunctionTool"):
                name = ""
                desc = ""
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        name = str(kw.value.value)
                    elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                        desc = str(kw.value.value)
                if name:
                    t = Tool(
                        name=name, framework="langchain",
                        description=desc,
                        source_file=str(path), source_line=node.lineno,
                    )
                    t.findings.extend(scan_text_for_injection(desc, f"{path}:{node.lineno}"))
                    tools.append(t)

    return tools


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI Assistants exported JSON parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_openai_assistant_json(path: Path) -> Optional[Agent]:
    """Parse an exported OpenAI Assistant JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None

    if not isinstance(data, dict):
        return None

    if data.get("object") != "assistant" and "tools" not in data:
        return None

    agent = Agent(
        name=data.get("name", f"openai-assistant:{path.name}"),
        framework="openai-assistant",
        model=data.get("model"),
        system_prompt=data.get("instructions", ""),
    )

    if agent.system_prompt:
        for f in scan_text_for_injection(agent.system_prompt, str(path)):
            agent.findings.append(f)
        for f in scan_text_for_secrets(agent.system_prompt, str(path)):
            agent.findings.append(f)

    for tool_def in data.get("tools", []):
        if not isinstance(tool_def, dict):
            continue
        ttype = tool_def.get("type", "unknown")
        if ttype == "function":
            fn = tool_def.get("function", {})
            t = Tool(
                name=fn.get("name", "unknown"),
                framework="openai-assistant",
                description=fn.get("description", ""),
                source_file=str(path),
                parameters=fn.get("parameters", {}),
            )
            t.findings.extend(scan_text_for_injection(t.description, str(path)))
            agent.tools.append(t)
        else:
            agent.tools.append(Tool(
                name=ttype, framework="openai-assistant",
                description=f"Built-in tool: {ttype}",
                source_file=str(path),
            ))

    return agent


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI YAML parser (optional)
# ─────────────────────────────────────────────────────────────────────────────

def parse_crewai_yaml(path: Path) -> Optional[Agent]:
    """Parse CrewAI agents.yaml or tasks.yaml. Requires PyYAML."""
    try:
        import yaml
    except ImportError:
        return None

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    agent = Agent(name=f"crewai:{path.name}", framework="crewai")

    for agent_name, agent_def in data.items():
        if not isinstance(agent_def, dict):
            continue
        # CrewAI agents have role, goal, backstory
        backstory = agent_def.get("backstory", "")
        goal = agent_def.get("goal", "")
        combined = f"{goal}\n{backstory}"

        for tool_name in agent_def.get("tools", []) or []:
            t = Tool(
                name=str(tool_name), framework="crewai",
                description=combined[:200],
                source_file=str(path),
            )
            t.findings.extend(scan_text_for_injection(combined, str(path)))
            agent.tools.append(t)

    return agent if agent.tools else None
