"""
AEGIS MCP Server — exposes scanning as Model Context Protocol tools.
This makes AEGIS a first-class citizen of Cognis.Studio (and Claude Desktop,
Cursor, Windsurf, Zed — any MCP-compatible host).

Install with: pip install 'cognis-aegis[mcp]'
Run as: aegis mcp
Or register in Claude Desktop config:
    "aegis": {"command": "aegis", "args": ["mcp"]}
"""
from __future__ import annotations

import json
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    raise ImportError("Install with: pip install 'cognis-aegis[mcp]'")

from aegis import __version__
from aegis.core import scan
from aegis.exporters import to_json, to_markdown


server = Server("cognis-aegis")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """Advertise the tools this MCP server provides."""
    return [
        Tool(
            name="aegis_scan",
            description=(
                "AEGIS — AI Agent Permission & Access Auditor. "
                "Statically audits agent projects (MCP, LangChain, LlamaIndex, OpenAI Assistants, "
                "CrewAI, AutoGen) and returns a permission matrix, lethal-trifecta detection, "
                "and risk-scored findings mapped to OWASP LLM Top 10 + MITRE ATLAS. "
                "Part of the Cognis Neural Suite."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Filesystem path to the agent project to audit",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "markdown"],
                        "default": "markdown",
                        "description": "Output format",
                    },
                },
                "required": ["target"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Dispatch tool calls."""
    if name == "aegis_scan":
        target = arguments.get("target", "")
        fmt = arguments.get("format", "markdown")

        if not target:
            return [TextContent(type="text", text="Error: target is required")]

        result = scan(target)
        output = to_json(result) if fmt == "json" else to_markdown(result)
        return [TextContent(type="text", text=output)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


def run_mcp_server(transport: str = "stdio") -> None:
    """Entry point called from `aegis mcp` CLI."""
    import asyncio

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    run_mcp_server()
