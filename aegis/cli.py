"""AEGIS command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis import __version__
from aegis.core import scan
from aegis.exporters import to_console, to_json, to_sarif, to_html, to_markdown


SEVERITY_ORDER = {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — AI Agent Permission & Access Auditor (Cognis Neural Suite)",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Scan an agent project")
    p_scan.add_argument("target", help="Path to project root or file")
    p_scan.add_argument("--format", "-f", choices=["console", "json", "sarif", "html", "markdown"],
                        default="console")
    p_scan.add_argument("--out", "-o", help="Output file (default: stdout)")
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                        help="Exit non-zero if any finding at or above this severity")

    p_serve = sub.add_parser("serve", help="Run AEGIS web dashboard")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--host", default="127.0.0.1")

    p_mcp = sub.add_parser("mcp", help="Run as MCP server (for Cognis.Studio integration)")
    p_mcp.add_argument("--transport", choices=["stdio", "http"], default="stdio")

    sub.add_parser("version", help="Print version")

    args = parser.parse_args(argv)

    if args.cmd in (None, "version"):
        print(f"aegis {__version__}")
        return 0

    if args.cmd == "scan":
        return _do_scan(args)

    if args.cmd == "serve":
        return _do_serve(args)

    if args.cmd == "mcp":
        return _do_mcp(args)

    parser.print_help()
    return 1


def _do_scan(args) -> int:
    result = scan(args.target)

    formatters = {
        "console": to_console,
        "json": to_json,
        "sarif": to_sarif,
        "html": to_html,
        "markdown": to_markdown,
    }
    output = formatters[args.format](result)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"[AEGIS] Wrote {args.out}", file=sys.stderr)
    else:
        print(output)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        for f in result.all_findings():
            if SEVERITY_ORDER.get(f.severity, 99) <= threshold:
                return 1

    return 0


def _do_serve(args) -> int:
    try:
        import uvicorn
        from aegis.web import app
    except ImportError:
        print("Install with: pip install 'cognis-aegis[web]'", file=sys.stderr)
        return 1
    print(f"[AEGIS] Web dashboard: http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _do_mcp(args) -> int:
    try:
        from aegis.mcp_server import run_mcp_server
    except ImportError:
        print("Install with: pip install 'cognis-aegis[mcp]'", file=sys.stderr)
        return 1
    run_mcp_server(transport=args.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
