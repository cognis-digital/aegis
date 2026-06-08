"""Command-line interface for AEGIS."""

from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import audit_file, AuditReport

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
}


def _render_table(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append(
        f"AEGIS audit  |  agents scanned: {report.agents_scanned}  "
        f"|  findings: {len(report.findings)}  "
        f"|  worst: {report.worst_severity or 'none'}"
    )
    lines.append("-" * 72)
    if not report.findings:
        lines.append("No trifecta exposure found. Agents are within safe bounds.")
        return "\n".join(lines)
    for f in report.findings:
        lines.append(f"[{_SEV_LABEL.get(f.severity, f.severity)}] {f.agent}: {f.title}")
        lines.append(f"        axes: {', '.join(f.axes)}")
        for axis, caps in f.capabilities.items():
            lines.append(f"        {axis:<12} <- {', '.join(caps)}")
        lines.append(f"        fix: {f.detail}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "AEGIS - AI Agent Permission & Access Auditor. Detects the lethal "
            "trifecta (credentials + untrusted input + external reach) that "
            "makes an AI agent exploitable by prompt injection."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser(
        "audit",
        help="Audit an agent manifest (JSON) for trifecta exposure.",
        description="Scan an agent manifest and report dangerous capability combinations.",
    )
    audit.add_argument("manifest", help="Path to agent manifest JSON file.")
    audit.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table).",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "audit":
        parser.print_help()
        return 0

    try:
        report = audit_file(args.manifest)
    except FileNotFoundError:
        print(f"aegis: manifest not found: {args.manifest}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"aegis: invalid manifest: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(_render_json(report))
    else:
        print(_render_table(report))

    # Non-zero exit when any trifecta/critical exposure is found, so AEGIS can
    # gate CI pipelines.
    if any(f.severity in ("critical", "high") for f in report.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
