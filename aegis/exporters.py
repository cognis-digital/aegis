"""Output formatters: JSON, HTML, SARIF, Markdown."""
from __future__ import annotations

import dataclasses
import html
import json
from pathlib import Path

from aegis.models import ScanResult


def to_json(result: ScanResult) -> str:
    """Serialize ScanResult to indented JSON."""
    return json.dumps(dataclasses.asdict(result), indent=2, default=str)


def to_sarif(result: ScanResult) -> str:
    """Serialize ScanResult to SARIF 2.1.0 for GitHub Code Scanning."""
    rules: dict = {}
    results = []

    for f in result.all_findings():
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
                "properties": {"category": f.category, "tags": f.references},
            }

        location_parts = (f.location or "").split(":")
        uri = location_parts[0] if location_parts else "unknown"
        line = int(location_parts[1]) if len(location_parts) > 1 and location_parts[1].isdigit() else 1

        results.append({
            "ruleId": f.id,
            "level": _sarif_level(f.severity),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }],
        })

    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AEGIS",
                    "version": result.aegis_version,
                    "informationUri": "https://suite.cognis.digital/aegis",
                    "organization": "Cognis Digital",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }, indent=2)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "none"}.get(severity, "note")


def to_console(result: ScanResult) -> str:
    """Pretty-print to terminal."""
    lines = []
    lines.append(f"AEGIS v{result.aegis_version}  —  Cognis Digital / Cognis Neural Suite")
    lines.append("─" * 70)
    lines.append(f"Target:       {result.target}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Scan time:    {result.scan_duration_ms} ms")
    lines.append(f"Agents found: {len(result.agents)}  ·  Tools: {result.total_tools()}")
    lines.append("")
    lines.append(f"COMPOSITE SCORE:  {result.composite_score:.1f} / 100  ({result.risk_level.upper()})")
    counts = result.findings_by_severity()
    lines.append(f"Findings: {counts['critical']} critical, {counts['high']} high, "
                 f"{counts['medium']} medium, {counts['low']} low, {counts['info']} info")
    lines.append("")

    if result.lethal_trifecta_present:
        lines.append("⚠️  LETHAL TRIFECTA DETECTED in agents:")
        for name in result.lethal_trifecta_present:
            lines.append(f"     • {name}")
        lines.append("   (private data access + untrusted content + external comms = exfil capable)")
        lines.append("")

    all_findings = sorted(
        result.all_findings(),
        key=lambda f: ("critical", "high", "medium", "low", "info").index(f.severity),
    )

    for f in all_findings[:50]:
        lines.append(f"[{f.severity.upper():8}] {f.id}  {f.title}")
        lines.append(f"           Location:    {f.location}")
        lines.append(f"           Remediation: {f.remediation}")
        if f.references:
            lines.append(f"           References:  {', '.join(f.references)}")
        lines.append("")

    if len(all_findings) > 50:
        lines.append(f"... and {len(all_findings) - 50} more findings (use --format json for full)")

    if result.compliance_crosswalk:
        lines.append("\nCOMPLIANCE CROSSWALK")
        for framework, count in sorted(result.compliance_crosswalk.items(), key=lambda x: -x[1]):
            lines.append(f"  {framework:<40} {count} finding{'s' if count != 1 else ''}")

    return "\n".join(lines)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>AEGIS Report — {target}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Inter',sans-serif;background:#0a0a14;color:#e8e8f0;margin:0;padding:2rem;line-height:1.5}}
  h1,h2,h3{{color:#bd97fd}}
  .container{{max-width:1200px;margin:0 auto}}
  .header{{border-bottom:2px solid #7c4dff;padding-bottom:1rem;margin-bottom:2rem}}
  .score{{font-size:3rem;font-weight:700;color:{score_color}}}
  .severity-critical{{color:#ff5e7e;border-left:4px solid #ff5e7e;padding-left:1rem}}
  .severity-high{{color:#ffb84d;border-left:4px solid #ffb84d;padding-left:1rem}}
  .severity-medium{{color:#ffe066;border-left:4px solid #ffe066;padding-left:1rem}}
  .severity-low{{color:#9b9bb0;border-left:4px solid #9b9bb0;padding-left:1rem}}
  .finding{{background:#13131f;border-radius:8px;padding:1rem;margin:0.5rem 0}}
  .meta{{color:#9b9bb0;font-size:0.875rem}}
  .trifecta{{background:#3a0c14;border:2px solid #ff5e7e;border-radius:8px;padding:1rem;margin:1rem 0}}
  code{{background:#13131f;padding:2px 6px;border-radius:4px;font-family:'JetBrains Mono',monospace}}
  table{{width:100%;border-collapse:collapse;margin:1rem 0}}
  th,td{{text-align:left;padding:0.5rem;border-bottom:1px solid #2a2a3e}}
  .cognis-mark{{color:#7c4dff;font-weight:700;letter-spacing:0.05em}}
</style>
</head><body><div class="container">
<div class="header">
  <h1>AEGIS Audit Report</h1>
  <p class="meta">Powered by <span class="cognis-mark">COGNIS NEURAL SUITE</span> · AEGIS v{version} · cognis.digital</p>
</div>

<h2>Summary</h2>
<table>
  <tr><th>Target</th><td><code>{target}</code></td></tr>
  <tr><th>Files scanned</th><td>{files_scanned}</td></tr>
  <tr><th>Agents found</th><td>{agent_count}</td></tr>
  <tr><th>Tools found</th><td>{tool_count}</td></tr>
  <tr><th>Scan duration</th><td>{scan_ms} ms</td></tr>
</table>

<h2>Risk Score</h2>
<div class="score">{score:.1f} / 100 — {risk_level}</div>
<p>Findings: <strong>{critical} critical</strong>, {high} high, {medium} medium, {low} low</p>

{trifecta_section}

<h2>Findings (top 100)</h2>
{findings_html}

<h2>Compliance Crosswalk</h2>
<table><tr><th>Framework</th><th>Findings</th></tr>
{crosswalk_html}
</table>

<hr>
<p class="meta">AEGIS is part of the <strong>Cognis Neural Suite</strong>.
This report can be filed as evidence for NIST AI RMF, EU AI Act Article 15,
ISO/IEC 42001, and DoD Responsible AI Strategy compliance.</p>
<p class="meta">Generated by AEGIS · <a href="https://cognis.digital" style="color:#bd97fd">cognis.digital</a></p>
</div></body></html>"""


def to_html(result: ScanResult) -> str:
    """Render a standalone HTML report."""
    counts = result.findings_by_severity()
    score_color = "#ff5e7e" if result.composite_score >= 80 else \
                  "#ffb84d" if result.composite_score >= 60 else \
                  "#ffe066" if result.composite_score >= 40 else "#3cff8a"

    trifecta_html = ""
    if result.lethal_trifecta_present:
        agents = ", ".join(html.escape(a) for a in result.lethal_trifecta_present)
        trifecta_html = (f'<div class="trifecta"><h3>⚠️ LETHAL TRIFECTA DETECTED</h3>'
                         f'<p>Agents combining private data + untrusted content + external comms: <strong>{agents}</strong></p>'
                         f'<p>This combination is exfiltration-capable. See OWASP LLM06.</p></div>')

    findings_html_parts = []
    sorted_findings = sorted(result.all_findings(),
                             key=lambda f: ("critical", "high", "medium", "low", "info").index(f.severity))
    for f in sorted_findings[:100]:
        findings_html_parts.append(
            f'<div class="finding severity-{f.severity}">'
            f'<strong>[{f.severity.upper()}] {html.escape(f.id)}</strong> '
            f'{html.escape(f.title)}<br>'
            f'<span class="meta">Location: <code>{html.escape(f.location)}</code></span><br>'
            f'<span class="meta">Remediation: {html.escape(f.remediation)}</span>'
            f'</div>'
        )

    crosswalk_html = "".join(
        f'<tr><td>{html.escape(k)}</td><td>{v}</td></tr>'
        for k, v in sorted(result.compliance_crosswalk.items(), key=lambda x: -x[1])
    )

    return HTML_TEMPLATE.format(
        target=html.escape(result.target),
        version=html.escape(result.aegis_version),
        files_scanned=result.files_scanned,
        agent_count=len(result.agents),
        tool_count=result.total_tools(),
        scan_ms=result.scan_duration_ms,
        score=result.composite_score,
        score_color=score_color,
        risk_level=result.risk_level.upper(),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        trifecta_section=trifecta_html,
        findings_html="\n".join(findings_html_parts) or "<p>No findings.</p>",
        crosswalk_html=crosswalk_html or "<tr><td>No references</td><td>0</td></tr>",
    )


def to_markdown(result: ScanResult) -> str:
    """Render a Markdown report for issues/PRs."""
    counts = result.findings_by_severity()
    lines = [
        f"# AEGIS Audit Report",
        f"_Powered by the **Cognis Neural Suite** — AEGIS v{result.aegis_version}_",
        "",
        f"**Target:** `{result.target}`",
        f"**Score:** {result.composite_score:.1f} / 100 ({result.risk_level})",
        f"**Findings:** {counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low",
        "",
    ]
    if result.lethal_trifecta_present:
        lines.append("## ⚠️ Lethal Trifecta Detected")
        lines.extend(f"- `{a}`" for a in result.lethal_trifecta_present)
        lines.append("")

    lines.append("## Top Findings")
    for f in sorted(result.all_findings(),
                    key=lambda x: ("critical", "high", "medium", "low", "info").index(x.severity))[:20]:
        lines.append(f"- **[{f.severity.upper()}] {f.id}** — {f.title}")
        lines.append(f"  - Location: `{f.location}`")
        lines.append(f"  - Remediation: {f.remediation}")
    return "\n".join(lines)
