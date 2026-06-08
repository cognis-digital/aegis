"""Smoke tests for AEGIS. Runs the real engine on the bundled demo manifest.

No network, no third-party deps.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis import (
    TOOL_NAME,
    TOOL_VERSION,
    audit_file,
    classify_capability,
    CAPABILITY_AXES,
)
from aegis.cli import main

DEMO = os.path.join(
    os.path.dirname(__file__), "..", "demos", "01-basic", "agents.json"
)


def test_metadata():
    assert TOOL_NAME == "aegis"
    assert TOOL_VERSION.count(".") == 2


def test_classify_axes():
    # A web fetch is untrusted-input (injection).
    inj = classify_capability({"name": "web_fetch", "description": "fetch a url"})
    assert "injection" in inj
    # Reading the billing DB touches credentials/private data.
    cred = classify_capability({"name": "billing_db_query", "scopes": ["read:db"]})
    assert "credentials" in cred
    # Sending email is outbound reach.
    reach = classify_capability({"name": "send_email", "scopes": ["send:email"]})
    assert "reach" in reach


def test_audit_demo_detects_trifecta():
    report = audit_file(DEMO)
    assert report.agents_scanned == 4
    assert report.has_findings

    by_agent = {}
    for f in report.findings:
        by_agent.setdefault(f.agent, []).append(f)

    # support-bot has all three axes -> critical lethal trifecta.
    support = by_agent["support-bot"]
    assert any(f.severity == "critical" for f in support)
    trifecta = next(f for f in support if f.severity == "critical")
    assert sorted(trifecta.axes) == sorted(CAPABILITY_AXES)

    # deploy-agent: untrusted input -> code execution is flagged critical.
    deploy = by_agent["deploy-agent"]
    assert any(
        f.severity == "critical" and "reach" in f.axes and "injection" in f.axes
        for f in deploy
    )

    # summarizer has exactly two axes -> high.
    summ = by_agent["summarizer"]
    assert any(f.severity == "high" for f in summ)

    # calculator is clean -> no finding.
    assert "calculator" not in by_agent

    assert report.worst_severity == "critical"


def test_cli_exit_code_nonzero_on_findings():
    # Findings present -> exit 1 (gates CI).
    assert main(["audit", DEMO]) == 1
    # JSON format also works.
    assert main(["audit", DEMO, "--format", "json"]) == 1


def test_cli_no_args_prints_help():
    assert main([]) == 0


if __name__ == "__main__":
    test_metadata()
    test_classify_axes()
    test_audit_demo_detects_trifecta()
    test_cli_exit_code_nonzero_on_findings()
    test_cli_no_args_prints_help()
    print("all smoke tests passed")
