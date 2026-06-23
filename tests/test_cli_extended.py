"""Tests for the CLI surface — both `audit` and the new `scan` subcommand."""
from __future__ import annotations

import json
import os

import pytest

from aegis.cli import main, build_parser

DEMOS = os.path.join(os.path.dirname(__file__), "..", "demos")
BASIC = os.path.join(DEMOS, "01-basic", "agents.json")
CLEAN = os.path.join(DEMOS, "03-analytics-agent-clean", "mcp.json")
CODING = os.path.join(DEMOS, "coding-assistant")


# ── parser wiring ─────────────────────────────────────────────────────────────

def test_parser_has_audit_and_scan():
    parser = build_parser()
    # argparse subparsers live on the _SubParsersAction choices.
    sub = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    names = set()
    for a in sub:
        names.update(a.choices)
    assert "audit" in names
    assert "scan" in names


def test_no_args_prints_help_returns_zero():
    assert main([]) == 0


# ── audit ─────────────────────────────────────────────────────────────────────

def test_audit_exit_nonzero_on_findings():
    assert main(["audit", BASIC]) == 1


def test_audit_json_format(capsys):
    rc = main(["audit", BASIC, "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["agents_scanned"] == 4
    assert rc == 1


def test_audit_table_format(capsys):
    main(["audit", BASIC])
    out = capsys.readouterr().out
    assert "AEGIS audit" in out
    assert "support-bot" in out


def test_audit_missing_manifest_returns_2(capsys):
    rc = main(["audit", "/no/such/file.json"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_audit_invalid_manifest_returns_2(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{{{ not json", encoding="utf-8")
    rc = main(["audit", str(p)])
    assert rc == 2
    assert "invalid manifest" in capsys.readouterr().err


# ── scan ──────────────────────────────────────────────────────────────────────

def test_scan_console_default(capsys):
    rc = main(["scan", CODING])
    out = capsys.readouterr().out
    assert "COMPOSITE SCORE" in out
    assert rc == 1  # default --fail-on high, demo has criticals


def test_scan_json_format(capsys):
    main(["scan", CODING, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert "agents" in data
    assert data["target"]


def test_scan_sarif_format(capsys):
    main(["scan", CODING, "--format", "sarif"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"


def test_scan_markdown_format(capsys):
    main(["scan", CODING, "--format", "markdown"])
    out = capsys.readouterr().out
    assert out.lstrip().startswith("# AEGIS Audit Report")


def test_scan_html_format(capsys):
    main(["scan", CODING, "--format", "html"])
    out = capsys.readouterr().out
    assert "<html" in out.lower()


def test_scan_fail_on_none_returns_zero():
    assert main(["scan", CODING, "--fail-on", "none"]) == 0


def test_scan_fail_on_critical_clean_returns_zero():
    assert main(["scan", CLEAN, "--fail-on", "critical"]) == 0


def test_scan_fail_on_high_dirty_returns_one():
    assert main(["scan", CODING, "--fail-on", "high"]) == 1


def test_scan_missing_target_returns_2(capsys):
    rc = main(["scan", "/no/such/dir/xyz"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_scan_output_to_file(tmp_path):
    out_file = tmp_path / "report.sarif"
    rc = main(["scan", CODING, "--format", "sarif", "-o", str(out_file)])
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert rc in (0, 1)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "aegis" in capsys.readouterr().out
