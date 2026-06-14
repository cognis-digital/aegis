"""Hardening tests for AEGIS: error handling and edge-case coverage.

These tests verify bad input is rejected gracefully and edge cases do not raise
unhandled exceptions.
"""
from __future__ import annotations

import pytest

from aegis.cli import main
from aegis.core import (
    audit_manifest,
    classify_capability,
    load_manifest,
    _coerce_agents,
    _capabilities_of,
)
from aegis.scoring import score
from aegis.models import Finding


# CLI error paths

def test_cli_missing_file_exits_2(capsys):
    rc = main(["audit", "/nonexistent/path/to/aegis_manifest.json"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_cli_directory_as_manifest_exits_2(capsys, tmp_path):
    rc = main(["audit", str(tmp_path)])
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.err
    assert "Traceback" not in captured.err


def test_cli_empty_manifest_exits_2(capsys, tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("")
    rc = main(["audit", str(empty)])
    assert rc == 2
    assert capsys.readouterr().err


def test_cli_malformed_json_exits_2(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = main(["audit", str(bad)])
    assert rc == 2
    assert capsys.readouterr().err


def test_cli_scalar_json_exits_2(capsys, tmp_path):
    bad = tmp_path / "scalar.json"
    bad.write_text("42")
    rc = main(["audit", str(bad)])
    assert rc == 2


# load_manifest edge cases

def test_load_manifest_empty_file_raises(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text("   ")
    with pytest.raises(ValueError, match="empty"):
        load_manifest(str(f))


def test_load_manifest_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_manifest("/no/such/file.json")


# _coerce_agents edge cases

def test_coerce_agents_skips_non_dict_entries():
    data = {"agents": [{"name": "ok"}, None, 42, {"name": "also-ok"}]}
    agents = _coerce_agents(data)
    assert len(agents) == 2


def test_coerce_agents_empty_list():
    assert _coerce_agents({"agents": []}) == []


def test_coerce_agents_scalar_raises():
    with pytest.raises(ValueError):
        _coerce_agents(123)


# _capabilities_of edge cases

def test_capabilities_of_string_value():
    caps = _capabilities_of({"name": "agent", "capabilities": "read_files"})
    assert caps == []


def test_capabilities_of_none_value():
    caps = _capabilities_of({"name": "agent"})
    assert caps == []


def test_capabilities_of_mixed_entries():
    caps = _capabilities_of({"capabilities": ["web_fetch", {"name": "exec"}, 99]})
    names = [c["name"] for c in caps]
    assert "web_fetch" in names and "exec" in names
    assert len(caps) == 2


# classify_capability: non-dict input

def test_classify_capability_non_dict():
    assert classify_capability(None) == {}
    assert classify_capability("web_fetch") == {}
    assert classify_capability(42) == {}


# scoring: unknown severity

def test_score_unknown_severity_no_keyerror():
    f = Finding(
        id="TEST-001", severity="unknown_sev", weight=5.0,
        title="t", description="", location="", remediation="",
    )
    s, level = score([f])
    assert s == 0.0 and level == "Minimal"


# audit_manifest edge cases

def test_audit_manifest_skips_non_dict_agents():
    agents = [{"name": "ok", "capabilities": []}, None, "bad"]
    report = audit_manifest(agents)
    assert report.agents_scanned == 1


def test_audit_manifest_empty_agents():
    report = audit_manifest([])
    assert report.agents_scanned == 0 and not report.has_findings


# scan(): nonexistent target

def test_scan_nonexistent_target():
    from aegis.core import scan
    with pytest.raises(ValueError, match="does not exist"):
        scan("/no/such/directory/anywhere")
