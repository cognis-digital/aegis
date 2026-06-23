"""Tests for the filesystem scan() engine and the exporters/scoring it drives."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.core import scan, TOOL_VERSION, _build_crosswalk, _looks_like, _iter_files
from aegis.exporters import to_json, to_sarif, to_html, to_markdown, to_console
from aegis.models import Finding, ScanResult

DEMOS = Path(__file__).parent.parent / "demos"


# ── discovery helpers ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,kind", [
    ("mcp.json", "mcp"),
    ("claude_desktop_config.json", "mcp"),
    ("agent.py", "python"),
    ("agents.yaml", "yaml"),
    ("conf.yml", "yaml"),
    ("data.json", "json"),
    ("notes.txt", "other"),
    ("image.png", "other"),
])
def test_looks_like(name, kind):
    assert _looks_like(Path(name)) == kind


def test_iter_files_skips_vendor_dirs(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.py").write_text("x", encoding="utf-8")
    (tmp_path / "real.py").write_text("x", encoding="utf-8")
    files = [p.name for p in _iter_files(tmp_path)]
    assert "real.py" in files
    assert "junk.py" not in files


def test_iter_files_single_file(tmp_path):
    f = tmp_path / "one.py"
    f.write_text("x", encoding="utf-8")
    assert [p.name for p in _iter_files(f)] == ["one.py"]


# ── scan() on demos ───────────────────────────────────────────────────────────

def test_scan_coding_assistant_is_critical():
    r = scan(DEMOS / "coding-assistant")
    assert r.composite_score >= 60
    assert r.risk_level in ("High", "Critical")
    assert r.total_findings() >= 5


def test_scan_reports_version():
    r = scan(DEMOS / "coding-assistant")
    assert r.aegis_version == TOOL_VERSION


def test_scan_detects_secret_and_reach_and_injection():
    ids = {f.id for f in scan(DEMOS / "coding-assistant").all_findings()}
    assert any(i.startswith("AEG-SEC-") for i in ids)
    assert "AEG-REACH-001" in ids
    assert "AEG-INJ-001" in ids


def test_scan_detects_trifecta_agent():
    r = scan(DEMOS / "coding-assistant")
    assert r.lethal_trifecta_present
    assert any(f.id == "AEG-TRIFECTA-001" for f in r.all_findings())


def test_scan_customer_support_secrets():
    ids = {f.id for f in scan(DEMOS / "customer-support").all_findings()}
    assert any(i.startswith("AEG-SEC-") for i in ids)


def test_scan_clean_agent_lower_risk():
    r = scan(DEMOS / "03-analytics-agent-clean")
    # The clean demo should not surface a lethal trifecta.
    assert not r.lethal_trifecta_present


def test_scan_records_timing_and_files():
    r = scan(DEMOS / "coding-assistant")
    assert r.files_scanned >= 1
    assert r.scan_duration_ms >= 0


def test_scan_missing_target_raises():
    with pytest.raises(FileNotFoundError):
        scan(DEMOS / "does-not-exist-xyz")


def test_scan_empty_dir_is_clean(tmp_path):
    r = scan(tmp_path)
    assert r.total_findings() == 0
    assert r.risk_level == "Minimal"


def test_scan_compliance_crosswalk_populated():
    r = scan(DEMOS / "coding-assistant")
    assert r.compliance_crosswalk
    # Hard-coded credential finding maps to CWE-798.
    assert any("CWE-798" in k or "IA-5" in k for k in r.compliance_crosswalk)


# ── ScanResult model ──────────────────────────────────────────────────────────

def _result_with(findings):
    r = ScanResult(target="t", aegis_version="0.0.0")
    r.global_findings = findings
    return r


def test_findings_by_severity_counts():
    r = _result_with([
        Finding(id="a", severity="critical", weight=3, title="t", description="", location="", remediation=""),
        Finding(id="b", severity="high", weight=2, title="t", description="", location="", remediation=""),
        Finding(id="c", severity="high", weight=2, title="t", description="", location="", remediation=""),
    ])
    counts = r.findings_by_severity()
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 0


def test_all_findings_aggregates_levels():
    from aegis.models import Agent, Tool
    r = ScanResult(target="t", aegis_version="0.0.0")
    r.global_findings = [Finding(id="g", severity="low", weight=1, title="", description="", location="", remediation="")]
    a = Agent(name="a", framework="generic")
    a.findings = [Finding(id="af", severity="low", weight=1, title="", description="", location="", remediation="")]
    t = Tool(name="t", framework="generic")
    t.findings = [Finding(id="tf", severity="low", weight=1, title="", description="", location="", remediation="")]
    a.tools = [t]
    r.agents = [a]
    assert len(r.all_findings()) == 3
    assert r.total_tools() == 1


def test_build_crosswalk_counts_references():
    fs = [
        Finding(id="a", severity="high", weight=2, title="", description="", location="", remediation="", references=["CWE-798"]),
        Finding(id="b", severity="high", weight=2, title="", description="", location="", remediation="", references=["CWE-798"]),
    ]
    cw = _build_crosswalk(fs)
    total = sum(cw.values())
    assert total >= 2


# ── exporters ─────────────────────────────────────────────────────────────────

def test_all_exporters_nonempty():
    r = scan(DEMOS / "coding-assistant")
    for fn in (to_console, to_json, to_sarif, to_html, to_markdown):
        out = fn(r)
        assert isinstance(out, str) and len(out) > 100


def test_to_json_is_parseable():
    r = scan(DEMOS / "coding-assistant")
    data = json.loads(to_json(r))
    assert data["target"]
    assert "agents" in data


def test_to_sarif_valid_2_1_0():
    r = scan(DEMOS / "coding-assistant")
    data = json.loads(to_sarif(r))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "AEGIS"
    assert data["runs"][0]["results"]


def test_to_sarif_levels_are_valid():
    r = scan(DEMOS / "coding-assistant")
    data = json.loads(to_sarif(r))
    valid = {"error", "warning", "note", "none"}
    for res in data["runs"][0]["results"]:
        assert res["level"] in valid


def test_to_html_contains_report_title_and_brand():
    out = to_html(scan(DEMOS / "coding-assistant"))
    assert "AEGIS Audit Report" in out
    assert "Cognis" in out


def test_to_markdown_lists_findings():
    out = to_markdown(scan(DEMOS / "coding-assistant"))
    assert out.startswith("# AEGIS Audit Report")
    assert "Remediation" in out


def test_to_console_shows_score_and_severity_counts():
    out = to_console(scan(DEMOS / "coding-assistant"))
    assert "COMPOSITE SCORE" in out
    assert "Findings:" in out
