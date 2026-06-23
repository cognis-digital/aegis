"""Exhaustive tests for capability classification and the manifest engine."""
from __future__ import annotations

import json
import os

import pytest

from aegis.core import (
    CAPABILITY_AXES,
    classify_capability,
    audit_manifest,
    load_manifest,
    _coerce_agents,
    _capabilities_of,
    _normalize,
    AuditReport,
    Finding,
)

DEMOS = os.path.join(os.path.dirname(__file__), "..", "demos")


# ── classify_capability ──────────────────────────────────────────────────────

@pytest.mark.parametrize("name,axis", [
    ("read_secret", "credentials"),
    ("vault_get", "credentials"),
    ("billing_db_query", "credentials"),
    ("customer_data_lookup", "credentials"),
    ("ssh_key_read", "credentials"),
    ("web_fetch", "injection"),
    ("crawl_site", "injection"),
    ("read_email", "injection"),
    ("parse_pdf", "injection"),
    ("rag_retrieve", "injection"),
    ("send_email", "reach"),
    ("http_post", "reach"),
    ("exec_shell", "reach"),
    ("git_push", "reach"),
    ("deploy_service", "reach"),
])
def test_keyword_signature_axis(name, axis):
    matched = classify_capability({"name": name})
    assert axis in matched, f"{name} should match axis {axis}: got {matched}"


def test_classify_returns_evidence_tokens():
    matched = classify_capability({"name": "web_fetch", "description": "fetch a url"})
    assert "injection" in matched
    assert isinstance(matched["injection"], list)
    assert matched["injection"], "evidence list must be non-empty"


def test_classify_no_duplicate_evidence():
    matched = classify_capability({"name": "web web web fetch", "description": "web fetch"})
    inj = matched.get("injection", [])
    assert len(inj) == len(set(inj)), "evidence tokens must be deduplicated"


@pytest.mark.parametrize("scope,axis", [
    ("read:secrets", "credentials"),
    ("read:files", "credentials"),
    ("read:db", "credentials"),
    ("read:web", "injection"),
    ("read:email", "injection"),
    ("net:outbound", "reach"),
    ("write:files", "reach"),
    ("exec:shell", "reach"),
    ("send:email", "reach"),
])
def test_explicit_scope_axis(scope, axis):
    matched = classify_capability({"name": "x", "scopes": [scope]})
    assert axis in matched


def test_classify_benign_capability_is_empty():
    matched = classify_capability({"name": "compute", "description": "evaluate a math expression"})
    # "compute" must not trip any axis.
    assert matched == {} or all(not v for v in matched.values())


def test_classify_handles_missing_fields():
    assert classify_capability({}) == {} or isinstance(classify_capability({}), dict)


def test_classify_case_insensitive():
    a = classify_capability({"name": "WEB_FETCH"})
    assert "injection" in a


def test_classify_scopes_and_keywords_combine():
    matched = classify_capability({"name": "send_email", "scopes": ["send:email"]})
    assert "reach" in matched
    assert len(matched["reach"]) >= 1


# ── _normalize ────────────────────────────────────────────────────────────────

def test_normalize_flattens_lists():
    out = _normalize(["a", "b"], "c")
    assert "a" in out and "b" in out and "c" in out


def test_normalize_flattens_dicts():
    out = _normalize({"key": "VALUE"})
    assert "key" in out and "value" in out


def test_normalize_lowercases():
    assert _normalize("HELLO") == "hello"


def test_normalize_drops_none():
    out = _normalize(None, "x", None)
    assert out.strip() == "x"


def test_normalize_strips_punctuation_keeps_scope_chars():
    out = _normalize("read:db!! foo@bar")
    assert "read:db" in out
    assert "!" not in out and "@" not in out


# ── _coerce_agents / _capabilities_of ────────────────────────────────────────

def test_coerce_agents_from_wrapper():
    assert _coerce_agents({"agents": [{}, {}]}) == [{}, {}]


def test_coerce_agents_from_list():
    assert _coerce_agents([{"name": "a"}]) == [{"name": "a"}]


def test_coerce_agents_single_object():
    assert _coerce_agents({"name": "solo"}) == [{"name": "solo"}]


def test_coerce_agents_rejects_scalar():
    with pytest.raises(ValueError):
        _coerce_agents(42)


def test_coerce_agents_rejects_non_list_agents():
    with pytest.raises(ValueError):
        _coerce_agents({"agents": "nope"})


def test_capabilities_of_string_list():
    caps = _capabilities_of({"capabilities": ["read_secret", "send_email"]})
    assert {c["name"] for c in caps} == {"read_secret", "send_email"}


def test_capabilities_of_prefers_capabilities_over_tools():
    caps = _capabilities_of({"capabilities": ["a"], "tools": ["b"]})
    assert caps == [{"name": "a"}]


def test_capabilities_of_falls_back_to_tools():
    caps = _capabilities_of({"tools": ["b"]})
    assert caps == [{"name": "b"}]


def test_capabilities_of_falls_back_to_permissions():
    caps = _capabilities_of({"permissions": [{"name": "p"}]})
    assert caps == [{"name": "p"}]


def test_capabilities_of_empty():
    assert _capabilities_of({}) == []


# ── audit_manifest semantics ──────────────────────────────────────────────────

def _agent(name, caps):
    return {"name": name, "capabilities": caps}


def test_trifecta_all_three_is_critical():
    rep = audit_manifest([_agent("t", [
        {"name": "read_secret"},
        {"name": "web_fetch"},
        {"name": "send_email"},
    ])])
    assert rep.findings[0].severity == "critical"
    assert sorted(rep.findings[0].axes) == sorted(CAPABILITY_AXES)


def test_two_axes_is_high():
    rep = audit_manifest([_agent("t", [
        {"name": "read_secret"},
        {"name": "web_fetch"},
    ])])
    sev = {f.severity for f in rep.findings}
    assert "high" in sev
    assert "critical" not in sev


def test_one_axis_is_clean():
    rep = audit_manifest([_agent("t", [{"name": "read_secret"}])])
    assert rep.findings == []


def test_zero_capability_agent_clean():
    rep = audit_manifest([_agent("empty", [])])
    assert not rep.has_findings


def test_injection_plus_exec_is_rce_finding():
    rep = audit_manifest([_agent("t", [
        {"name": "read_issue"},
        {"name": "run_deploy", "scopes": ["exec:shell"]},
    ])])
    rce = [f for f in rep.findings if "code execution" in f.title]
    assert rce and rce[0].severity == "critical"


def test_agents_scanned_counts_all():
    rep = audit_manifest([_agent("a", []), _agent("b", []), _agent("c", [])])
    assert rep.agents_scanned == 3


def test_unnamed_agent_label():
    rep = audit_manifest([{"capabilities": [
        {"name": "read_secret"}, {"name": "web_fetch"}, {"name": "send_email"},
    ]}])
    assert rep.findings[0].agent == "unnamed-agent"


def test_agent_id_used_when_no_name():
    rep = audit_manifest([{"id": "agent-42", "capabilities": [
        {"name": "read_secret"}, {"name": "web_fetch"}, {"name": "send_email"},
    ]}])
    assert rep.findings[0].agent == "agent-42"


def test_report_worst_severity_none_when_empty():
    rep = AuditReport()
    assert rep.worst_severity is None


def test_report_to_dict_shape():
    rep = audit_manifest([_agent("t", [
        {"name": "read_secret"}, {"name": "web_fetch"}, {"name": "send_email"},
    ])])
    d = rep.to_dict()
    assert set(d) >= {"agents_scanned", "finding_count", "worst_severity", "findings"}
    assert d["finding_count"] == len(d["findings"])


def test_finding_capabilities_listed_per_axis():
    rep = audit_manifest([_agent("t", [
        {"name": "read_secret"}, {"name": "web_fetch"}, {"name": "send_email"},
    ])])
    caps = rep.findings[0].capabilities
    assert set(caps) == set(CAPABILITY_AXES)
    assert "read_secret" in caps["credentials"]
    assert "web_fetch" in caps["injection"]
    assert "send_email" in caps["reach"]


def test_critical_property_filters():
    rep = audit_manifest([_agent("t", [
        {"name": "read_secret"}, {"name": "web_fetch"}, {"name": "send_email"},
    ])])
    assert all(f.severity == "critical" for f in rep.critical)


def test_load_manifest_roundtrip(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"agents": [_agent("x", [{"name": "read_secret"}])]}), encoding="utf-8")
    agents = load_manifest(str(p))
    assert agents[0]["name"] == "x"


def test_load_manifest_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_manifest("/no/such/manifest.json")
