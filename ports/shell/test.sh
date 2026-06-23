#!/bin/sh
# Smoke test for the AEGIS shell port. Requires jq. Exits non-zero on failure.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AEGIS="$here/aegis.sh"
DEMOS="$here/../../demos"
fail() { echo "FAIL: $1" >&2; exit 1; }

# 1) Basic demo: exit 1 (critical present), worst critical, 4 findings.
out=$(sh "$AEGIS" --format json "$DEMOS/01-basic/agents.json") || rc=$? && rc=${rc:-0}
echo "$out" | grep -q '"worst_severity": "critical"' || fail "worst not critical"
echo "$out" | grep -q '"agents_scanned": 4' || fail "agents_scanned != 4"
echo "$out" | grep -q '"finding_count": 4' || fail "finding_count != 4"
echo "$out" | grep -q 'support-bot' || fail "missing support-bot finding"

# 2) Exit code is 1 when critical/high present.
if sh "$AEGIS" "$DEMOS/01-basic/agents.json" >/dev/null 2>&1; then
  fail "expected exit 1 on critical findings"
fi

# 3) Clean agent: exit 0, no findings.
out=$(sh "$AEGIS" --format json "$DEMOS/03-analytics-agent-clean/mcp.json")
echo "$out" | grep -q '"finding_count": 0' || fail "clean agent should have 0 findings"
sh "$AEGIS" "$DEMOS/03-analytics-agent-clean/mcp.json" >/dev/null 2>&1 || fail "clean agent should exit 0"

# 4) Missing manifest -> exit 2.
if sh "$AEGIS" /no/such/file.json >/dev/null 2>&1; then
  fail "missing manifest should exit 2"
fi

echo "shell port: all smoke tests passed"
