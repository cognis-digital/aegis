# Scenario: Over-privileged procurement agent

Has shell=True curl + arbitrary file writes + payment approval over HTTP without auth.

## Expected findings

- AEG-SEC-001 (hardcoded OpenAI key)
- AEG-REACH-001 (shell command injection via name)
- AEG-CAP-001 / AEG-MCP-* (HTTP without auth, can call create_po + approve_payment)

## Why this matters

This is the lethal-trifecta agent: credential exposure + injection vector + financial reach. Highest possible severity.
