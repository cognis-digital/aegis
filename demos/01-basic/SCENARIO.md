# Demo 01 - Basic trifecta audit

This scenario models a small fleet of AI agents defined in `agents.json`. Each
agent declares the tools/capabilities it has been granted. AEGIS classifies
every capability along three risk axes and flags the **lethal trifecta**:

1. **credentials** - can read secrets / private data (env vars, files, DB)
2. **injection** - ingests untrusted input (web pages, email, documents)
3. **reach** - can act on the outside world (send email, HTTP POST, shell)

An agent with all three can be turned into a data-exfiltration pipeline by a
single prompt injection hidden in the untrusted input.

## The agents

- **support-bot** - reads customer email (injection), reads the billing DB
  (credentials), and can send email replies (reach). This is the full lethal
  trifecta: **CRITICAL**.
- **deploy-agent** - reads GitHub issue comments (injection) and runs shell
  deploy commands (reach). Untrusted input reaching code execution:
  **CRITICAL** (injection -> RCE).
- **summarizer** - only reads web pages (injection) and writes a summary file.
  Two axes -> **HIGH** (one grant away from trifecta).
- **calculator** - pure compute, no risky axes. **No finding.**

## Run it

```sh
python -m aegis audit demos/01-basic/agents.json
python -m aegis audit demos/01-basic/agents.json --format json
```

Exit code is non-zero (1) because critical/high findings exist - so AEGIS can
fail a CI gate. Use the JSON output for pipelines.
