# Ports of AEGIS

The primary AEGIS command — `aegis audit <manifest.json>` — ported across
languages so you can drop the trifecta auditor into any stack or ship a single
static binary into a CI image or air-gapped enclave.

Every port implements the **same logic** as the Python reference
(`aegis/core.py`): load an AI-agent manifest, classify each capability along the
three lethal-trifecta axes — **credentials + injection + reach** — and report
agents that hold all three (`critical`), two of three (`high`), or that route
untrusted input into a shell/exec/deploy capability (`critical`, injection→RCE).

All ports share:

- the same axis signature tables and explicit-scope map,
- the same manifest shapes (`{"agents":[…]}`, a bare list, or a single agent),
- the same JSON output keys (`agents_scanned`, `finding_count`, `worst_severity`, `findings`),
- the same **exit codes**: `0` clean · `1` critical/high finding present · `2` bad/missing manifest.

| Language | Path | Build / run | Test |
|---|---|---|---|
| Python (reference) | [`../aegis/`](../aegis/) | `aegis audit demos/01-basic/agents.json` | `pytest` |
| Go | [`go/`](go/) | `cd ports/go && go run . ../../demos/01-basic/agents.json` | `go test ./...` |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- ../../demos/01-basic/agents.json` | `cargo test` |
| JavaScript / Node | [`javascript/`](javascript/) | `node ports/javascript/index.js demos/01-basic/agents.json` | `node --test` |
| POSIX shell (+ jq) | [`shell/`](shell/) | `sh ports/shell/aegis.sh demos/01-basic/agents.json` | `sh ports/shell/test.sh` |

Each port also accepts `--format json` for machine-readable output:

```console
$ node ports/javascript/index.js --format json demos/01-basic/agents.json
{
  "agents_scanned": 4,
  "finding_count": 4,
  "worst_severity": "critical",
  "findings": [
    { "agent": "support-bot", "severity": "critical", "axes": ["credentials","injection","reach"], ... }
  ]
}
```

## Verified in CI

The Go, Rust, JavaScript, and shell ports are built and smoke-tested against the
bundled demo manifests on every push by
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml) — so the ports
are real and reproducible even if a given toolchain isn't installed locally. The
Go and Rust ports are **zero-dependency** (the Rust port includes a tiny
stdlib-only JSON parser); the JS port is Node-stdlib-only; the shell port needs
only `jq`.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md). A new port should pass the same demo
assertions and match the JSON output shape above.
