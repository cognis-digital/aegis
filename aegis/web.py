"""
AEGIS web dashboard — FastAPI UI for running scans interactively.
Install with: pip install 'cognis-aegis[web]'
"""
from __future__ import annotations

from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException, Form
    from fastapi.responses import HTMLResponse, JSONResponse
except ImportError:
    raise ImportError("Install with: pip install 'cognis-aegis[web]'")

from aegis.core import scan
from aegis.exporters import to_html, to_json

app = FastAPI(
    title="AEGIS Dashboard",
    description="AI Agent Permission & Access Auditor — Cognis Neural Suite",
    version="0.1.0",
)

INDEX_HTML = """
<!DOCTYPE html><html><head>
<title>AEGIS Dashboard — Cognis Neural Suite</title>
<style>
body{font-family:-apple-system,Inter,sans-serif;background:#0a0a14;color:#e8e8f0;margin:0;padding:2rem}
.container{max-width:900px;margin:0 auto}
h1{color:#bd97fd}
.cognis{color:#7c4dff;font-weight:700;letter-spacing:0.05em}
input,button{font-family:inherit;padding:0.5rem 1rem;border-radius:6px;border:1px solid #2a2a3e;background:#13131f;color:#e8e8f0;font-size:1rem}
button{background:#7c4dff;cursor:pointer;border:none}
button:hover{background:#5e35cc}
.box{background:#13131f;padding:1.5rem;border-radius:8px;margin:1rem 0}
</style></head><body><div class="container">
<h1>AEGIS Dashboard</h1>
<p>Powered by <span class="cognis">COGNIS NEURAL SUITE</span> · <a href="https://cognis.digital" style="color:#bd97fd">cognis.digital</a></p>
<div class="box">
<h3>Scan a path</h3>
<form action="/scan" method="post">
  <input type="text" name="target" placeholder="/path/to/agent-project" style="width:60%" required>
  <button type="submit">Scan</button>
</form>
</div>
<p><strong>API endpoints:</strong></p>
<ul>
  <li><code>POST /scan</code> form: target</li>
  <li><code>GET /api/scan?target=...</code></li>
  <li><code>GET /health</code></li>
</ul>
<p style="color:#9b9bb0;margin-top:2rem">AEGIS is an MCP-compatible tool. Cognis.Studio customers can install it directly: <code>cognis-studio mcp install aegis</code></p>
</div></body></html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


@app.get("/health")
async def health():
    from aegis import __version__
    return {"status": "ok", "version": __version__, "service": "aegis"}


@app.get("/api/scan")
async def api_scan(target: str):
    if not target:
        raise HTTPException(400, "target required")
    if not Path(target).exists():
        raise HTTPException(404, "target path not found")
    result = scan(target)
    import json
    return JSONResponse(content=json.loads(to_json(result)))


@app.post("/scan", response_class=HTMLResponse)
async def scan_form(target: str = Form(...)):
    if not Path(target).exists():
        return HTMLResponse(f"<p>Path not found: {target}</p>", status_code=404)
    result = scan(target)
    return to_html(result)
